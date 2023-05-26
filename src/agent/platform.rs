use std::path::PathBuf;
use std::io::Read;
use std::sync::{Mutex, Arc};
use std::time::{SystemTime, Duration};

use anyhow::{Result, anyhow};
use log::*;
use futures::Stream;
use futures::stream::StreamExt;
use async_stream::stream;
use tonic::{Request, Status};
use tonic::codegen::InterceptedService;
use tonic::service::Interceptor;
use tonic::transport::{Channel, Uri};
use tonic::metadata::AsciiMetadataValue;
use tokio::task::JoinHandle;

pub mod pb {
    tonic::include_proto!("edgebit.agent.v1alpha");
}

use pb::token_service_client::TokenServiceClient;
use pb::inventory_service_client::InventoryServiceClient;

use crate::registry::PkgRef;
use crate::version::VERSION;

const TOKEN_FILE: &str = "/var/lib/edgebit/token";
const EXPIRATION_SLACK: Duration = Duration::from_secs(60);
const DEFAULT_EXPIRATION: Duration = Duration::from_secs(60*60);

struct AuthInterceptor {
    token: AuthToken,
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> std::result::Result<Request<()>, Status> {
        request.metadata_mut().insert("authorization", self.token.get());
        Ok(request)
    }
}

pub struct Client {
    inventory_svc: InventoryServiceClient<InterceptedService<Channel, AuthInterceptor>>,
    sess_keeper_task: JoinHandle<()>,
}

impl Client {
    pub async fn connect(endpoint: Uri, deploy_token: String, hostname: String, machine_id: String) -> Result<Self> {
        let channel = Channel::builder(endpoint)
            .connect()
            .await?;

        let sess_keeper = SessionKeeper::new(channel.clone(), deploy_token, hostname, machine_id).await?;
        let auth_interceptor = AuthInterceptor{token: sess_keeper.get_auth_token()};
        let sess_keeper_task = tokio::task::spawn(sess_keeper.refresh_loop());
        let inventory_svc = InventoryServiceClient::with_interceptor(channel, auth_interceptor);

        Ok(Self{
            inventory_svc,
            sess_keeper_task,
        })
    }

    pub async fn upload_sbom(&mut self, image_id: String, sbom_reader: std::fs::File) -> Result<()> {
        // Header first
        let header_req = pb::UploadSbomRequest{
            kind: Some(pb::upload_sbom_request::Kind::Header(
                pb::UploadSbomHeader{
                    format: pb::SbomFormat::Syft as i32,
                    image_id,
                    image: Some(pb::Image{
                        kind: Some(pb::image::Kind::Generic(pb::GenericImage{})),
                    }),
                },
            )),
        };

        let header_stream = futures::stream::once(
            futures::future::ready(header_req)
        );

        // TODO: There must be a simpler way to deal with a stream causing an error
        let result = Arc::new(Mutex::new(Result::Ok(())));
        let stream = header_stream.chain(data_stream(sbom_reader, result.clone()));

        self.inventory_svc.upload_sbom(stream).await?;

        std::sync::Arc::<std::sync::Mutex<Result<(), anyhow::Error>>>::try_unwrap(result)
            .unwrap()
            .into_inner()
            .unwrap()
    }

    pub async fn upsert_workload(&mut self, workload: pb::UpsertWorkloadRequest) -> Result<()> {
        self.inventory_svc.upsert_workload(workload).await?;
        Ok(())
    }

    pub async fn report_in_use(&mut self, workload_id: String, pkgs: Vec<PkgRef>) -> Result<()> {
        let in_use = pkgs.into_iter()
            .map(|p| {
                pb::PkgInUse{
                    id: p.id,
                    files: p.filenames
                        .iter()
                        .filter_map(|f| f.as_raw().to_str().map(|f| f.to_string()))
                        .collect()
                }
            })
            .collect();

        let req = pb::ReportInUseRequest{
            in_use,
            workload_id,
        };

        trace!("ReportInUse: {req:?}");
        self.inventory_svc.report_in_use(req).await?;
        Ok(())
    }

    pub async fn reset_workloads(&mut self) -> Result<()> {
        self.inventory_svc.reset_workloads(pb::ResetWorkloadsRequest{
            cluster_id: String::new(),
            workloads: Vec::new(),
        }).await?;
        Ok(())
    }

    pub async fn stop(self) {
        self.sess_keeper_task.abort();
        _ = self.sess_keeper_task.await;
    }
}

#[derive(Clone)]
struct AuthToken {
    token: Arc<Mutex<AsciiMetadataValue>>,
}

impl AuthToken {
    fn new(val: &str) -> Result<Self> {
        let token = format_bearer(val)?;

        Ok(Self {
            token: Arc::new(Mutex::new(token)),
        })
    }

    fn get(&self) -> AsciiMetadataValue {
        self.token.lock()
            .unwrap()
            .clone()
    }

    fn set(&self, val: &str) -> Result<()> {
        let mut lk = self.token.lock().unwrap();
        *lk = format_bearer(val)?;
        Ok(())
    }
}

fn format_bearer(val: &str) -> Result<AsciiMetadataValue> {
    Ok(format!("Bearer {val}").parse()?)
}


struct RefreshToken {
    token: String,
}

impl RefreshToken {
    fn new(token: String) -> Self {
        Self{
            token,
        }
    }
    fn load() -> Result<Self> {
        let token = std::fs::read_to_string(TOKEN_FILE)?;
        Ok(Self{token})
    }

    fn save(&self) -> Result<()> {
        let token_file = PathBuf::from(TOKEN_FILE);
        let dir = token_file.parent().unwrap();
        std::fs::create_dir_all(dir)?;
        Ok(std::fs::write(TOKEN_FILE, &self.token)?)
    }

    fn get(&self) -> String {
        self.token.clone()
    }
}

struct SessionKeeper {
    refresh_token: RefreshToken,
    auth_token: AuthToken,
    expiration: SystemTime,
    channel: Channel,
}

impl SessionKeeper {
    async fn new(channel: Channel, deploy_token: String, hostname: String, machine_id: String) -> Result<Self> {
        let mut token_svc = TokenServiceClient::new(channel.clone());

        let (refresh_token, session_token, expiration) = match RefreshToken::load() {
            Ok(refresh_token) => {
                let req = pb::GetSessionTokenRequest{
                    refresh_token: refresh_token.get(),
                    agent_version: VERSION.to_string(),
                };

                let resp = token_svc.get_session_token(req).await?
                    .into_inner();

                (refresh_token, resp.session_token, resp.session_token_expiration)
            },
            Err(_) => {
                let req = pb::EnrollAgentRequest{
                    deployment_token: deploy_token,
                    hostname,
                    agent_version: VERSION.to_string(),
                    machine_id,
                };

                let resp = token_svc.enroll_agent(req)
                    .await?
                    .into_inner();

                let refresh_token = RefreshToken::new(resp.refresh_token);
                refresh_token.save()
                    .unwrap_or_else(|err| {
                        error!("Error saving agent token: {err}");
                    });

                (refresh_token, resp.session_token, resp.session_token_expiration)
            }
        };

        let auth_token = AuthToken::new(&session_token)?;
        let expiration = get_expiration(expiration);

        Ok(Self{
            refresh_token,
            auth_token,
            expiration,
            channel,
        })
    }

    fn get_auth_token(&self) -> AuthToken {
        self.auth_token.clone()
    }

    async fn refresh_loop(self) {
        let mut token_svc = TokenServiceClient::new(self.channel);
        let mut expiration = self.expiration;

        loop {
            let mut interval = expiration.duration_since(SystemTime::now())
                .unwrap_or_else(|_| {
                    error!("Session expiration is in the past");
                    DEFAULT_EXPIRATION
                });

            interval = interval.checked_sub(EXPIRATION_SLACK)
                .unwrap_or(interval);

            info!("Sleeping for {interval:?}");

            tokio::time::sleep(interval).await;

            let req = pb::GetSessionTokenRequest{
                refresh_token: self.refresh_token.get(),
                agent_version: VERSION.to_string(),
            };

            expiration = match token_svc.get_session_token(req).await {
                Ok(resp) => {
                    let resp = resp.into_inner();
                    self.auth_token.set(&resp.session_token).unwrap();
                    info!("Session renewed");
                    get_expiration(resp.session_token_expiration)
                },
                Err(err) => {
                    error!("Session renewal failed: {err}");
                    SystemTime::now() + EXPIRATION_SLACK
                }
            }
        }
    }
}

fn get_expiration(expiration: Option<prost_types::Timestamp>) -> SystemTime {
    match expiration {
        Some(expiration) => {
            match SystemTime::try_from(expiration) {
                Ok(expiration) => expiration,
                Err(_) => {
                    error!("Invalid session expiration time");
                    SystemTime::now() + DEFAULT_EXPIRATION
                }

            }
        },
        None => {
            error!("Session token is missing expiration");
            SystemTime::now() + DEFAULT_EXPIRATION
        }
    }
}

fn data_stream<'a, R: Read + Send + 'a>(mut rd: R, result: Arc<Mutex<Result<()>>>) -> impl Stream<Item=pb::UploadSbomRequest> + Send {
    stream!{
        let mut buf = vec![0u8; 64*1024];
        loop {
            match rd.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    yield pb::UploadSbomRequest{
                        kind: Some(pb::upload_sbom_request::Kind::Data(buf[0..n].to_vec())),
                    };
                },
                Err(e) => {
                    match e.kind() {
                        std::io::ErrorKind::Interrupted => continue,
                        kind => {
                            use std::ops::DerefMut;
                            *(result.lock().unwrap().deref_mut()) = Err(anyhow!("io error: {kind}"));
                            break;
                        },
                    }
                }
            }
        }
    }
}
