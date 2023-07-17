use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use async_stream::stream;
use futures::stream::StreamExt;
use futures::Stream;
use log::*;
use tokio::task::JoinHandle;
use tonic::codegen::InterceptedService;
use tonic::metadata::AsciiMetadataValue;
use tonic::service::Interceptor;
use tonic::transport::{Channel, Uri};
use tonic::{Request, Status};

pub mod pb {
    tonic::include_proto!("edgebit.agent.v1alpha");
}

use pb::inventory_service_client::InventoryServiceClient;
use pb::token_service_client::TokenServiceClient;

use crate::registry::PkgRef;
use crate::version::VERSION;

const EXPIRATION_SLACK: Duration = Duration::from_secs(10 * 60);
const DEFAULT_EXPIRATION: Duration = Duration::from_secs(60 * 60);
const RETRY_INTERVAL: Duration = Duration::from_secs(1);

pub struct Client {
    inventory_svc: InventoryServiceClient<InterceptedService<Channel, AuthToken>>,
    sess_keeper_task: JoinHandle<()>,
}

impl Client {
    pub async fn connect(
        endpoint: Uri,
        deploy_token: String,
        hostname: String,
        machine_id: String,
    ) -> Result<Self> {
        let channel = Channel::builder(endpoint).connect().await?;

        let mut token = enroll_loop(
            channel.clone(),
            deploy_token.clone(),
            hostname.clone(),
            machine_id.clone(),
        )
        .await;

        let auth_token = AuthToken::new(&token.session_token);

        let inventory_svc =
            InventoryServiceClient::with_interceptor(channel.clone(), auth_token.clone());

        let sess_keeper_task = tokio::task::spawn(async move {
            while let Err(err) = refresh_loop(
                channel.clone(),
                token.refresh_token.clone(),
                auth_token.clone(),
                token.expiration,
            )
            .await
            {
                error!("Session renewal failed: {err}");

                // try re-enrolling
                token = enroll_loop(
                    channel.clone(),
                    deploy_token.clone(),
                    hostname.clone(),
                    machine_id.clone(),
                )
                .await;
                auth_token.set(&token.session_token);
            }
        });

        Ok(Self {
            inventory_svc,
            sess_keeper_task,
        })
    }

    pub async fn upload_sbom(
        &mut self,
        image_id: String,
        sbom_reader: std::fs::File,
    ) -> Result<()> {
        // Header first
        let header_req = pb::UploadSbomRequest {
            kind: Some(pb::upload_sbom_request::Kind::Header(
                pb::UploadSbomHeader {
                    format: pb::SbomFormat::Syft as i32,
                    image_id,
                    image: Some(pb::Image {
                        kind: Some(pb::image::Kind::Generic(pb::GenericImage {})),
                    }),
                },
            )),
        };

        let header_stream = futures::stream::once(futures::future::ready(header_req));

        // TODO: There must be a simpler way to deal with a stream causing an error
        let result = Arc::new(Mutex::new(Result::Ok(())));
        let stream = header_stream.chain(data_stream(sbom_reader, result.clone()));

        self.inventory_svc
            .upload_sbom(stream)
            .await
            .map_err(|e| anyhow!("{}", e.message()))?;

        std::sync::Arc::<std::sync::Mutex<Result<(), anyhow::Error>>>::try_unwrap(result)
            .unwrap()
            .into_inner()
            .unwrap()
    }

    pub async fn upsert_workload(&mut self, workload: pb::UpsertWorkloadRequest) -> Result<()> {
        self.inventory_svc
            .upsert_workload(workload)
            .await
            .map_err(|e| anyhow!("{}", e.message()))?;
        Ok(())
    }

    pub async fn report_in_use(&mut self, workload_id: String, pkgs: Vec<PkgRef>) -> Result<()> {
        let in_use = pkgs
            .into_iter()
            .map(|p| pb::PkgInUse {
                id: p.id,
                files: p
                    .filenames
                    .iter()
                    .filter_map(|f| f.as_raw().to_str().map(|f| f.to_string()))
                    .collect(),
            })
            .collect();

        let req = pb::ReportInUseRequest {
            in_use,
            workload_id,
        };

        trace!("ReportInUse: {req:?}");
        self.inventory_svc
            .report_in_use(req)
            .await
            .map_err(|e| anyhow!("{}", e.message()))?;
        Ok(())
    }

    pub async fn reset_workloads(&mut self) -> Result<()> {
        self.inventory_svc
            .reset_workloads(pb::ResetWorkloadsRequest {
                cluster_id: String::new(),
                workloads: Vec::new(),
            })
            .await
            .map_err(|e| anyhow!("{}", e.message()))?;
        Ok(())
    }

    pub async fn stop(self) {
        self.sess_keeper_task.abort();
        _ = self.sess_keeper_task.await;
    }
}

#[derive(Clone)]
struct AuthToken {
    inner: Arc<Mutex<AsciiMetadataValue>>,
}

impl AuthToken {
    fn new(token: &str) -> Self {
        let bearer = format_bearer(token);

        Self {
            inner: Arc::new(Mutex::new(bearer)),
        }
    }

    fn bearer(&self) -> AsciiMetadataValue {
        self.inner.lock().unwrap().clone()
    }

    fn set(&self, token: &str) {
        *self.inner.lock().unwrap() = format_bearer(token);
    }
}

impl Interceptor for AuthToken {
    fn call(&mut self, mut request: Request<()>) -> std::result::Result<Request<()>, Status> {
        request
            .metadata_mut()
            .insert("authorization", self.bearer());
        Ok(request)
    }
}

fn format_bearer(val: &str) -> AsciiMetadataValue {
    // val must be ASCII
    format!("Bearer {val}").parse().unwrap()
}

struct EnrolledToken {
    refresh_token: String,
    session_token: String,
    expiration: SystemTime,
}

async fn enroll(
    channel: Channel,
    deploy_token: String,
    hostname: String,
    machine_id: String,
) -> Result<EnrolledToken> {
    let mut token_svc = TokenServiceClient::new(channel);

    let req = pb::EnrollAgentRequest {
        deployment_token: deploy_token,
        hostname,
        agent_version: VERSION.to_string(),
        machine_id,
    };

    let resp = token_svc
        .enroll_agent(req)
        .await
        .map_err(|e| anyhow!("{}", e.message()))?
        .into_inner();

    // ensure the token is ascii
    _ = AsciiMetadataValue::try_from(&resp.session_token)
        .map_err(|_| anyhow!("session token is not ASCII"))?;

    Ok(EnrolledToken {
        refresh_token: resp.refresh_token,
        session_token: resp.session_token,
        expiration: get_expiration(resp.session_token_expiration),
    })
}

async fn enroll_loop(
    channel: Channel,
    deploy_token: String,
    hostname: String,
    machine_id: String,
) -> EnrolledToken {
    loop {
        match enroll(
            channel.clone(),
            deploy_token.clone(),
            hostname.clone(),
            machine_id.clone(),
        )
        .await
        {
            Ok(tok) => return tok,
            Err(err) => {
                error!("Agent enrollment failed: {err}");
                tokio::time::sleep(RETRY_INTERVAL).await;
            }
        }
    }
}

async fn refresh_loop(
    channel: Channel,
    refresh_token: String,
    auth_token: AuthToken,
    mut expiration: SystemTime,
) -> Result<()> {
    let mut token_svc = TokenServiceClient::with_interceptor(channel, auth_token.clone());

    loop {
        let mut deadline = expiration - EXPIRATION_SLACK;
        if deadline < SystemTime::now() {
            // shouldn't happen in prod but can happen with mocks
            deadline = expiration;
        }

        let dt: chrono::DateTime<chrono::Utc> = deadline.into();
        info!("Next session renewal at {}", dt.to_rfc2822());

        sleep_until(deadline).await;

        let req = pb::GetSessionTokenRequest {
            refresh_token: refresh_token.clone(),
            agent_version: VERSION.to_string(),
        };

        let resp = token_svc
            .get_session_token(req)
            .await
            .map_err(|e| anyhow!("{}", e.message()))?
            .into_inner();

        // ensure the token is ascii
        _ = AsciiMetadataValue::try_from(&resp.session_token)
            .map_err(|_| anyhow!("session token is not ASCII"))?;

        auth_token.set(&resp.session_token);
        expiration = get_expiration(resp.session_token_expiration);

        info!("Session renewed");
    }
}

fn get_expiration(expiration: Option<prost_types::Timestamp>) -> SystemTime {
    match expiration {
        Some(expiration) => match SystemTime::try_from(expiration) {
            Ok(expiration) => expiration,
            Err(_) => {
                error!("Invalid session expiration time");
                SystemTime::now() + DEFAULT_EXPIRATION
            }
        },
        None => {
            error!("Session token is missing expiration");
            SystemTime::now() + DEFAULT_EXPIRATION
        }
    }
}

fn data_stream<'a, R: Read + Send + 'a>(
    mut rd: R,
    result: Arc<Mutex<Result<()>>>,
) -> impl Stream<Item = pb::UploadSbomRequest> + Send {
    stream! {
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

async fn sleep_until(deadline: SystemTime) {
    // Avoid sleeping for more than a minute.
    // On virtualized machines, time is not always accurately kept
    while let Ok(remaining) = deadline.duration_since(SystemTime::now()) {
        let dur = std::cmp::min(remaining, Duration::from_secs(60));
        tokio::time::sleep(dur).await;
    }
}
