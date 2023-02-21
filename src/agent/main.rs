pub mod open_monitor;
pub mod control_plane;
pub mod sbom;
pub mod registry;

use std::{path::Path, time::SystemTime};

use anyhow::{Result, anyhow};
use gethostname::gethostname;
use log::*;
use clap::Parser;
use uuid::Uuid;

use open_monitor::OpenEvent;
use registry::Registry;
use sbom::Sbom;
use control_plane::pb;

const BASEOS_ID_PATH: &str = "/var/lib/edgebit/baseos-id";

#[derive(Parser)]
struct CliArgs {
    #[clap(long = "sbom")]
    sbom: Option<String>,

    #[clap(long = "no-sbom-upload")]
    no_sbom_upload: bool,
}

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    let args = CliArgs::parse();
    match run(&args).await {
        Ok(_) => {},
        Err(err) => {
            eprintln!("err: {err}");
            eprintln!("src: {}", err.source().unwrap());
        }
    }
}

async fn run(args: &CliArgs) -> Result<()> {
    let url = std::env::var("EDGEBIT_URL")
        .map_err(|_| anyhow!("Is EDGEBIT_URL env var set?"))?;

    let token = std::env::var("EDGEBIT_ID")
        .map_err(|_| anyhow!("Is EDGEBIT_ID env var set?"))?;

    info!("Connecting to Edgebit at {url}");
    let mut client = control_plane::Client::connect(
        url.try_into()?,
        token.try_into()?,
    ).await?;

    let sbom = match &args.sbom {
        Some(sbom_path) => {
            info!("Loading SBOM");
            let sbom_path: &Path = sbom_path.as_ref();
            let sbom = Sbom::load(sbom_path)?;

            if !args.no_sbom_upload {
                upload_sbom(&mut client, sbom_path, sbom.id()).await?;
            }

            sbom
        },
        None => {
            info!("Generating SBOM");
            let tmp_file = sbom::generate()?;
            let sbom = Sbom::load(tmp_file.path())?;

            if !args.no_sbom_upload {
                upload_sbom(&mut client, tmp_file.path(), sbom.id()).await?;
            }

            sbom
        },
    };

    let mut pkg_registry = Registry::from_sbom(&sbom)?;

    let workload = HostWorkload::load();

    info!("Registering workload");
    register_workload(&mut client, &workload, sbom.id()).await?;

    info!("Starting to monitor packages in use");
    report_in_use(&mut client, &mut pkg_registry, &workload.id).await?;
    Ok(())
}

async fn report_in_use(client: &mut control_plane::Client, pkg_registry: &mut Registry, workload_id: &str) -> Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<OpenEvent>(1000);
    let monitor_task = tokio::task::spawn_blocking(move || open_monitor::run(tx));

    // batch in 1s intervals

    while let Some(evt) = rx.recv().await {
        match evt.filename.into_string() {
            Ok(filename) => {
                let filenames = vec![filename];
                let pkgs = pkg_registry.get_packages(filenames);
                if !pkgs.is_empty() {
                    if let Err(err) = client.report_in_use(workload_id.to_string(), pkgs).await {
                        error!("report_in_use failed: {err}");
                    }
                }
            },

            Err(_) => (),
        }
    }

    monitor_task.await.unwrap().unwrap();

    Ok(())
}

async fn register_workload(client: &mut control_plane::Client, workload: &HostWorkload, image_id: String) -> Result<()> {
    let req = pb::UpsertWorkloadRequest {
        workload_id: workload.id.clone(),
        workload: Some(pb::Workload{
            group: workload.group.clone(),
            kind: Some(pb::workload::Kind::Host(pb::Host{
                hostname: workload.host.clone(),
                instance: String::new(),
                os_pretty_name: workload.os_pretty_name.clone(),
            })),
        }),
        start_time: Some(SystemTime::now().into()),
        end_time: None,
        image_id: image_id,
        image: Some(pb::Image{
            kind: Some(pb::image::Kind::Generic(pb::GenericImage{})),
        }),
    };

    client.upsert_workload(req).await
}

async fn upload_sbom(client: &mut control_plane::Client, path: &Path, image_id: String) -> Result<()> {
    info!("Uploading SBOM to EdgeBit");
    let f = std::fs::File::open(path)?;
    client.upload_sbom(image_id, f).await?;
    Ok(())
}

struct HostWorkload {
    id: String,
    group: Vec<String>,
    host: String,
    os_pretty_name: String,
}

impl HostWorkload {
    fn load() -> Self {
        let id = load_baseos_id();

        let host = gethostname()
            .to_string_lossy()
            .into_owned();

        let os_pretty_name = match rs_release::get_os_release() {
            Ok(mut os_release) => {
                os_release.remove("PRETTY_NAME")
                    .or_else(|| os_release.remove("NAME"))
                    .unwrap_or("Linux".to_string())
            },
            Err(err) => {
                error!("Failed to retrieve os-release: {err}");
                String::new()
            }
        };

        Self {
            id,
            group: Vec::new(),
            host,
            os_pretty_name,
        }
    }
}

fn load_baseos_id() -> String {
    if let Ok(id) = std::fs::read_to_string(BASEOS_ID_PATH) {
        return id;
    }

    let id = uuid_string();

    if let Err(err) = std::fs::write(BASEOS_ID_PATH, &id) {
        error!("Failed to save BaseOS workload ID to {BASEOS_ID_PATH}: {err}");
    }

    id
}

fn uuid_string() -> String {
    let mut buf = Uuid::encode_buffer();
    Uuid::new_v4()
        .as_hyphenated()
        .encode_lower(&mut buf)
        .to_string()
}