pub mod config;
pub mod open_monitor;
pub mod platform;
pub mod sbom;
pub mod registry;
pub mod containers;
pub mod fanotify;
pub mod workload_mgr;

use std::path::{Path, PathBuf};
use std::time::SystemTime;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use log::*;
use clap::Parser;
use tokio::sync::mpsc::{Receiver};

use config::Config;
use sbom::Sbom;
use platform::pb;
use containers::ContainerInfo;
use workload_mgr::{WorkloadManager, Event, HostWorkload};

#[derive(Parser)]
struct CliArgs {
    #[clap(long = "config")]
    config: Option<PathBuf>,

    #[clap(long = "sbom")]
    sbom: Option<String>,

    #[clap(long = "no-sbom-upload")]
    no_sbom_upload: bool,
}

#[tokio::main]
async fn main() {
    let args = CliArgs::parse();

    match run(&args).await {
        Ok(_) => {},
        Err(err) => eprintln!("{err}"),
    }
}

async fn run(args: &CliArgs) -> Result<()> {
    let config_path = match &args.config {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(config::CONFIG_PATH),
    };

    let config = Config::load(config_path)
        .map_err(|err| anyhow!("Error loading config file: {err}"))?;

    let config = Arc::new(config);

    std::env::set_var("RUST_LOG", config.log_level());
    pretty_env_logger::init();

    let version = env!("CARGO_PKG_VERSION");
    info!("EdgeBit Agent v{version}");

    let url = config.edgebit_url();
    let token = config.edgebit_id();

    info!("Connecting to EdgeBit at {url}");
    let mut client = platform::Client::connect(
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
            let tmp_file = sbom::generate(config.clone())?;
            let sbom = Sbom::load(tmp_file.path())?;

            if !args.no_sbom_upload {
                upload_sbom(&mut client, tmp_file.path(), sbom.id()).await?;
            }

            sbom
        },
    };

    let (events_tx, events_rx) = tokio::sync::mpsc::channel::<Event>(1000);
    let wl_mgr = WorkloadManager::start(sbom, config, events_tx).await?;

    info!("Registering BaseOS workload");
    let req = wl_mgr.with_host_workload(to_upsert_workload_req);
    client.upsert_workload(req).await?;

    info!("Starting to monitor packages in use");
    report_in_use(&mut client, events_rx).await;

    Ok(())
}

async fn report_in_use(client: &mut platform::Client, mut events: Receiver<Event>) {
    loop {
        match events.recv().await {
            Some(Event::ContainerStarted(id, info)) => handle_container_started(client, id, info).await,
            Some(Event::ContainerStopped(id, info)) => handle_container_stopped(client, id, info).await,
            Some(Event::PackageInUse(id, pkgs)) => _ = client.report_in_use(id, pkgs).await,
            None => break,
        }
    }
}

fn to_upsert_workload_req(workload: &HostWorkload) -> pb::UpsertWorkloadRequest {
    pb::UpsertWorkloadRequest {
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
        image_id: workload.image_id.clone(),
        image: Some(pb::Image{
            kind: Some(pb::image::Kind::Generic(pb::GenericImage{})),
        }),
    }
}

async fn handle_container_started(client: &mut platform::Client, id: String, info: ContainerInfo) {
    _ = client.upsert_workload(pb::UpsertWorkloadRequest{
            workload_id: id,
            workload: Some(pb::Workload{
                group: Vec::new(),
                kind: Some(pb::workload::Kind::Container(pb::Container{
                    name: info.name.unwrap_or(String::new()),
                })),
            }),
            start_time: info.start_time.map(|t| t.into()),
            end_time: None,
            image_id: info.image_id.unwrap_or(String::new()),
            image: Some(pb::Image{
                kind: Some(pb::image::Kind::Docker(pb::DockerImage{
                    tag: info.image.unwrap_or(String::new()),
                })),
            }),
    }).await;
}

async fn handle_container_stopped(client: &mut platform::Client, id: String, info: ContainerInfo) {
    _ = client.upsert_workload(pb::UpsertWorkloadRequest{
        workload_id: id,
        end_time: info.end_time.map(|t| t.into()),
        ..Default::default()
    }).await;
}

async fn upload_sbom(client: &mut platform::Client, path: &Path, image_id: String) -> Result<()> {
    info!("Uploading SBOM to EdgeBit");
    let f = std::fs::File::open(path)?;
    client.upload_sbom(image_id, f).await?;
    Ok(())
}