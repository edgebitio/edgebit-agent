pub mod open_monitor;
pub mod control_plane;
pub mod sbom;
pub mod registry;
pub mod containers;
pub mod fanotify;
pub mod workload_mgr;

use std::{path::Path, time::SystemTime};

use anyhow::{Result, anyhow};
use log::*;
use clap::Parser;
use tokio::sync::mpsc::{Receiver};

use sbom::Sbom;
use control_plane::pb;
use containers::ContainerInfo;
use workload_mgr::{WorkloadManager, Event, HostWorkload};

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

    let version = env!("CARGO_PKG_VERSION");
    info!("EdgeBit Agent v{version}");

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

    info!("Connecting to EdgeBit at {url}");
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

    let (events_tx, events_rx) = tokio::sync::mpsc::channel::<Event>(1000);
    let wl_mgr = WorkloadManager::start(sbom, events_tx).await?;

    info!("Registering BaseOS workload");
    register_host_workload(&mut client, wl_mgr.get_host_workload()).await?;

    info!("Starting to monitor packages in use");
    report_in_use(&mut client, &wl_mgr, events_rx).await;

    Ok(())
}

async fn report_in_use(client: &mut control_plane::Client, workloads: &WorkloadManager, mut events: Receiver<Event>) {
    loop {
        match events.recv().await {
            Some(Event::ContainerStarted(id, info)) => handle_container_started(client, id, info).await,
            Some(Event::ContainerStopped(id, info)) => handle_container_stopped(client, id, info).await,
            Some(Event::PackageInUse(id, pkgs)) => _ = client.report_in_use(id, pkgs).await,
            None => break,
        }
    }
}

async fn register_host_workload(client: &mut control_plane::Client, workload: &HostWorkload) -> Result<()> {
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
        image_id: workload.image_id.clone(),
        image: Some(pb::Image{
            kind: Some(pb::image::Kind::Generic(pb::GenericImage{})),
        }),
    };

    client.upsert_workload(req).await
}

async fn handle_container_started(client: &mut control_plane::Client, id: String, info: ContainerInfo) {
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

async fn handle_container_stopped(client: &mut control_plane::Client, id: String, info: ContainerInfo) {
    _ = client.upsert_workload(pb::UpsertWorkloadRequest{
        workload_id: id,
        end_time: info.end_time.map(|t| t.into()),
        ..Default::default()
    }).await;
}

async fn upload_sbom(client: &mut control_plane::Client, path: &Path, image_id: String) -> Result<()> {
    info!("Uploading SBOM to EdgeBit");
    let f = std::fs::File::open(path)?;
    client.upload_sbom(image_id, f).await?;
    Ok(())
}