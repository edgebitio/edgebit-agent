pub mod open_monitor;
pub mod control_plane;
pub mod sbom;
pub mod registry;
pub mod containers;
pub mod fanotify;

use std::{path::Path, time::SystemTime};

use anyhow::{Result, anyhow};
use gethostname::gethostname;
use log::*;
use clap::Parser;
use uuid::Uuid;

use open_monitor::{OpenMonitor, OpenEvent};
use registry::Registry;
use sbom::Sbom;
use control_plane::pb;

const BASEOS_ID_PATH: &str = "/var/lib/edgebit/baseos-id";
use containers::{DockerContainers, ContainerEvent};

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

    info!("Registering BaseOS workload");
    register_workload(&mut client, &workload, sbom.id()).await?;

    info!("Starting to monitor packages in use");
    report_in_use(&mut client, &mut pkg_registry, &workload.id).await?;
    Ok(())
}

async fn report_in_use(client: &mut control_plane::Client, pkg_registry: &mut Registry, workload_id: &str) -> Result<()> {
    let (open_tx, mut open_rx) = tokio::sync::mpsc::channel::<OpenEvent>(1000);
    let monitor = OpenMonitor::start(open_tx)?;
    monitor.add_path("/")?;

    let (cont_tx, mut cont_rx) = tokio::sync::mpsc::channel::<ContainerEvent>(10);
    let conts = DockerContainers::track(cont_tx).await?;

    for (_, info) in conts.all() {
        if let Some(rootfs) = info.rootfs {
            monitor.add_path(&rootfs)?;
        }
    }

    loop {
        tokio::select!{
            evt = open_rx.recv() => {
                match evt {
                    Some(evt) => handle_open_event(pkg_registry, client, evt, workload_id.to_string()).await,
                    None => break,
                }
            },
            evt = cont_rx.recv() => {
                match evt {
                    Some(evt) => handle_container_event(client, &monitor, evt).await,
                    None => break,
                }
            }
        }
    }

    monitor.stop().await;

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

async fn handle_open_event(pkg_registry: &Registry, client: &mut control_plane::Client, evt: OpenEvent, workload_id: String) {
    match evt.filename.into_string() {
        Ok(filename) => {
            debug!("[{}]: {filename}", evt.cgroup_name);

            let filenames = vec![filename];
            let pkgs = pkg_registry.get_packages(filenames);
            if !pkgs.is_empty() {
                if let Err(err) = client.report_in_use(workload_id, pkgs).await {
                    error!("report_in_use failed: {err}");
                }
            }
        },

        Err(name) => {
            error!("Non UTF-8 filename opened: {}", name.to_string_lossy());
        }
    }
}

async fn handle_container_event(client: &mut control_plane::Client, monitor: &OpenMonitor, evt: ContainerEvent) {
    match evt {
        ContainerEvent::Started(id, info) => {
            match info.rootfs {
                Some(rootfs) => {
                    if let Err(err) = monitor.add_path(&rootfs) {
                        error!("Failed to start monitoring {} for container {}", rootfs, id);
                    }
                },
                None => error!("Container {id} started but rootfs missing"),
            }

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
        },
        ContainerEvent::Stopped(id, info) => {
            match info.rootfs {
                Some(rootfs) => {
                    if let Err(err) = monitor.remove_path(&rootfs) {
                        error!("Failed to stop monitoring {} for container {}", rootfs, id);
                    }
                },
                None => error!("Container {id} stopped but rootfs missing"),
            }

            _ = client.upsert_workload(pb::UpsertWorkloadRequest{
                workload_id: id,
                end_time: info.end_time.map(|t| t.into()),
                ..Default::default()
            }).await;
        }
    };
}

async fn upload_sbom(client: &mut control_plane::Client, path: &Path, image_id: String) -> Result<()> {
    info!("Uploading SBOM to Edgebit");
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
