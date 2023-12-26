pub mod chroot_cmd;
pub mod cloud_metadata;
pub mod config;
pub mod containers;
pub mod fanotify;
pub mod jitter;
pub mod label;
pub mod open_monitor;
pub mod platform;
pub mod sbom;
pub mod scoped_path;
pub mod version;
pub mod workloads;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{anyhow, Result};
use clap::Parser;
use log::*;
use prost_types::Timestamp;
use tokio::sync::mpsc::Receiver;
use uuid::Uuid;

use config::Config;
use containers::{ContainerInfo, Containers};
use jitter::JitteredDuration;
use platform::pb;
use sbom::Sbom;
use scoped_path::*;
use version::VERSION;
use workloads::host::HostWorkload;
use workloads::{Event, Workloads};

use crate::open_monitor::{FileOpenMonitorArc, NullOpenMonitor, OpenEvent, OpenMonitor};
use crate::workloads::track_container_lifecycle;

use crate::cloud_metadata::CloudMetadata;

const TIMESTAMP_INFINITY: Timestamp = Timestamp {
    seconds: 4134009600, // 2101-01-01
    nanos: 0,
};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(300);
const HEARTBEAT_JITTER: Duration = Duration::from_secs(30);

const MACHINE_ID_PATH: &str = "etc/machine-id";

#[derive(Parser)]
struct CliArgs {
    #[clap(long = "config")]
    config: Option<PathBuf>,

    #[clap(long = "sbom")]
    sbom: Option<PathBuf>,

    #[clap(long = "no-sbom-upload")]
    no_sbom_upload: bool,

    #[clap(long = "host-root")]
    host_root: Option<PathBuf>,

    #[clap(long = "hostname")]
    hostname: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = CliArgs::parse();

    match run(&args).await {
        Ok(_) => {}
        Err(err) => eprintln!("{err}"),
    }
}

async fn run(args: &CliArgs) -> Result<()> {
    let config_path = match &args.config {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(config::CONFIG_PATH),
    };

    let config = Config::load(config_path, args.hostname.clone(), args.host_root.clone())
        .map_err(|err| anyhow!("Error loading config file: {err}"))?;

    let config = Arc::new(config);

    std::env::set_var("RUST_LOG", config.log_level());
    pretty_env_logger::init();

    info!("EdgeBit Agent v{VERSION}");

    let url = config.edgebit_url();
    let token = config.edgebit_id();
    let host_root = RootFsPath::from(config.host_root());
    let machine_id = read_machine_id(&host_root.join(MACHINE_ID_PATH))?;

    info!("Connecting to EdgeBit at {url}");
    let mut client =
        platform::Client::connect(url.try_into()?, token, config.hostname(), machine_id).await?;

    let host_image_id = if config.machine_sbom() {
        load_sbom(args, config.clone(), &mut client).await?.id()
    } else {
        Uuid::new_v4().to_string()
    };

    client.reset_workloads().await?;

    let cloud_meta = CloudMetadata::load().await;

    let (open_mon, open_rx) = if config.pkg_tracking() {
        let (tx, rx) = tokio::sync::mpsc::channel::<OpenEvent>(1000);
        let mon: FileOpenMonitorArc = Arc::new(OpenMonitor::start(tx)?);
        (mon, Some(rx))
    } else {
        let mon: FileOpenMonitorArc = Arc::new(NullOpenMonitor);
        (mon, None)
    };

    let (cont_tx, cont_rx) = tokio::sync::mpsc::channel(10);
    let mut containers = Containers::new(config.clone(), cloud_meta.clone(), cont_tx);
    if let Some(host) = config.docker_host() {
        containers.track_docker(host);
    }

    if let Some(host) = config.containerd_host() {
        containers.track_k8s(host);
    }

    let (events_tx, events_rx) = tokio::sync::mpsc::channel::<Event>(1000);
    let host_wrkld = HostWorkload::new(
        host_image_id,
        config.clone(),
        open_mon.clone(),
        cloud_meta.host_labels(),
    )?;

    register_host_workload(&mut client, &host_wrkld, config.labels()).await?;

    let containers = Arc::new(containers);
    let workloads = Workloads::new(config.clone(), host_wrkld, open_mon.clone());

    tokio::task::spawn(track_container_lifecycle(
        cont_rx,
        workloads.containers.clone(),
        events_tx.clone(),
    ));

    if let Some(rx) = open_rx {
        tokio::task::spawn(workloads::in_use::track_pkgs_in_use(
            containers.clone(),
            workloads.clone(),
            rx,
        ));
    }

    info!("Monitoring workloads");
    monitor(config, workloads, &mut client, events_rx).await;

    Ok(())
}

async fn monitor(
    config: Arc<Config>,
    workloads: Workloads,
    client: &mut platform::Client,
    mut events: Receiver<Event>,
) {
    let mut periods = tokio::time::interval(Duration::from_millis(1000));
    let labels = config.labels();

    let mut last_reported = Instant::now();
    let mut jitter = JitteredDuration::new(HEARTBEAT_JITTER);

    loop {
        tokio::select! {
            evt = events.recv() => {
                match evt {
                    Some(Event::ContainerStarted(id, info)) => handle_container_started(client, id, info, labels.clone()).await,
                    Some(Event::ContainerStopped(id, info)) => handle_container_stopped(client, id, info).await,
                    None => break,
                }
            },
            _ = periods.tick() => {
                let mut reported = false;

                let (host_id, pkgs) = workloads.host.lock()
                    .unwrap()
                    .flush_in_use();

                if !pkgs.is_empty() {
                    if let Err(err) = client.report_in_use(host_id.clone(), pkgs).await {
                        error!("Failed to report-in-use: {err}");
                    }

                    reported = true;
                }

                let batches = workloads.containers.lock()
                    .unwrap()
                    .flush_in_use();

                for (id, pkgs) in batches {
                    if !pkgs.is_empty() {
                        if let Err(err) = client.report_in_use(id, pkgs).await {
                            error!("Failed to report-in-use: {err}");
                        }

                        reported = true;
                    }
                }

                if reported {
                    last_reported = Instant::now();
                } else if last_reported.elapsed() >= jitter.add(HEARTBEAT_INTERVAL) {
                    if let Err(err) = client.report_in_use(host_id, Vec::new()).await {
                        error!("Failed to report-in-use (heartbeat): {err}");
                    }

                    last_reported = Instant::now();
                }
            }
        }
    }
}

fn to_upsert_workload_req(
    workload: &HostWorkload,
    mut extra_labels: HashMap<String, String>,
) -> pb::UpsertWorkloadRequest {
    let mut labels = workload.labels.clone();
    labels.extend(extra_labels.drain());

    pb::UpsertWorkloadRequest {
        workload_id: workload.id.clone(),
        workload: Some(pb::Workload {
            labels,
            kind: Some(pb::workload::Kind::Host(pb::Host {
                hostname: workload.hostname.clone(),
                instance: String::new(),
                os_pretty_name: workload.os_pretty_name.clone(),
            })),
        }),
        start_time: Some(SystemTime::now().into()),
        end_time: Some(TIMESTAMP_INFINITY),
        image_id: workload.image_id.clone(),
        image: Some(pb::Image {
            kind: Some(pb::image::Kind::Generic(pb::GenericImage {})),
        }),
        machine_id: String::new(),
    }
}

async fn handle_container_started(
    client: &mut platform::Client,
    id: String,
    info: ContainerInfo,
    mut extra_labels: HashMap<String, String>,
) {
    info!("Registering container started: {id}");
    debug!("Container info: {info:?}");

    let mut labels = info.labels.clone();
    labels.extend(extra_labels.drain());

    let res = client
        .upsert_workload(pb::UpsertWorkloadRequest {
            workload_id: id,
            workload: Some(pb::Workload {
                labels,
                kind: Some(pb::workload::Kind::Container(pb::Container {
                    name: info.name.unwrap_or_default(),
                })),
            }),
            start_time: info.start_time.map(|t| t.into()),
            end_time: Some(TIMESTAMP_INFINITY),
            image_id: info.image_id.unwrap_or_default(),
            image: Some(pb::Image {
                kind: Some(pb::image::Kind::Docker(pb::DockerImage {
                    tag: info.image.unwrap_or_default(),
                })),
            }),
            machine_id: String::new(),
        })
        .await;

    if let Err(err) = res {
        error!("Failed to register container started: {err}");
    }
}

async fn handle_container_stopped(client: &mut platform::Client, id: String, info: ContainerInfo) {
    info!("Registering container stopped: {id}");

    let res = client
        .upsert_workload(pb::UpsertWorkloadRequest {
            workload_id: id,
            end_time: info.end_time.map(|t| t.into()),
            ..Default::default()
        })
        .await;

    if let Err(err) = res {
        error!("Failed to register container stopped: {err}");
    }
}

async fn load_sbom(
    args: &CliArgs,
    config: Arc<Config>,
    client: &mut platform::Client,
) -> Result<Sbom> {
    let sbom = match &args.sbom {
        Some(sbom_path) => {
            info!("Loading SBOM");
            let sbom = Sbom::load(&sbom_path.into())?;

            if !args.no_sbom_upload {
                upload_sbom(client, sbom_path, sbom.id()).await?;
            }

            sbom
        }
        None => {
            info!("Generating SBOM");
            let host_root = RootFsPath::from(config.host_root());
            let tmp_file = sbom::generate(config.clone(), &host_root).await?;
            let sbom = Sbom::load(&tmp_file.path().into())?;

            if !args.no_sbom_upload {
                upload_sbom(client, tmp_file.path(), sbom.id()).await?;
            }

            sbom
        }
    };

    Ok(sbom)
}

async fn upload_sbom(client: &mut platform::Client, path: &Path, image_id: String) -> Result<()> {
    info!("Uploading SBOM to EdgeBit");
    let f = std::fs::File::open(path)?;
    client.upload_sbom(image_id, f).await?;
    Ok(())
}

async fn register_host_workload(
    client: &mut platform::Client,
    workload: &HostWorkload,
    extra_labels: HashMap<String, String>,
) -> Result<()> {
    info!("Registering BaseOS workload");
    let req = to_upsert_workload_req(workload, extra_labels);
    client.upsert_workload(req).await?;
    Ok(())
}

fn read_machine_id(path: &RootFsPath) -> Result<String> {
    match std::fs::read_to_string(path.as_raw()) {
        Ok(id) => {
            let id = id.trim();
            if id.len() != 32 {
                Err(anyhow!(
                    "MachineID ({}) is not 32 chars long",
                    path.display()
                ))
            } else if id == "00000000000000000000000000000000" {
                Err(anyhow!(
                    "MachineID ({}) is not valid -- all zeros",
                    path.display()
                ))
            } else {
                Ok(id.to_string())
            }
        }
        Err(err) => Err(anyhow!(
            "failed to read MachineID from {}: {err}",
            path.display()
        )),
    }
}
