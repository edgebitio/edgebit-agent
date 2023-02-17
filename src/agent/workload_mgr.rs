use std::sync::Arc;
use std::collections::HashMap;

use anyhow::{Result, anyhow};
use log::*;
use gethostname::gethostname;
use tokio::sync::mpsc::{Sender, Receiver};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::registry::{Registry, PkgRef};
use crate::containers::{DockerContainers, ContainerInfo, ContainerEvent};
use crate::open_monitor::{OpenMonitor, OpenEvent};
use crate::sbom::Sbom;

const BASEOS_ID_PATH: &str = "/var/lib/edgebit/baseos-id";

pub enum Event {
    ContainerStarted(String, ContainerInfo),
    ContainerStopped(String, ContainerInfo),
    PackageInUse(String, Vec<PkgRef>),
}

struct Inner {
    containers: DockerContainers,
    open_monitor: OpenMonitor,
    host_workload: HostWorkload,
    container_workloads: HashMap<String, ContainerWorkload>,
    events: Sender<Event>,
}

pub struct WorkloadManager {
    inner: Arc<Inner>,
    run_task: JoinHandle<()>,
}

impl WorkloadManager {
    pub async fn start(host_sbom: Sbom, events: Sender<Event>) -> Result<Self> {
        let (open_tx, open_rx) = tokio::sync::mpsc::channel::<OpenEvent>(1000);
        let open_monitor = OpenMonitor::start(open_tx)?;

        let (cont_tx, cont_rx) = tokio::sync::mpsc::channel::<ContainerEvent>(10);
        let containers = DockerContainers::track(cont_tx).await?;

        let host_workload = HostWorkload::load(host_sbom)?;

        open_monitor.add_path("/")?;

        for (_, info) in containers.all() {
            if let Some(rootfs) = info.rootfs {
                open_monitor.add_path(&rootfs)?;
            }
        }

        let inner = Arc::new(Inner{
            containers,
            open_monitor,
            host_workload,
            container_workloads: HashMap::new(),
            events,
        });

        let run_task = tokio::task::spawn(
            run(inner.clone(), open_rx, cont_rx)
        );

        Ok(Self{
            inner,
            run_task,
        })
    }

    pub fn get_host_workload(&self) -> &HostWorkload {
        &self.inner.host_workload
    }
}

async fn run(inner: Arc<Inner>, mut open_rx: Receiver<OpenEvent>, mut cont_rx: Receiver<ContainerEvent>) {
    loop {
        tokio::select!{
            evt = open_rx.recv() => {
                match evt {
                    Some(evt) => handle_open_event(&inner, evt).await,
                    None => break,
                }
            },
            evt = cont_rx.recv() => {
                match evt {
                    Some(evt) => handle_container_event(&inner, evt).await,
                    None => break,
                }
            }
        }
    }
}

async fn handle_open_event(inner: &Inner, evt: OpenEvent) {
    match evt.filename.into_string() {
        Ok(filename) => {
            debug!("[{}]: {filename}", evt.cgroup_name);
            let filenames = vec![filename];

            let in_use = match inner.containers.id_from_cgroup(&evt.cgroup_name) {
                Some(id) => {
                    let pkg = PkgRef{
                        id: String::new(),
                        filenames,
                    };

                    Event::PackageInUse(id, vec![pkg])
                },
                None => {
                    let pkgs = inner.host_workload.pkgs.get_packages(filenames);
                    if pkgs.is_empty() {
                        return;
                    }

                    Event::PackageInUse(inner.host_workload.id.clone(), pkgs)
                }
            };

            _ = inner.events.send(in_use).await;
        },

        Err(name) => {
            error!("Non UTF-8 filename opened: {}", name.to_string_lossy());
        }
    }
}

async fn handle_container_event(inner: &Inner, evt: ContainerEvent) {
    match evt {
        ContainerEvent::Started(id, info) => {
            match &info.rootfs {
                Some(rootfs) => {
                    if let Err(err) = inner.open_monitor.add_path(rootfs) {
                        error!("Failed to start monitoring {} for container {}", rootfs, id);
                    }
                },
                None => error!("Container {id} started but rootfs missing"),
            }

            _ = inner.events.send(Event::ContainerStarted(id, info)).await;
        },
        ContainerEvent::Stopped(id, info) => {
            match &info.rootfs {
                Some(rootfs) => {
                    if let Err(err) = inner.open_monitor.remove_path(rootfs) {
                        error!("Failed to stop monitoring {} for container {}", rootfs, id);
                    }
                },
                None => error!("Container {id} stopped but rootfs missing"),
            }

            _ = inner.events.send(Event::ContainerStopped(id, info)).await;
        }
    };
}

pub struct HostWorkload {
    pub id: String,
    pub group: Vec<String>,
    pub host: String,
    pub os_pretty_name: String,
    pub image_id: String,
    pkgs: Registry,
}

impl HostWorkload {
    fn load(sbom: Sbom) -> Result<Self> {
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

        Ok(Self{
            id,
            group: Vec::new(),
            host,
            os_pretty_name,
            image_id: sbom.id(),
            pkgs: Registry::from_sbom(&sbom)?,
        })
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

struct ContainerWorkload {}
