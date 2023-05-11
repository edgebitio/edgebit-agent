pub mod docker;
pub mod podman;
pub mod k8s_containerd;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, Duration};
use std::path::PathBuf;

use anyhow::{Result, anyhow};
use log::*;
use lazy_static::lazy_static;
use regex::Regex;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use tokio::net::{UnixStream, TcpStream};
use async_trait::async_trait;
use tonic::transport::channel::Channel;
use tonic::transport::{Uri, Endpoint};
use tower::service_fn;

use docker::DockerTracker;
use podman::PodmanTracker;
use k8s_containerd::K8sContainerdTracker;

use crate::config::Config;
use crate::scoped_path::*;
use crate::cloud_metadata::CloudMetadata;

// Docker containers will contain the id somewhere in the cgroup name
const CONTAINER_CLEANUP_LAG: Duration = Duration::from_secs(10);

lazy_static! {
    // Docker containers will contain the id somewhere in the cgroup name
    static ref CGROUP_NAME_RE: Regex = Regex::new(r".*([[:xdigit:]]{64})").unwrap();
}

#[derive(Clone, Debug)]
pub struct ContainerInfo {
    pub name: Option<String>,
    pub image_id: Option<String>,
    pub image: Option<String>,
    pub rootfs: Option<HostPath>,
    pub start_time: Option<SystemTime>,
    pub end_time: Option<SystemTime>,
    pub mounts: Vec<PathBuf>,
    pub labels: HashMap<String, String>,
}

#[derive(Debug)]
pub enum ContainerEvent {
    Started(String, ContainerInfo),
    Stopped(String, ContainerInfo),
}

pub type ContainerMap = HashMap<String, ContainerInfo>;

struct Inner {
    cont_map: Arc<Mutex<ContainerMap>>,
    ch: Sender<ContainerEvent>,
}

pub struct Containers {
    inner: Arc<Inner>,
    config: Arc<Config>,
    tasks: Vec<JoinHandle<()>>,
    cloud_meta: CloudMetadata,
}

impl Containers {
    pub fn new(config: Arc<Config>, cloud_meta: CloudMetadata, ch: Sender<ContainerEvent>) -> Self {
        let inner = Arc::new(Inner {
            cont_map: Arc::new(Mutex::new(ContainerMap::new())),
            ch,
        });

        Self {
            inner,
            config,
            tasks: Vec::new(),
            cloud_meta,
        }
    }

    pub fn track_docker(&mut self, host: String) {
        let ev: ContainerEventsPtr = self.inner.clone();
        let cloud_meta = self.cloud_meta.clone();

        let task = tokio::task::spawn(async move {
            loop {
                let tracker = match DockerTracker::connect(&host).await {
                    Ok(tracker) => tracker,
                    Err(err) => {
                        error!("Failed to connect to docker: {err}");
                        return;
                    }
                };

                match tracker.is_podman().await {
                    Ok(true) => {
                        info!("Podman detected, reconnecting");
                        match PodmanTracker::connect(&host).await {
                            Ok(tracker) => {
                                if let Err(err) = tracker.track(cloud_meta.clone(), ev.clone()).await {
                                    error!("Container monitoring: {err}");
                                }
                            },

                            Err(err) => error!("Failed to connect to podman: {err}"),
                        }
                    },
                    _ => {
                        if let Err(err) = tracker.track(cloud_meta.clone(), ev.clone()).await {
                            error!("Container monitoring: {err}");
                        }
                    }
                }

                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        self.tasks.push(task);
    }

    pub fn track_k8s(&mut self, host: String) {
        let ev: ContainerEventsPtr = self.inner.clone();
        let roots = HostPath::from(self.config.containerd_roots());

        let task = tokio::task::spawn(async move {
            loop {
                let tracker = K8sContainerdTracker::connect(&host, roots.clone()).await;
                if let Err(err) = tracker.track(ev.clone()).await {
                    error!("Container monitoring: {err}");
                }

                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
        self.tasks.push(task);
    }

    pub fn id_from_cgroup(&self, cgroup: &str) -> Option<String> {
        let groups = CGROUP_NAME_RE.captures(cgroup)?;
        let id = groups.get(1)?.as_str();

        let cont_map = self.inner.cont_map.lock().unwrap();
        if cont_map.contains_key(id) {
            Some(id.to_string())
        } else {
            None
        }
    }

    pub fn all(&self) -> ContainerMap {
        self.inner.cont_map.lock()
            .unwrap()
            .clone()
    }
}

#[async_trait]
pub trait ContainerRuntimeEvents {
    async fn container_started(&self, id: String, info: ContainerInfo);
    async fn container_stopped(&self, id: String, stop_time: SystemTime);
}

#[async_trait]
impl ContainerRuntimeEvents for Inner {
    async fn container_started(&self, id: String, info: ContainerInfo) {
        info!("Container started {id}: {info:?}");

        self.cont_map.lock()
            .unwrap()
            .insert(id.clone(), info.clone());

        self.ch.send(ContainerEvent::Started(id, info)).await.unwrap();
    }

    async fn container_stopped(&self, id: String, stop_time: SystemTime) {
        info!("Container {id} stopped");

        // TODO: it's racy to rely on the cont_map to have the info since
        // if this is called before load_running, it may not be there.
        if self.cont_map.lock().unwrap().contains_key(&id) {
            // Hack to deal with open events also being processed under delay
            let ch = self.ch.clone();
            let cont_map = self.cont_map.clone();

            tokio::task::spawn(async move {
                tokio::time::sleep(CONTAINER_CLEANUP_LAG).await;

                let info = {
                    cont_map.lock().unwrap().remove(&id)
                };

                if let Some(mut info) = info {
                    info.end_time = Some(stop_time);
                    _ = ch.send(ContainerEvent::Stopped(id, info)).await;
                }
            });
        }
    }
}

pub type ContainerEventsPtr = Arc<dyn ContainerRuntimeEvents + Send + Sync>;

pub async fn grpc_connect(host: &str) -> Result<Channel> {
    info!("Connecting to {host}");

    let ep = Endpoint::try_from("http://[::]").unwrap();

    let addr = host.strip_prefix("tcp://")
        .or_else(|| host.strip_prefix("http://"));

    let ch = if let Some(addr) = addr {
        let host = addr.to_string();
        ep.connect_with_connector(service_fn(move |_: Uri| TcpStream::connect(host.clone()))).await?
    } else if let Some(addr) = host.strip_prefix("unix://") {
        let path = PathBuf::from(addr);
        ep.connect_with_connector(service_fn(move |_: Uri| UnixStream::connect(path.clone()))).await?
    } else {
        return Err(anyhow!("Unsupported host scheme: {host}"));
    };

    Ok(ch)
}
