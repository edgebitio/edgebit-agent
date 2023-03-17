pub mod docker;
pub mod podman;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, Duration};

use log::*;
use lazy_static::lazy_static;
use regex::Regex;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use async_trait::async_trait;

use docker::DockerTracker;
use podman::PodmanTracker;

use crate::scoped_path::*;

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
}

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
    tracker_task: JoinHandle<()>,
}

impl Containers {
    pub fn track(host: String, ch: Sender<ContainerEvent>) -> Self {
        let inner = Arc::new(Inner {
            cont_map: Arc::new(Mutex::new(ContainerMap::new())),
            ch: ch.clone(),
        });

        let ev: ContainerEventsPtr = inner.clone();

        let tracker_task = tokio::task::spawn(async move {
            loop {
                let tracker = DockerTracker::connect(&host).await.unwrap();
                match tracker.is_podman().await {
                    Ok(true) => {
                        info!("Podman detected, reconnecting");
                        match PodmanTracker::connect(&host).await {
                            Ok(tracker) => {
                                if let Err(err) = tracker.track(ev.clone()).await {
                                    error!("Container monitoring: {err}");
                                }
                            },

                            Err(err) => error!("Failed to connect to podman: {err}"),
                        }

                    },
                    _ => {
                        if let Err(err) = tracker.track(ev.clone()).await {
                            error!("Container monitoring: {err}");
                        }
                    }
                }

                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        Self {
            inner,
            tracker_task,
        }
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
    fn add_container(&self, id: String, info: ContainerInfo);
    async fn flush(&self);
    async fn container_started(&self, id: String, info: ContainerInfo);
    async fn container_stopped(&self, id: String, stop_time: SystemTime);
}

#[async_trait]
impl ContainerRuntimeEvents for Inner {
    fn add_container(&self, id: String, info: ContainerInfo) {
        self.cont_map.lock()
            .unwrap()
            .insert(id, info);
    }

    async fn flush(&self) {
        let events: Vec<_> = self.cont_map.lock()
            .unwrap()
            .iter()
            .map(|(id, info)| ContainerEvent::Started(id.clone(), info.clone()))
            .collect();

        for ev in events {
            if let Err(err) = self.ch.send(ev).await {
                error!("Failed to send events on a channel: {err}");
            }
        }
    }

    async fn container_started(&self, id: String, info: ContainerInfo) {
        debug!("Container {id}: {info:?}");

        self.cont_map.lock()
            .unwrap()
            .insert(id.clone(), info.clone());

        _ = self.ch.send(ContainerEvent::Started(id, info)).await;
    }

    async fn container_stopped(&self, id: String, stop_time: SystemTime) {
        debug!("Container {id} stopped");

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
