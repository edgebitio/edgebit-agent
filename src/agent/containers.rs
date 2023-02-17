use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::ffi::OsStr;
use std::time::UNIX_EPOCH;
use std::time::{SystemTime, Duration};

use anyhow::{Result};
use log::*;
use tokio::task::JoinHandle;
use tokio::sync::mpsc::Sender;
use bollard::{Docker};
use bollard::system::EventsOptions;
use bollard::models::{EventMessage, EventMessageTypeEnum};
use bollard::container::ListContainersOptions;
use futures::stream::{Stream, StreamExt};
use lazy_static::lazy_static;
use regex::Regex;
use chrono::{DateTime, offset::Utc};

const DOCKER_HOST: &str = "unix:///var/run/docker.sock";
const GRAPH_DRIVER_OVERLAYFS: &str = "overlay2";

lazy_static! {
    // It will be one of two patterns:
    // "/docker/<container_id>"
    // "docker-<container_id>.scope"
    static ref CGROUP_NAME_RE: Regex = Regex::new(r".*docker.([[:xdigit:]]{64})(?:\.scope)?").unwrap();
}

#[derive(Clone, Debug)]
pub struct ContainerInfo {
    pub name: Option<String>,
    pub image_id: Option<String>,
    pub image: Option<String>,
    pub rootfs: Option<String>,
    pub start_time: Option<SystemTime>,
    pub end_time: Option<SystemTime>,
}

pub enum ContainerEvent {
    Started(String, ContainerInfo),
    Stopped(String, ContainerInfo),
}

pub type ContainerMap = HashMap<String, ContainerInfo>;

pub struct DockerContainers {
    docker: Arc<Docker>,
    cont_map: Arc<Mutex<ContainerMap>>,
    events_task: JoinHandle<()>,
}

impl DockerContainers {
    pub async fn track(ch: Sender<ContainerEvent>) -> Result<Self> {
        let docker = Arc::new(
            Docker::connect_with_unix(
                DOCKER_HOST,
                5,
                bollard::API_DEFAULT_VERSION
            )?
        );

        let opts = EventsOptions {
            since: None,
            until: None,
            filters: [
                ("event", vec!["start", "die"]),
            ].into(),
        };

        let stream = docker.events(Some(opts));

        let cont_map = Arc::new(Mutex::new(ContainerMap::new()));

        let events_task = tokio::task::spawn(
            stream_events(docker.clone(), cont_map.clone(), stream, ch.clone())
        );

        // Load already running containers
        load_running(&docker, cont_map.clone()).await?;

        // Emit ContainerEvent::Started event for the running containers
        emit_existing(cont_map.clone(), ch).await;

        Ok(Self {
            docker,
            cont_map,
            events_task,
        })
    }

    pub fn id_from_cgroup(&self, cgroup: &str) -> Option<String> {
        let groups = CGROUP_NAME_RE.captures(cgroup)?;
        let id = groups.get(1)?.as_str();

        let cont_map = self.cont_map.lock().unwrap();
        if cont_map.contains_key(id) {
            Some(id.to_string())
        } else {
            None
        }
    }

    pub fn all(&self) -> ContainerMap {
        self.cont_map.lock()
            .unwrap()
            .clone()
    }
}

async fn stream_events(
    docker: Arc<Docker>,
    cont_map: Arc<Mutex<ContainerMap>>,
    mut stream: impl Stream<Item = Result<EventMessage, bollard::errors::Error>> + Unpin,
    ch: Sender<ContainerEvent>
) {
    while let Some(evt) = stream.next().await {
        debug!("Docker event: {evt:?}");

        match evt {
            Ok(msg) => process_event(&docker, &cont_map, msg, &ch).await,
            Err(err) => error!("failed to receive docker event: {err}"),
        }
    }

    debug!("Docker event streaming done");
}

async fn process_event(docker: &Docker, cont_map: &Mutex<ContainerMap>, msg: EventMessage, ch: &Sender<ContainerEvent>) {
    if msg.typ == Some(EventMessageTypeEnum::CONTAINER) {
        if let Some(action) = msg.action {
            if let Some(actor) = msg.actor {
                let id = actor.id.unwrap_or("(none)".to_string());

                match action.as_ref() {
                    "start" => {
                        debug!("Container {id} started");

                        match inspect_container(docker, &id).await {
                            Ok(info) => {
                                debug!("Container {id}: {info:?}");
                                cont_map.lock()
                                    .unwrap()
                                    .insert(id.clone(), info.clone());

                                _ = ch.send(ContainerEvent::Started(id, info)).await;
                            },
                            Err(err) => {
                                error!("Docker inspect_container({id}): {err}");
                                return;
                            }
                        }
                    },
                    "die" => {
                        debug!("Container {id} stopped");

                        // TODO: it's racy to rely on the cont_map to have the info since
                        // if this is called before load_running, it may not be there.
                        let info = {
                            cont_map.lock().unwrap().remove(&id)
                        };

                        if let Some(mut info) = info {
                            info.end_time = msg.time.map(systime_from_secs);

                            _ = ch.send(ContainerEvent::Stopped(id, info)).await;
                        }
                    },
                    _ => (),
                }
            }
        }
    }
}

async fn load_running(docker: &Docker, cont_map: Arc<Mutex<ContainerMap>>) -> Result<()> {
    let opts = ListContainersOptions::<&str>{
        filters: HashMap::from([
            ("status", vec!["running"])
        ]),
        ..Default::default()
    };

    let conts = docker.list_containers(Some(opts)).await?;

    let mut cont_map = cont_map.lock().unwrap();
    let cont_map: &mut ContainerMap = &mut cont_map;

    for c in conts {
        if c.id.is_none() {
            continue;
        }
        let id = c.id.unwrap();

        match inspect_container(docker, &id).await {
            Ok(info) => {
                debug!("Container {id}: {info:?}");
                cont_map.insert(id, info);
            },
            Err(err) => {
                error!("Docker inspect_container({id}): {err}");
                continue;
            }
        };
    }

    Ok(())
}

async fn inspect_container(docker: &Docker, id: &str) -> Result<ContainerInfo> {
    let cont_resp = docker.inspect_container(id, None).await?;

    let rootfs = match cont_resp.graph_driver {
        Some(mut driver) => {
            if driver.name == GRAPH_DRIVER_OVERLAYFS {
                driver.data.remove("MergedDir")
            } else {
                None
            }
        },
        None => None,
    };

    let image_tag = match &cont_resp.image {
        Some(id) => {
            docker.inspect_image(id).await?
                .repo_tags
                .map(|tags| head(&tags))
                .flatten()
        },
        None => None,
    };

    let (start_time, end_time) = match cont_resp.state {
        Some(state) => {
            // Convert from ISO 8601 string to SystemTime

            let started = state.started_at
                .map(|t| t.parse::<DateTime<Utc>>().ok())
                .flatten()
                .map(|t| t.into());

            let finished = state.finished_at
                .map(|t| t.parse::<DateTime<Utc>>().ok())
                .flatten()
                .map(|t| t.into());

            (started, finished)
        },
        None => (None, None)
    };

    Ok(ContainerInfo{
        name: cont_resp.name,
        image_id: cont_resp.image,
        image: image_tag,
        rootfs,
        start_time,
        end_time,
    })
}

async fn emit_existing(cont_map: Arc<Mutex<ContainerMap>>, ch: Sender<ContainerEvent>) {
    for (id, info) in cont_map.lock().unwrap().iter() {
        _ = ch.send(ContainerEvent::Started(id.clone(), info.clone())).await;
    }
}

fn head<T: Clone>(v: &[T]) -> Option<T> {
    if v.is_empty() {
        None
    } else {
        Some(v[0].clone())
    }
}

fn systime_from_secs(secs: i64) -> SystemTime {
    let dur = Duration::from_secs(secs as u64);
    UNIX_EPOCH + dur
}
