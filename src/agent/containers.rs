use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;
use std::time::{SystemTime, Duration};

use anyhow::{Result, anyhow};
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
use chrono::{DateTime, offset::Utc, offset::FixedOffset};

const GRAPH_DRIVER_OVERLAYFS: &str = "overlay2";
const DOCKER_CONNECT_TIMEOUT: u64 = 5;

lazy_static! {
    // Docker containers will contain the id somewhere in the cgroup name
    static ref CGROUP_NAME_RE: Regex = Regex::new(r".*([[:xdigit:]]{64})").unwrap();

    static ref DT_UNIX_EPOCH: DateTime<FixedOffset> = DateTime::parse_from_rfc3339("1970-01-01T00:00:00-00:00").unwrap();
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
    cont_map: Arc<Mutex<ContainerMap>>,
    task: JoinHandle<()>,
}

impl DockerContainers {
    pub fn track(host: String, ch: Sender<ContainerEvent>) -> Self {
        let cont_map = Arc::new(Mutex::new(ContainerMap::new()));

        let task = tokio::task::spawn(run(host, cont_map.clone(), ch));

        Self {
            cont_map,
            task,
        }
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

async fn connect_with_retry(host: &str) -> Result<Docker> {
    let docker = docker_connection(host)?;

    let mut quiet = false;
    loop {
        match docker.ping().await {
            Ok(_) => {
                info!("Connected to Docker daemon");
                break;
            },
            Err(err) => {
                if quiet {
                    debug!("Failed to connect to Docker daemon: {err}");
                } else {
                    error!("Failed to connect to Docker daemon: {err}");
                    quiet = true;
                }

                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }

    Ok(docker)
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

    for c in conts {
        if c.id.is_none() {
            continue;
        }
        let id = c.id.unwrap();

        match inspect_container(docker, &id).await {
            Ok(info) => {
                debug!("Container {id}: {info:?}");
                cont_map.lock().unwrap().insert(id, info);
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
                .filter(|t| t > &DT_UNIX_EPOCH)
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
    let events: Vec<_> = cont_map.lock()
        .unwrap()
        .iter()
        .map(|(id, info)| ContainerEvent::Started(id.clone(), info.clone()))
        .collect();

    for ev in events {
        if let Err(err) = ch.send(ev).await {
            error!("Failed to send events on a channel: {err}");
        }
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

async fn run(host: String, cont_map: Arc<Mutex<ContainerMap>>, ch: Sender<ContainerEvent>) {
    loop {
        match connect_with_retry(&host).await {
            Ok(docker) => {
                if let Err(err) = monitor_containers(docker, cont_map.clone(), ch.clone()).await {
                    error!("Container monitoring: {err}");
                }
            },

            Err(err) => error!("Failed to join connect_with_retry: {err}"),
        }
    }
}

fn docker_connection(host: &str) -> Result<Docker> {
    if host.starts_with("tcp://") || host.starts_with("http://") {
        Ok(Docker::connect_with_http(host, DOCKER_CONNECT_TIMEOUT, bollard::API_DEFAULT_VERSION)?)
    } else if host.starts_with("unix://") {
        Ok(Docker::connect_with_unix(host, DOCKER_CONNECT_TIMEOUT, bollard::API_DEFAULT_VERSION)?)
    } else {
        Err(anyhow!("Unsupported Docker host scheme: {host}"))
    }
}

async fn monitor_containers(docker: Docker, cont_map: Arc<Mutex<ContainerMap>>, ch: Sender<ContainerEvent>) -> Result<()> {
    let opts = EventsOptions {
        since: None,
        until: None,
        filters: [
            ("event", vec!["start", "die"]),
        ].into(),
    };

    let docker = Arc::new(docker);

    let stream = docker.events(Some(opts));

    let events_task = tokio::task::spawn(
        stream_events(docker.clone(), cont_map.clone(), stream, ch.clone())
    );

    // Load already running containers
    load_running(&docker, cont_map.clone()).await?;

    // Emit ContainerEvent::Started event for the running containers
    emit_existing(cont_map.clone(), ch).await;

    _ = events_task.await;

    Ok(())
}