use std::collections::HashMap;
use std::sync::{Arc};
use std::time::UNIX_EPOCH;
use std::time::{SystemTime, Duration};

use anyhow::{Result, anyhow};
use log::*;
use bollard::{Docker};
use bollard::system::EventsOptions;
use bollard::models::{EventMessage, EventMessageTypeEnum};
use bollard::container::ListContainersOptions;
use futures::stream::StreamExt;
use lazy_static::lazy_static;
use chrono::{DateTime, offset::Utc, offset::FixedOffset};

use super::{ContainerEventsPtr, ContainerInfo};
use crate::scoped_path::*;

const GRAPH_DRIVER_OVERLAYFS: &str = "overlay2";
const DOCKER_CONNECT_TIMEOUT: u64 = 5;

lazy_static! {
    static ref DT_UNIX_EPOCH: DateTime<FixedOffset> = DateTime::parse_from_rfc3339("1970-01-01T00:00:00-00:00").unwrap();
}

pub struct DockerTracker {
    docker: Docker,
}

impl DockerTracker {
    pub async fn connect(host: &str) -> Result<Self> {
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

        Ok(Self{
            docker,
        })
    }

    pub async fn is_podman(&self) -> Result<bool> {
        // Check if this is really Docker or actually Podman
        if let Some(components) = self.docker.version().await?.components {
            for comp in components {
                if comp.name.to_lowercase().contains("podman") {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    pub async fn track(self, events: ContainerEventsPtr) -> Result<()> {
        let docker = Arc::new(self.docker);

        let events_task = tokio::task::spawn(
            stream_events(docker.clone(), events.clone())
        );

        // Load already running containers
        load_running(&docker, events.clone()).await?;

        events.flush().await;

        _ = events_task.await;

        Ok(())
    }
}

async fn stream_events(
    docker: Arc<Docker>,
    events: ContainerEventsPtr
) {
    let opts = EventsOptions {
        since: None,
        until: None,
        filters: [
            ("event", vec!["start", "die"]),
        ].into(),
    };

    let mut stream = docker.events(Some(opts));

    while let Some(evt) = stream.next().await {
        debug!("Docker event: {evt:?}");

        match evt {
            Ok(msg) => process_event(&docker, msg, events.clone()).await,
            Err(err) => error!("failed to receive docker event: {err}"),
        }
    }

    debug!("Docker event streaming done");
}

async fn process_event(docker: &Docker, msg: EventMessage, events: ContainerEventsPtr) {
    if msg.typ == Some(EventMessageTypeEnum::CONTAINER) {
        if let Some(action) = msg.action {
            if let Some(actor) = msg.actor {
                let id = actor.id.unwrap_or("(none)".to_string());

                match action.as_ref() {
                    "start" => {
                        debug!("Container {id} started");

                        match inspect_container(docker, &id).await {
                            Ok(info) => {
                                events.container_started(id, info).await;
                            },
                            Err(err) => {
                                error!("Failed to inspect container(id={id}): {err}");
                                return;
                            }
                        }
                    },
                    "die" => {
                        let end_time = msg.time
                            .map(systime_from_secs)
                            .unwrap_or(SystemTime::now());

                        events.container_stopped(id, end_time).await;
                    },
                    _ => (),
                }
            }
        }
    }
}

async fn load_running(docker: &Docker, events: ContainerEventsPtr) -> Result<()> {
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
                events.add_container(id, info);
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
                    .map(|path| HostPath::from(path))
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

fn systime_from_secs(secs: i64) -> SystemTime {
    let dur = Duration::from_secs(secs as u64);
    UNIX_EPOCH + dur
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

fn head<T: Clone>(v: &[T]) -> Option<T> {
    if v.is_empty() {
        None
    } else {
        Some(v[0].clone())
    }
}
