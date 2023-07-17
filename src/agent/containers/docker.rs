use std::collections::HashMap;
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use std::time::{SystemTime, Duration};

use anyhow::{Result, anyhow};
use log::*;
use bollard::Docker;
use bollard::system::EventsOptions;
use bollard::models::{EventMessage, EventMessageTypeEnum, ContainerStateStatusEnum};
use bollard::container::ListContainersOptions;
use futures::stream::StreamExt;
use lazy_static::lazy_static;
use chrono::{DateTime, offset::Utc, offset::FixedOffset};

use super::{ContainerEventsPtr, ContainerInfo};
use crate::scoped_path::*;
use crate::cloud_metadata::CloudMetadata;

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

    pub async fn track(self, cloud_meta: CloudMetadata, events: ContainerEventsPtr) -> Result<()> {
        let tracker = Arc::new(Tracker{
            docker: self.docker,
            cloud_meta,
            events,
        });

        let events_task = {
            let tracker = tracker.clone();
            tokio::task::spawn(async move {
                tracker.stream_events().await;
            })
        };

        // Load already running containers
        tracker.load_running().await?;

        _ = events_task.await;

        Ok(())
    }
}

struct Tracker {
    docker: Docker,
    cloud_meta: CloudMetadata,
    events: ContainerEventsPtr,
}

impl Tracker {
    async fn stream_events(&self) {
        let opts = EventsOptions {
            since: None,
            until: None,
            filters: [
                ("event", vec!["start", "die"]),
            ].into(),
        };

        let mut stream = self.docker.events(Some(opts));

        while let Some(evt) = stream.next().await {
            debug!("Docker event: {evt:?}");

            match evt {
                Ok(msg) => self.process_event(msg).await,
                Err(err) => error!("failed to receive docker event: {err}"),
            }
        }

        debug!("Docker event streaming done");
    }

    async fn process_event(&self, msg: EventMessage) {
        if msg.typ == Some(EventMessageTypeEnum::CONTAINER) {
            if let Some(action) = msg.action {
                if let Some(actor) = msg.actor {
                    let id = actor.id.unwrap_or("(none)".to_string());

                    match action.as_ref() {
                        "start" => {
                            debug!("Container {id} started");

                            match self.inspect_container(&id).await {
                                Ok(info) => {
                                    self.events.container_started(id, info).await;
                                },
                                Err(err) => {
                                    error!("Failed to inspect container(id={id}): {err}");
                                }
                            }
                        },
                        "die" => {
                            let end_time = msg.time
                                .map(systime_from_secs)
                                .unwrap_or(SystemTime::now());

                            self.events.container_stopped(id, end_time).await;
                        },
                        _ => (),
                    }
                }
            }
        }
    }

    async fn load_running(&self) -> Result<()> {
        let opts = ListContainersOptions::<&str>{
            filters: HashMap::from([
                ("status", vec!["running"])
            ]),
            ..Default::default()
        };

        let conts = self.docker.list_containers(Some(opts)).await?;

        for c in conts {
            if c.id.is_none() {
                continue;
            }
            let id = c.id.unwrap();

            match self.inspect_container(&id).await {
                Ok(info) => {
                    debug!("Container started: {id}; {info:?}");
                    self.events.container_started(id, info).await;
                },
                Err(err) => {
                    error!("Docker inspect_container({id}): {err}");
                    continue;
                }
            };
        }

        Ok(())
    }

    async fn inspect_container(&self, id: &str) -> Result<ContainerInfo> {
        let cont_resp = self.docker.inspect_container(id, None).await?;

        let rootfs = match cont_resp.graph_driver {
            Some(mut driver) => {
                if driver.name == GRAPH_DRIVER_OVERLAYFS {
                    driver.data.remove("MergedDir")
                        .map(HostPath::from)
                } else {
                    None
                }
            },
            None => None,
        };

        let image_tag = match &cont_resp.image {
            Some(id) => {
                self.docker.inspect_image(id).await?
                    .repo_tags
                    .and_then(|tags| head(&tags))
            },
            None => None,
        };

        let (start_time, end_time) = match cont_resp.state {
            Some(state) => {
                // Convert from ISO 8601 string to SystemTime

                let started_at = state.started_at
                    .and_then(|t| t.parse::<DateTime<Utc>>().ok())
                    .map(|t| t.into());

                let finished_at = match state.status {
                    Some(ContainerStateStatusEnum::RUNNING) | Some(ContainerStateStatusEnum::PAUSED) => None,
                    _ => {
                        state.finished_at.and_then(|t| t.parse::<DateTime<Utc>>().ok())
                            .filter(|t| t > &DT_UNIX_EPOCH)
                            .map(|t| t.into())
                    }
                };

                (started_at, finished_at)
            },
            None => (None, None)
        };

        let mounts = cont_resp.mounts
            .unwrap_or_default()
            .into_iter()
            .filter_map(|m| m.destination.map(|d| d.into()))
            .collect();

        Ok(ContainerInfo{
            name: cont_resp.name,
            image_id: cont_resp.image,
            image: image_tag,
            rootfs,
            start_time,
            end_time,
            mounts,
            labels: self.cloud_meta.container_labels(id),
        })
    }

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
