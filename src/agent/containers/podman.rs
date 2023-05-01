
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result};
use log::*;
use podman_api::{Podman};
use podman_api::opts::{EventsOpts, ContainerListOpts};
use podman_api::models::Event;
use futures::stream::StreamExt;

use super::{ContainerEventsPtr, ContainerInfo};
use crate::scoped_path::*;
use crate::cloud_metadata::CloudMetadata;

const GRAPH_DRIVER_OVERLAYFS: &str = "overlay";
const EVENT_TYPE_CONTAINER: &str = "container";

pub struct PodmanTracker {
    podman: Podman,
}

impl PodmanTracker {
    pub async fn connect(host: &str) -> Result<Self> {
        info!("Connecting to {host}");
        let podman = Podman::new(host)?;

        let mut quiet = false;
        loop {
            match podman.ping().await {
                Ok(_) => {
                    info!("Connected to Podman daemon");
                    break;
                },
                Err(err) => {
                    if quiet {
                        debug!("Failed to connect to Podman daemon: {err}");
                    } else {
                        error!("Failed to connect to Podman daemon: {err}");
                        quiet = true;
                    }

                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }

        Ok(Self{
            podman,
        })
    }

    pub async fn track(self, cloud_meta: CloudMetadata, events: ContainerEventsPtr) -> Result<()> {
        let tracker = Arc::new(Tracker{
            podman: self.podman,
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
    podman: Podman,
    cloud_meta: CloudMetadata,
    events: ContainerEventsPtr,
}

impl Tracker {
    async fn stream_events(&self) {
        let filter = ("event".to_string(), vec!["start".to_string(), "died".to_string()]);

        let opts = EventsOpts::builder()
            .stream(true)
            .filters([filter])
            .build();

        let mut stream = self.podman.events(&opts);

        while let Some(evt) = stream.next().await {
            debug!("Podman Event: {evt:?}");

            match evt {
                Ok(msg) => self.process_event(msg).await,
                Err(err) => error!("Failed to receive podman event: {err}"),
            }
        }

        debug!("Event streaming done");
    }

    async fn process_event(&self, msg: Event) {
        if msg.typ == EVENT_TYPE_CONTAINER {
            let id = msg.actor.id;

            match msg.action.as_ref() {
                "start" => {
                    debug!("Container {id} started");

                    match self.inspect_container(&id).await {
                        Ok(info) => {
                            self.events.container_started(id, info).await;
                        },
                        Err(err) => {
                            error!("Failed to inspect container(id={id}): {err}");
                            return;
                        }
                    }
                },
                "died" => {
                    self.events.container_stopped(id, msg.time.into()).await;
                },
                _ => (),
            }
        }
    }

    async fn load_running(&self) -> Result<()> {
        let opts = ContainerListOpts::builder()
            .build();

        let conts = self.podman.containers().list(&opts).await?;

        for c in conts {
            if c.id.is_none() {
                continue;
            }
            let id = c.id.unwrap();

            match self.inspect_container(&id).await {
                Ok(info) => {
                    debug!("Container {id}: {info:?}");
                    self.events.container_started(id, info).await;
                },
                Err(err) => {
                    error!("Podman inspect_container({id}): {err}");
                    continue;
                }
            }
        }

        Ok(())
    }

    async fn inspect_container(&self, id: &str) -> Result<ContainerInfo> {
        let cont_resp = self.podman.containers()
            .get(id)
            .inspect()
            .await?;

        let rootfs = match cont_resp.graph_driver {
            Some(driver) => {
                if driver.name.is_none() || driver.name.as_ref().unwrap() == GRAPH_DRIVER_OVERLAYFS {
                    match driver.data {
                        Some(mut data) => {
                            data.remove("MergedDir")
                                .map(|path| HostPath::from(path))
                        },
                        None => {
                            error!("Container id={id}: graph driver data missing");
                            None
                        }
                    }
                } else {
                    error!("Container id={id}: unknown graph driver: {}", driver.name.unwrap());
                    None
                }
            },
            None => None,
        };

        let (start_time, end_time) = match cont_resp.state {
            Some(state) => {
                let started_at = state.started_at
                    .map(|t| t.into());

                let finished_at = match state.status.as_deref() {
                    Some("running") | Some("paused") => None,
                    _ => {
                        state.finished_at
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
            image: cont_resp.image_name,
            rootfs,
            start_time,
            end_time,
            mounts,
            labels: self.cloud_meta.container_labels(id),
        })
    }
}