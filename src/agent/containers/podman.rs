
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

    pub async fn track(self, events: ContainerEventsPtr) -> Result<()> {
        let podman = Arc::new(self.podman);

        let events_task = {
            let podman = podman.clone();
            let events = events.clone();

            tokio::task::spawn(async move {
                stream_events(&podman, events).await;
            })
        };

        // Load already running containers
        load_running(&podman, events.clone()).await?;

        events.flush().await;

        _ = events_task.await;

        Ok(())
    }

}

async fn stream_events(
    podman: &Podman,
    events: ContainerEventsPtr
) {
    let filter = ("event".to_string(), vec!["start".to_string(), "died".to_string()]);

    let opts = EventsOpts::builder()
        .stream(true)
        .filters([filter])
        .build();

    let mut stream = podman.events(&opts);

    while let Some(evt) = stream.next().await {
        debug!("Podman Event: {evt:?}");

        match evt {
            Ok(msg) => process_event(podman, msg, events.clone()).await,
            Err(err) => error!("Failed to receive podman event: {err}"),
        }
    }

    debug!("Event streaming done");
}

async fn process_event(podman: &Podman, msg: Event, events: ContainerEventsPtr) {
    if msg.typ == EVENT_TYPE_CONTAINER {
        let id = msg.actor.id;

        match msg.action.as_ref() {
            "start" => {
                debug!("Container {id} started");

                match inspect_container(podman, &id).await {
                    Ok(info) => {
                        events.container_started(id, info).await;
                    },
                    Err(err) => {
                        error!("Failed to inspect container(id={id}): {err}");
                        return;
                    }
                }
            },
            "died" => {
                events.container_stopped(id, msg.time.into()).await;
            },
            _ => (),
        }
    }
}

async fn load_running(podman: &Podman, events: ContainerEventsPtr) -> Result<()> {
    let opts = ContainerListOpts::builder()
        .build();

    let conts = podman.containers().list(&opts).await?;

    for c in conts {
        if c.id.is_none() {
            continue;
        }
        let id = c.id.unwrap();

        match inspect_container(podman, &id).await {
            Ok(info) => {
                debug!("Container {id}: {info:?}");
                events.add_container(id, info);
            },
            Err(err) => {
                error!("Podman inspect_container({id}): {err}");
                continue;
            }
        }
    }

    Ok(())
}

async fn inspect_container(podman: &Podman, id: &str) -> Result<ContainerInfo> {
    let cont_resp = podman.containers()
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
            let started = state.started_at
                .map(|t| t.into());

            let finished = state.finished_at
                .map(|t| t.into());

            (started, finished)
        },
        None => (None, None)
    };

    Ok(ContainerInfo{
        name: cont_resp.name,
        image_id: cont_resp.image,
        image: cont_resp.image_name,
        rootfs,
        start_time,
        end_time,
    })
}