pub mod containers;
pub mod host;
pub mod in_use;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::num::NonZeroUsize;

use log::*;
use anyhow::Result;
use tokio::sync::mpsc::{Sender, Receiver};

use crate::open_monitor::FileOpenMonitorArc;
use crate::scoped_path::*;
use crate::config::Config;
use crate::containers::{ContainerEvent, ContainerInfo};

use host::HostWorkload;
use containers::ContainerWorkloads;

pub(crate) const REPORTED_LRU_SIZE: NonZeroUsize = unsafe { NonZeroUsize::new_unchecked(256) };

#[derive(Debug)]
pub enum Event {
    ContainerStarted(String, ContainerInfo),
    ContainerStopped(String, ContainerInfo),
}

#[derive(Clone)]
pub struct Workloads {
    pub host: Arc<Mutex<HostWorkload>>,
    pub containers: Arc<Mutex<ContainerWorkloads>>,
}

impl Workloads {
    pub fn new(config: Arc<Config>, host: HostWorkload, open_mon: FileOpenMonitorArc) -> Self {
        Self {
            host: Arc::new(Mutex::new(host)),
            containers: Arc::new(Mutex::new(ContainerWorkloads::new(config, open_mon)))
        }
    }
}

struct PathSet {
    members: HashMap<WorkloadPath, ()>,
}

impl PathSet {
    fn new() -> Result<Self> {
        Ok(Self {
            members: HashMap::new(),
        })
    }

    fn add(&mut self, path: WorkloadPath) {
        self.members.insert(path, ());
    }

    fn contains(&self, path: &WorkloadPath) -> bool {
        self.members
            .keys()
            .any(|f| path.as_raw().starts_with(f.as_raw()))
    }

    fn all<'a>(&'a self) -> impl Iterator<Item=&WorkloadPath> + 'a {
        self.members.keys()
    }
}

pub(crate) fn resolve_failed(filepath: &WorkloadPath, err: anyhow::Error) {
    match err.downcast::<std::io::Error>() {
        Ok(io_err) => {
            // File not found is ok as it was a transient file that got deleted
            // This almost exclusively occurs on data files
            if io_err.kind() != std::io::ErrorKind::NotFound {
                info!("Failed to canonicalize {}: {io_err}", filepath.display());
            }
        },
        Err(err) => {
            info!("Failed to canonicalize {}: {err}", filepath.display());
        }
    }
}

pub(crate) fn is_not_found(err: &anyhow::Error) -> bool {
    if let Some(err) = err.downcast_ref::<std::io::Error>() {
        err.kind() == std::io::ErrorKind::NotFound
    } else {
        false
    }
}

#[inline]
fn is_file(path: &RootFsPath) -> bool {
    match std::fs::metadata(path.as_raw()) {
        Ok(md) => md.is_file(),
        Err(_) => false,
    }
}

pub async fn track_container_lifecycle(mut rx: Receiver<ContainerEvent>, workloads: Arc<Mutex<ContainerWorkloads>>, events: Sender<Event>) {
    loop {
        match rx.recv().await {
            Some(ContainerEvent::Started(id, info)) => {
                workloads.lock()
                    .unwrap()
                    .container_started(id.clone(), info.clone());

                if let Err(err) = events.send(Event::ContainerStarted(id, info)).await {
                    error!("Failed to send events on a channel: {err}");
                }
            },
            Some(ContainerEvent::Stopped(id, info)) => {
                workloads.lock()
                    .unwrap()
                    .container_stopped(id.clone(), info.clone());

                if let Err(err) = events.send(Event::ContainerStopped(id, info)).await {
                    error!("Failed to send events on a channel: {err}");
                }
            },
            None => break,
        }
    }
}