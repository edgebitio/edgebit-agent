use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use std::time::{Instant, Duration};

use log::*;
use tokio::sync::mpsc::Receiver;

use crate::containers::Containers;
use crate::open_monitor::OpenEvent;
use super::Workloads;

const OPEN_EVENT_LAG: Duration = Duration::from_millis(500);

struct OpenEventQueueItem {
    timestamp: Instant,
    evt: OpenEvent,
}

pub async fn track_pkgs_in_use(containers: Arc<Containers>, workloads: Workloads, mut rx: Receiver<OpenEvent>) {
    let mut open_event_q = Mutex::new(VecDeque::<OpenEventQueueItem>::new());

    let mut periods = tokio::time::interval(Duration::from_millis(100));

    loop {
        tokio::select!{
            _ = periods.tick() => {
                let cutoff = Instant::now()
                    .checked_sub(OPEN_EVENT_LAG)
                    .unwrap();

                while let Some(evt) = pop_open_event(&mut open_event_q, cutoff) {
                    let cgroup = evt.cgroup_name.unwrap_or(String::new());
                    trace!("[{cgroup}]: {}", evt.filename.display());

                    if let Some(id) = containers.id_from_cgroup(&cgroup) {
                        workloads.containers.lock()
                            .unwrap()
                            .file_opened(&id, &evt.filename)
                    } else {
                        workloads.host.lock()
                            .unwrap()
                            .file_opened(&evt.filename)
                    }
                }
            },
            evt = rx.recv() => {
                match evt {
                    Some(evt) => {
                        open_event_q.lock()
                            .unwrap()
                            .push_back(OpenEventQueueItem{
                                    timestamp: Instant::now(),
                                    evt,
                                });
                    },
                    None => break,
                }
            }
        }
    }
}

fn pop_open_event(q: &mut Mutex<VecDeque<OpenEventQueueItem>>, cutoff: Instant) -> Option<OpenEvent> {
    let q = q.get_mut().unwrap();
    if q.front()?.timestamp > cutoff {
        None
    } else {
        q.pop_front()
            .map(|item| item.evt)
    }
}