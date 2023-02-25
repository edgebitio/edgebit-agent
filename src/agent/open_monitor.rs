use std::time::Duration;
use std::path::Path;
use std::ffi::OsString;
use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow};
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use log::*;
use libbpf_rs::{PerfBufferBuilder, MapFlags};

use crate::fanotify::Fanotify;

mod probes {
    include!(concat!(env!("OUT_DIR"), "/probes.skel.rs"));
}

const ZOMBIE_EVENTS_BUF_SIZE: usize = 4;

#[derive(Clone)]
struct BpfProbes {
    // ProbesSkel contains OpenObject which has a *mut,
    // making it not possible to use with .await
    skel: Arc<Mutex<probes::ProbesSkel<'static>>>,
}

impl BpfProbes {
    fn load() -> Result<Self> {
        let skel_builder = probes::ProbesSkelBuilder::default();
        let open_skel = skel_builder.open()?;
        let mut skel = open_skel.load()?;
        skel.attach()?;

        Ok(Self {
            skel: Arc::new(Mutex::new(skel)),
        })
    }

    fn lookup_cgroup(&self, pid: u32) -> Result<Option<String>> {
        let key = pid.to_ne_bytes();
        let val = self.skel.lock()
            .unwrap()
            .maps()
            .pid_to_info()
            .lookup(&key, MapFlags::ANY)?;

        Ok(match val {
            Some(bytes) => {
                let bytes: &[u8] = &bytes;
                let info: ProcessInfo = bytes.try_into()
                    .map_err(|_| anyhow!("error casting bytes into ProcessInfo"))?;

                let cgroup = info.cgroup_path()?
                    .to_string();

                Some(cgroup)
            },
            None => None,
        })
    }

    fn remove_pid(&self, pid: &[u8]) -> Result<()> {
        self.skel.lock()
            .unwrap()
            .maps_mut()
            .pid_to_info()
            .delete(pid)?;

        Ok(())
    }

    fn watch_zombies<F>(&self, callback: F) -> JoinHandle<Result<()>>
    where F: Send + Sync + Fn(&[u8]) -> () + 'static
    {
        let cb = Box::new(move |_cpu, buf: &[u8]| {
           callback(buf) 
        });

        let skel = self.skel.clone();

        tokio::task::spawn_blocking(move || {
            let zombies = {
                let skel = skel.lock().unwrap();
                let maps = skel.maps();

                match PerfBufferBuilder::new(maps.zombie_events())
                    .pages(ZOMBIE_EVENTS_BUF_SIZE)
                    .sample_cb(cb)
                    .lost_cb(handle_lost_events)
                    .build() {

                    Ok(zombies) => zombies,
                    Err(err) => return Err(anyhow::Error::from(err))
                }
            };

            loop {
                _ = zombies.poll(Duration::from_millis(100));
            }
        })
    }
}

fn handle_lost_events(cpu: i32, count: u64) {
    warn!("Lost {count} events on CPU {cpu}");
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessInfo {
    zombie: u8,
    cgroup: [u8; 255],
}

impl ProcessInfo {
    fn cgroup_path(&self) -> Result<&str> {
        let cg = std::str::from_utf8(&self.cgroup)
            .map_err(|_| anyhow!("cgroup name with non-UTF8 characters"))?;

        Ok(cg)
    }
}

impl TryFrom<&[u8]> for ProcessInfo {
    type Error = ();

    fn try_from(buf: &[u8]) -> Result<Self, ()> {
        let sz = core::mem::size_of::<Self>();
        if buf.len() < sz {
            return Err(())
        }

        let val = unsafe { *(buf.as_ptr() as *const Self) };
        Ok(val)
    }
}

pub struct OpenMonitor {
    fan: Arc<Fanotify>,
    fan_task: JoinHandle<()>,
    probes: BpfProbes,
    zombie_task: JoinHandle<Result<()>>,
}

impl OpenMonitor {
    pub fn start(ch: Sender<OpenEvent>) -> Result<Self> {
        let fan = Arc::new(Fanotify::new()?);
        let probes = BpfProbes::load()?;

        let fan_task = tokio::task::spawn(
            monitor(fan.clone(), probes.clone(), ch)
        );

        // Watch for processes to exit and schedule their process info to be cleaned up
        // a few seconds after
        let zombie_task = {
            let probes2 = probes.clone();

            probes.watch_zombies(move |pid| {
                let pid = pid.to_vec();
                let probes = probes2.clone();

                tokio::task::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    if let Err(err) = probes.remove_pid(&pid) {
                        error!("Failed to remove process info from BPF map: {err}");
                    }
                });
            })
        };

        Ok(Self {
            fan,
            fan_task,
            probes,
            zombie_task,
        })
    }

    pub async fn stop(self) {
        self.fan_task.abort();
        _ = self.fan_task.await;

        self.zombie_task.abort();
        _ = self.zombie_task.await;
    }

    // NB: Adds the mountpoint of path, not actual path.
    pub fn add_path(&self, path: &Path) -> Result<()> {
        let path = path.to_str()
            .ok_or_else(|| anyhow!("{} contains non-UTF8 bytes", path.to_string_lossy()))?;

        self.fan.add_open_mark(path)
    }

    // NB: Removes the mountpoint of path, not actual path.
    pub fn remove_path(&self, path: &Path) -> Result<()> {
        let path = path.to_str()
            .ok_or_else(|| anyhow!("{} contains non-UTF8 bytes", path.to_string_lossy()))?;

        self.fan.remove_open_mark(path)
    }
}

async fn monitor(fan: Arc<Fanotify>, probes: BpfProbes, ch: Sender<OpenEvent>) {
    loop {
        let events = match fan.next().await {
            Ok(events) => events,
            Err(err) => {
                error!("fanotify next: {err}");
                continue;
            }
        };

        for e in events {
            let filename = match e.path() {
                Ok(path) => path.into_os_string(),
                Err(err) => {
                    error!("Failed to extract file path: {err}");
                    continue;
                }
            };

            let cgroup = match probes.lookup_cgroup(e.pid as u32) {
                Ok(Some(cgroup)) => cgroup,
                Ok(None) => String::new(),
                Err(err) =>  {
                    error!("lookup_cgroup: {err}");
                    String::new()
                }
            };

            let open = OpenEvent {
                cgroup_name: cgroup,
                filename,
            };

            _ = ch.send(open).await;
        }
    }
}

/*
fn pid_from_bytes(bytes: &[u8]) -> Result<u32> {
    if bytes.len() < sizeof(u32) {
        return Err(anyhow!("truncated PID"));
    }

    let buf = [0u8; 4];
    buf.copy_from_slice(src);

    Ok(u32::from_ne_bytes(buf))
}
*/

pub struct OpenEvent {
    //pub cgroup: u64,
    pub cgroup_name: String,
    pub filename: OsString,
}