use std::ffi::{c_char, CStr};
use std::mem::size_of;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Result};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{Map, MapFlags, MapHandle, PerfBufferBuilder, RingBufferBuilder};
use thiserror::Error;

use log::*;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;

use crate::fanotify::Fanotify;
use crate::scoped_path::*;

mod probes {
    include!(concat!(env!("OUT_DIR"), "/probes.skel.rs"));
}

const OPEN_EVENTS_BUF_SIZE: usize = 256;
const ZOMBIE_EVENTS_BUF_SIZE: usize = 4;

pub trait FileOpenMonitor {
    // NB: Adds the mountpoint of path, not the actual path.
    fn add_path(&self, path: &RootFsPath) -> Result<()>;

    // NB: Removes the mountpoint of path, not the actual path.
    fn remove_path(&self, path: &RootFsPath) -> Result<()>;
}

pub type FileOpenMonitorArc = Arc<dyn FileOpenMonitor + Send + Sync>;

enum CommBufferMap<'a> {
    RingBuffer(&'a Map),
    PerfBuffer(&'a Map),
}

enum CommBuffer<'cb> {
    RingBuffer(libbpf_rs::RingBuffer<'cb>),
    PerfBuffer(libbpf_rs::PerfBuffer<'cb>),
}

impl<'cb> CommBuffer<'cb> {
    fn load<F>(map: CommBufferMap<'_>, pages: usize, cb: F) -> Result<Self>
    where
        F: Fn(&[u8]) + Send + Sync + 'static,
    {
        match map {
            CommBufferMap::RingBuffer(rb) => {
                let mut builder = RingBufferBuilder::new();
                builder.add(rb, move |buf: &[u8]| {
                    cb(buf);
                    0i32
                })?;

                let rb = builder.build()?;
                Ok(CommBuffer::RingBuffer(rb))
            }
            CommBufferMap::PerfBuffer(pb) => {
                let pb = PerfBufferBuilder::new(pb)
                    .pages(pages)
                    .sample_cb(move |_cpu, buf: &[u8]| cb(buf))
                    .lost_cb(handle_lost_events)
                    .build()?;

                Ok(CommBuffer::PerfBuffer(pb))
            }
        }
    }

    fn poll(&self, dur: Duration) -> Result<()> {
        match self {
            CommBuffer::RingBuffer(rb) => rb.poll(dur)?,
            CommBuffer::PerfBuffer(pb) => pb.poll(dur)?,
        }

        Ok(())
    }
}

fn handle_lost_events(cpu: i32, count: u64) {
    warn!("Lost {count} events on CPU {cpu}");
}

#[derive(Error, Debug)]
#[error(transparent)]
pub struct LoadError(#[from] libbpf_rs::Error);

struct BpfProbes {
    // ProbesSkel contains OpenObject which has a *mut,
    // making it not possible to use with .await
    skel: probes::ProbesSkel<'static>,
    use_ring_buf: bool,
}

impl BpfProbes {
    fn load() -> Result<Self> {
        // first thing is to bump the ulimit for locked memory for older kernels
        bump_rlimit()?;

        let use_ring_buf = supports_ring_buffer();
        info!("Using ring buffer: {use_ring_buf}");

        let mut with_optional = true;

        loop {
            match Self::load_internal(use_ring_buf, with_optional) {
                Ok(skel) => return Ok(skel),
                Err(err) => {
                    if err.is::<LoadError>() {
                        if with_optional {
                            info!(
                                "Loading of BPF probes failed, retrying with optional probes disabled"
                            );
                            with_optional = false;
                        } else {
                            return Err(anyhow!("ProbesSkelBuilder::load(): {err}"));
                        }
                    } else {
                        return Err(err);
                    }
                }
            }
        }
    }

    fn load_internal(use_ring_buf: bool, with_optional_probes: bool) -> Result<Self> {
        let skel_builder = probes::ProbesSkelBuilder::default();

        let mut open_skel = skel_builder
            .open()
            .map_err(|err| anyhow!("ProbesSkelBuilder::open(): {err}"))?;

        open_skel
            .maps_mut()
            .rb_open_events()
            .set_autocreate(use_ring_buf)?;

        open_skel
            .maps_mut()
            .pb_open_events()
            .set_autocreate(!use_ring_buf)?;

        open_skel
            .maps_mut()
            .rb_zombie_events()
            .set_autocreate(use_ring_buf)?;

        open_skel
            .maps_mut()
            .pb_zombie_events()
            .set_autocreate(!use_ring_buf)?;

        open_skel
            .progs_mut()
            .enter_openat2()
            .set_autoload(with_optional_probes)?;

        open_skel
            .progs_mut()
            .exit_openat2()
            .set_autoload(with_optional_probes)?;

        let mut skel = open_skel.load().map_err(LoadError)?;

        skel.attach().map_err(LoadError)?;

        Ok(Self { skel, use_ring_buf })
    }

    fn open_events<'cb, F>(&self, cb: F) -> Result<CommBuffer<'cb>>
    where
        F: Fn(&[u8]) + Send + Sync + 'static,
    {
        let maps = self.skel.maps();

        if self.use_ring_buf {
            let map = CommBufferMap::RingBuffer(maps.rb_open_events());
            CommBuffer::load(map, 0, cb)
        } else {
            let map = CommBufferMap::PerfBuffer(maps.pb_open_events());
            CommBuffer::load(map, OPEN_EVENTS_BUF_SIZE, cb)
        }
    }

    fn zombie_events<'cb, F>(&self, cb: F) -> Result<CommBuffer<'cb>>
    where
        F: Fn(&[u8]) + Send + Sync + 'static,
    {
        let maps = self.skel.maps();

        if self.use_ring_buf {
            let map = CommBufferMap::RingBuffer(maps.rb_zombie_events());
            CommBuffer::load(map, 0, cb)
        } else {
            let map = CommBufferMap::PerfBuffer(maps.pb_zombie_events());
            CommBuffer::load(map, ZOMBIE_EVENTS_BUF_SIZE, cb)
        }
    }

    fn lookup_cgroup(&self, pid: u32) -> Result<Option<String>> {
        let key = pid.to_ne_bytes();
        let val = self
            .skel
            .maps()
            .pid_to_info()
            .lookup(&key, MapFlags::ANY)
            .map_err(|err| anyhow!("pid_to_info::lookup(): {err}"))?;

        Ok(match val {
            Some(bytes) => {
                let bytes: &[u8] = &bytes;
                let info: ProcessInfo = bytes
                    .try_into()
                    .map_err(|_| anyhow!("error casting bytes into ProcessInfo"))?;

                let cgroup = info.cgroup_path()?.to_string();

                Some(cgroup)
            }
            None => None,
        })
    }

    fn remove_pid(&mut self, pid: &[u8]) -> Result<()> {
        self.skel
            .maps_mut()
            .pid_to_info()
            .delete(pid)
            .map_err(|err| anyhow!("pid_to_info::delete(): {err}"))?;

        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessInfo {
    zombie: u8,
    cgroup: [u8; 255],
}

impl ProcessInfo {
    fn cgroup_path(&self) -> Result<&str> {
        let nul = self
            .cgroup
            .iter()
            .position(|b| *b == 0u8)
            .unwrap_or(self.cgroup.len());

        let cg = std::str::from_utf8(&self.cgroup[..nul]).map_err(|_| {
            anyhow!(
                "cgroup name with non-UTF8 characters: {:?}",
                &self.cgroup[..nul]
            )
        })?;

        Ok(cg)
    }
}

impl TryFrom<&[u8]> for ProcessInfo {
    type Error = ();

    fn try_from(buf: &[u8]) -> Result<Self, ()> {
        let sz = core::mem::size_of::<Self>();
        if buf.len() < sz {
            return Err(());
        }

        let val = unsafe { *(buf.as_ptr() as *const Self) };
        Ok(val)
    }
}

pub struct OpenMonitor {
    fan: Arc<Fanotify>,
    fan_task: JoinHandle<()>,
    _probes: Arc<Mutex<BpfProbes>>,
    zombie_task: JoinHandle<()>,
    opens_task: JoinHandle<()>,
}

impl OpenMonitor {
    pub fn start(ch: Sender<OpenEvent>) -> Result<Self> {
        let fan = Arc::new(Fanotify::new()?);
        let probes = Arc::new(Mutex::new(BpfProbes::load()?));

        let fan_task =
            tokio::task::spawn(monitor_fanotify(fan.clone(), probes.clone(), ch.clone()));

        let opens_task = monitor_bpf_open_events(probes.clone(), ch)?;

        let zombie_task = monitor_zombies(probes.clone())?;

        Ok(Self {
            fan,
            fan_task,
            _probes: probes,
            zombie_task,
            opens_task,
        })
    }

    pub async fn stop(self) {
        self.fan_task.abort();
        _ = self.fan_task.await;

        self.zombie_task.abort();
        _ = self.zombie_task.await;

        self.opens_task.abort();
        _ = self.opens_task.await;
    }
}

impl FileOpenMonitor for OpenMonitor {
    // NB: Adds the mountpoint of path, not the actual path.
    fn add_path(&self, path: &RootFsPath) -> Result<()> {
        self.fan.add_open_mark(path.as_raw().to_path_buf())
    }

    // NB: Removes the mountpoint of path, not the actual path.
    fn remove_path(&self, path: &RootFsPath) -> Result<()> {
        self.fan.remove_open_mark(path.as_raw().to_path_buf())
    }
}

async fn monitor_fanotify(
    fan: Arc<Fanotify>,
    probes: Arc<Mutex<BpfProbes>>,
    ch: Sender<OpenEvent>,
) {
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
                Ok(path) => WorkloadPath::from(path),
                Err(err) => {
                    error!("Failed to extract file path: {err}");
                    continue;
                }
            };

            let cgroup_name = match probes.lock().unwrap().lookup_cgroup(e.pid as u32) {
                Ok(cgroup) => cgroup,
                Err(err) => {
                    error!("lookup_cgroup: {err}");
                    None
                }
            };

            trace!("fanotify: {} / {:?}", filename.display(), cgroup_name);

            let open = OpenEvent {
                cgroup_name,
                filename,
            };

            _ = ch.send(open).await;
        }
    }
}

fn monitor_bpf_open_events(
    probes_arc: Arc<Mutex<BpfProbes>>,
    ch: Sender<OpenEvent>,
) -> Result<JoinHandle<()>> {
    let events = {
        let probes = probes_arc.lock().unwrap();
        let probes_arc = probes_arc.clone();

        probes.open_events(move |buf| {
            let evt = buf.as_ptr() as *const EvtOpen;
            let fname = unsafe { CStr::from_ptr(&((*evt).filename) as *const c_char) };
            let pid = unsafe { u32::from_ne_bytes((*evt).pid) };

            let filename = WorkloadPath::from_cstr(fname);

            let cgroup_name = match probes_arc.lock().unwrap().lookup_cgroup(pid) {
                Ok(cgroup) => cgroup,
                Err(err) => {
                    error!("lookup_cgroup: {err}");
                    None
                }
            };

            trace!("bpf: {} / {:?}", filename.display(), cgroup_name);

            let open = OpenEvent {
                cgroup_name,
                filename,
            };

            if let Err(err) = ch.blocking_send(open) {
                error!("Error sending OpenEvent on a channel: {err}");
            }
        })?
    };

    Ok(tokio::task::spawn_blocking(move || loop {
        _ = events.poll(Duration::from_millis(100));
    }))
}

fn monitor_zombies(probes_arc: Arc<Mutex<BpfProbes>>) -> Result<JoinHandle<()>> {
    let events = {
        let probes = probes_arc.lock().unwrap();
        let probes_arc = probes_arc.clone();

        probes.zombie_events(move |buf| {
            let pid = buf.to_vec();
            let probes_arc = probes_arc.clone();

            tokio::task::spawn(async move {
                tokio::time::sleep(Duration::from_secs(10)).await;
                if let Err(err) = probes_arc.lock().unwrap().remove_pid(&pid) {
                    error!("Failed to remove process info from BPF map: {err}");
                }
            });
        })?
    };

    Ok(tokio::task::spawn_blocking(move || loop {
        _ = events.poll(Duration::from_millis(100));
    }))
}

// matches evt_open in probes.bpf.c
#[repr(C)]
struct EvtOpen {
    pid: [u8; 4],
    filename: [std::ffi::c_char; 256],
}

pub struct OpenEvent {
    pub cgroup_name: Option<String>,
    pub filename: WorkloadPath,
}

fn bump_rlimit() -> Result<()> {
    use nix::sys::resource::Resource;
    nix::sys::resource::setrlimit(
        Resource::RLIMIT_MEMLOCK,
        nix::sys::resource::RLIM_INFINITY,
        nix::sys::resource::RLIM_INFINITY,
    )
    .map_err(|err| anyhow!("failed to raise lock memory rlimit: {err}"))?;

    Ok(())
}

fn supports_ring_buffer() -> bool {
    use libbpf_rs::libbpf_sys::{bpf_map_create_opts, size_t};

    let opts = bpf_map_create_opts {
        sz: size_of::<bpf_map_create_opts>() as size_t,
        ..Default::default()
    };

    MapHandle::create(
        libbpf_rs::MapType::RingBuf,
        Some("test"),
        0u32,
        0u32,
        4096u32,
        &opts,
    )
    .is_ok()
}

pub struct NullOpenMonitor;

impl FileOpenMonitor for NullOpenMonitor {
    fn add_path(&self, _path: &RootFsPath) -> Result<()> {
        Ok(())
    }

    // NB: Removes the mountpoint of path, not the actual path.
    fn remove_path(&self, _path: &RootFsPath) -> Result<()> {
        Ok(())
    }
}
