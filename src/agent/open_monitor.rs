use std::{collections::HashMap, time::Duration};
use std::path::Path;
use std::ffi::OsString;

use anyhow::{Result};
use tokio::sync::mpsc::Sender;
use log::*;
use libbpf_rs::{PerfBufferBuilder};

use edgebit_agent::common_defs::EvtOpen;

mod probes {
    include!(concat!(env!("OUT_DIR"), "/probes.skel.rs"));
}

const MINORBITS: usize = 20;

pub fn run(ch: Sender<OpenEvent>) -> Result<()> {
    info!("Building inode cache");
    let inodes = InodeCache::load()?;
    info!("Done building inode cache");

    monitor(&inodes, ch)?;
    Ok(())
}

fn monitor(inodes: &InodeCache, mut ch: Sender<OpenEvent>) -> Result<()> {
    let skel_builder = probes::ProbesSkelBuilder::default();
    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    let cb = Box::new(|_cpu, buf: &[u8]| {
        handle_event(buf, inodes, &mut ch);
    });
    let perf = PerfBufferBuilder::new(skel.maps_mut().events())
        .sample_cb(cb)
        .lost_cb(handle_lost_events)
        .build()?;

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}

fn handle_event(buf: &[u8], inodes: &InodeCache, ch: &mut Sender<OpenEvent>) {
    if let Ok(evt) = TryInto::<EvtOpen>::try_into(buf) {
        if let Some(filename) = inodes.lookup(evt.dev, evt.ino) {
            let open = OpenEvent{
                cgroup: evt.cgroup,
                filename: filename.clone(),
            };
            info!("match: {filename:?}, {}/{}", evt.dev, evt.ino);
            _ = ch.blocking_send(open);
        } else {
            warn!("filename not found for dev={:x}, ino={}", evt.dev, evt.ino);
        }
    }
}

fn handle_lost_events(cpu: i32, count: u64) {
    warn!("Lost {count} events on CPU {cpu}");
}

pub struct OpenEvent {
    pub cgroup: u64,
    pub filename: OsString,
}

type DevIno = (u64, u64);

pub struct InodeCache {
    inner: HashMap<DevIno, OsString>,
}

impl InodeCache {
    pub fn new() -> Self {
        Self{
            inner: HashMap::new(),
        }
    }

    pub fn load() -> Result<Self> {
        let mut cache = HashMap::new();
        traverse("/", &mut cache)?;
        Ok(Self{
            inner: cache,
        })
    }

    pub fn lookup(&self, dev: u64, ino: u64) -> Option<&OsString> {
        self.inner.get(&(dev, ino))
    }
}

fn traverse<P: AsRef<Path>>(path: P, cache: &mut HashMap<DevIno, OsString>) -> Result<()> {
    let path = path.as_ref();
    for dirent in std::fs::read_dir(path)? {
        if let Ok(dirent) = dirent {
            if let Ok(file_type) = dirent.file_type() {
                let mut full_name = path.to_path_buf();
                full_name.push(dirent.file_name());
                if file_type.is_dir() {
                    if is_system_dir(&full_name) {
                        continue;
                    }
                    _ = traverse(full_name, cache);
                } else if file_type.is_file() {
                    if let Ok(meta) = dirent.metadata() {
                        use std::os::linux::fs::MetadataExt;
                        let dev = dev_libc_to_kernel(meta.st_dev());
                        let devino = (dev, meta.st_ino());

                        trace!("{} @ {devino:?}", full_name.to_string_lossy());
                        cache.insert(devino, full_name.into_os_string());
                    }
                }
            }
        }
    }

    Ok(())
}

fn is_system_dir(path: &Path) -> bool {
    const SYSTEM_PREFIXES: &[&str] = &["/proc/", "/run/", "/var/run/", "/sys/", "/tmp/"];

    SYSTEM_PREFIXES.iter()
        .any(|prefix| path.starts_with(prefix))
}

fn dev_libc_to_kernel(dev: u64) -> u64 {
    // The kernel internally stores the dev as: MMMmmmmm (M=major, m=minor)
    // The libc stores the dev as mmmMMMmm (same as uapi)
    // We normalize it to the kernel encoding
    let major = (dev & 0xfff00) >> 8;
    let minor = (dev & 0xff) | ((dev & !0xfffff) >> 12);
    (major << MINORBITS) | minor
}
