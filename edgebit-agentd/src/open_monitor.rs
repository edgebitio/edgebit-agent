use std::collections::HashMap;
use std::path::Path;
use std::ffi::OsString;
use std::sync::Arc;

use aya::{Bpf, include_bytes_aligned};
use aya::programs::{TracePoint};
use aya::maps::MapRefMut;
use aya::maps::perf::{AsyncPerfEventArray, AsyncPerfEventArrayBuffer};
use anyhow::{Result, anyhow};
use bytes::BytesMut;
use tokio::sync::mpsc::Sender;
use log::*;

use common_defs::EvtOpen;

const SYSCALLS: &[&str] = &[ "creat", "open", "openat", "openat2" ];
const MINORBITS: usize = 20;

pub struct OpenMonitor {
    bpf: Bpf,
    inodes: InodeCache,
}

impl OpenMonitor {
    pub fn load() -> Result<Self> {
        info!("Building inode cache");
        let inodes = InodeCache::load()?;
        info!("Done building inode cache");
/*
        #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/debug/ebpf"
        ))?;
        #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/ebpf"
        ))?;
*/

        let mut bpf = Bpf::load(include_bytes_aligned!(
            "../../ebpf/probes.bpf.o"
        ))?;

        for syscall in SYSCALLS {
            for hook in &["exit"] {
                let tp_name = format!("sys_{hook}_{syscall}");
                let prog_name = format!("{hook}_{syscall}");
                let prog = bpf.program_mut(&prog_name)
                    .ok_or(anyhow!("BPF prog not found: {prog_name}"))?;
                let tp: &mut TracePoint = prog.try_into()?;
                
                tp.load()?;
                tp.attach("syscalls", &tp_name)?;
            }
        }

        Ok(Self{
            bpf,
            inodes,
        })
    }

    pub async fn run(self, ch: Sender<OpenEvent>) -> Result<()> {
        let mut perf_array = AsyncPerfEventArray::try_from(self.bpf.map_mut("events")?)?;
        let inodes = Arc::new(self.inodes);

        let mut tasks = Vec::new();

        for cpu_id in aya::util::online_cpus()? {
            // open a separate perf buffer for each cpu
            let perf_buf = perf_array.open(cpu_id, None)?;

            let ch = ch.clone();
            let inodes = inodes.clone();

            // process each perf buffer in a separate task
            let tsk = tokio::task::spawn(async move {
                monitor_on(perf_buf, inodes, ch).await;
                info!("perf array task exiting");
            });

            tasks.push(tsk);
        }

        for tsk in tasks {
            _ = tsk.await;
            info!("perf array task exited");
        }

        Ok(())
    }
}

async fn monitor_on(mut perf_buf: AsyncPerfEventArrayBuffer<MapRefMut>, inodes: Arc<InodeCache>, ch: Sender<OpenEvent>) {
    let mut buffers = (0..10)
        .map(|_| BytesMut::with_capacity(1024))
        .collect::<Vec<_>>();

    loop {
        // wait for events
        debug!("waiting for events");
        if let Ok(events) = perf_buf.read_events(&mut buffers).await {
            // events.read contains the number of events that have been read,
            // and is always <= buffers.len()
            debug!("read {} events", events.read);
            for i in 0..events.read {
                let buf = &mut buffers[i];
                if let Ok(evt) = TryInto::<EvtOpen>::try_into(buf.as_ref()) {
                    if let Some(filename) = inodes.lookup(evt.dev, evt.ino) {
                        let open = OpenEvent{
                            cgroup: evt.cgroup,
                            filename: filename.clone(),
                        };
                        info!("match: {filename:?}, {}/{}", evt.dev, evt.ino);
                        _ = ch.send(open).await;
                    } else {
                        warn!("filename not found for dev={:x}, ino={}", evt.dev, evt.ino);
                    }
                }
            }
        } else {
            info!("no events, breaking");
            break;
        }
    }
}

pub struct OpenEvent {
    pub cgroup: u64,
    pub filename: OsString,
}

/*
fn cstr_to_str(buf: &[u8]) -> Result<String> {
    let s: Vec<u8> = buf.iter()
        .take_while(|x| **x != 0u8)
        .map(|x| *x)
        .collect();

    Ok(String::from_utf8(s)?)
}
*/

type DevIno = (u64, u64);

pub struct InodeCache {
    inner: HashMap<DevIno, OsString>,
}

impl InodeCache {
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

                        debug!("{} @ {devino:?}", full_name.to_string_lossy());
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