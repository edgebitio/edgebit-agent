use aya::{Bpf, include_bytes_aligned};
use aya::programs::{TracePoint};
use aya::maps::perf::AsyncPerfEventArray;
use anyhow::{Result, anyhow};
use bytes::BytesMut;
use tokio::sync::mpsc::Sender;

use common_defs::EvtOpen;

const SYSCALLS: &[&str] = &[ "creat", "open", "openat", "openat2" ];

pub struct OpenMonitor {
    bpf: Bpf,
}

impl OpenMonitor {
    pub fn load() -> Result<Self> {
        #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/debug/ebpf"
        ))?;
        #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/ebpf"
        ))?;

        for syscall in SYSCALLS {
            for hook in &["enter", "exit"] {
                let tp_name = format!("sys_{hook}_{syscall}");
                let prog_name = format!("{hook}_{syscall}");
                let prog = bpf.program_mut(&prog_name)
                    .ok_or(anyhow!("BPF prog not found: {prog_name}"))?;
                let tp: &mut TracePoint = prog.try_into()?;
                
                tp.load()?;
                tp.attach("syscalls", &tp_name)?;
            }
        }

        Ok(Self{bpf})
    }

    pub async fn run(self, ch: Sender<OpenEvent>) -> Result<()> {
        let mut perf_array = AsyncPerfEventArray::try_from(self.bpf.map_mut("EVENTS")?)?;

        let mut tasks = Vec::new();

        for cpu_id in aya::util::online_cpus()? {
            // open a separate perf buffer for each cpu
            let mut buf = perf_array.open(cpu_id, None)?;

            let ch = ch.clone();

            // process each perf buffer in a separate task
            let tsk = tokio::task::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();

                loop {
                    // wait for events
                    if let Ok(events) = buf.read_events(&mut buffers).await {
                        // events.read contains the number of events that have been read,
                        // and is always <= buffers.len()
                        for i in 0..events.read {
                            let buf = &mut buffers[i];
                            if let Ok(evt) = buf.as_ref().try_into() {
                                _ = ch.send(evt).await;
                            }
                        }
                    } else {
                        break;
                    }
                }
            });

            tasks.push(tsk);
        }

        for tsk in tasks {
            _ = tsk.await;
        }

        Ok(())
    }
}

pub struct OpenEvent {
    pub cgroup: u64,
    pub flags: u32,
    pub ret: i32,
    pub filename: String,
}

impl TryFrom<&[u8]> for OpenEvent {
    type Error = anyhow::Error;

    fn try_from(buf: &[u8]) -> Result<Self> {
        let sz = std::mem::size_of::<EvtOpen>();
        if buf.len() < sz {
            return Err(anyhow!("buffer too small"));
        }

        let evt: &EvtOpen = bytemuck::from_bytes(&buf[..sz]);

        Ok(OpenEvent{
            cgroup: evt.cgroup,
            flags: evt.flags,
            ret: evt.ret,
            filename: cstr_to_str(&evt.filename)?,
        })
    }
}

fn cstr_to_str(buf: &[u8]) -> Result<String> {
    let s: Vec<u8> = buf.iter()
        .take_while(|x| **x != 0u8)
        .map(|x| *x)
        .collect();

    Ok(String::from_utf8(s)?)
}
