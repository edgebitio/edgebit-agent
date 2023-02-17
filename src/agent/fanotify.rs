use std::os::fd::{OwnedFd, FromRawFd, AsRawFd};
use std::io::ErrorKind;
use std::path::PathBuf;

use anyhow::Result;
use fanotify::low_level::{FAN_NONBLOCK, FAN_MARK_ADD, FAN_MARK_REMOVE, FAN_MARK_FILESYSTEM, FAN_OPEN, AT_FDCWD, O_RDONLY};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

pub struct Event {
    pub mask: u64,
    pub fd: OwnedFd,
    pub pid: i32,
}

impl Event {
    pub fn path(&self) -> Result<PathBuf> {
        let mut proc_path: PathBuf = "/proc/self/fd".into();
        let fd = self.fd.as_raw_fd() as i32;
        proc_path.push(fd.to_string());

        Ok(std::fs::read_link(proc_path)?)
    }
}

pub struct Fanotify {
    fd: AsyncFd<OwnedFd>,
}

impl Fanotify {
    pub fn new() -> Result<Self> {
        let fd = fanotify::low_level::fanotify_init(FAN_NONBLOCK, O_RDONLY)?;
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self{
            fd: AsyncFd::with_interest(owned, Interest::READABLE)?,
        })
    }

    pub fn add_open_mark(&self, path: &str) -> Result<()> {
        fanotify::low_level::fanotify_mark(
            self.fd.as_raw_fd() as i32,
            FAN_MARK_ADD|FAN_MARK_FILESYSTEM,
            FAN_OPEN,
            AT_FDCWD,
            path)?;

        Ok(())
    }

    pub fn remove_open_mark(&self, path: &str) -> Result<()> {
        fanotify::low_level::fanotify_mark(
            self.fd.as_raw_fd() as i32,
            FAN_MARK_REMOVE|FAN_MARK_FILESYSTEM,
            FAN_OPEN,
            AT_FDCWD,
            path)?;

        Ok(())
    }

    pub async fn next(&self) -> Result<Vec<Event>> {
        loop {
            let mut guard = self.fd.readable().await?;

            let items_res = guard.try_io(|inner| {
                fanotify::low_level::fanotify_read(inner.get_ref().as_raw_fd() as i32)
            });

            match items_res {
                Ok(Ok(items)) => {
                    return Ok(items.iter()
                        .map(|item| {
                            Event{
                                mask: item.mask,
                                fd: unsafe { OwnedFd::from_raw_fd(item.fd) },
                                pid: item.pid,
                            }
                        })
                        .collect())
                },
                Ok(Err(err)) => {
                    match err.kind() {
                        ErrorKind::WouldBlock => { continue; },
                        _ => return Err(err.into()),
                    }
                },
                Err(_) => continue,
            }
        }
    }
}