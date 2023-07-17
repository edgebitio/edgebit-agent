use std::ffi::{OsString, OsStr, CString, CStr};
use std::os::unix::ffi::OsStringExt;
use std::path::{PathBuf, Path};
use std::os::fd::{AsRawFd, OwnedFd, FromRawFd, RawFd};

use anyhow::Result;
use nix::sys::wait::WaitStatus;
use nix::unistd::ForkResult;
use nix::fcntl::{AtFlags, FdFlag};
use tokio_pipe::{PipeRead, PipeWrite};


pub struct CommandWithChroot {
    exe: PathBuf,
    chroot: PathBuf,
    args: Vec<OsString>,
    stdin_file: Option<std::fs::File>,
    stdout_file: Option<std::fs::File>,
    stderr_file: Option<std::fs::File>,
}

impl CommandWithChroot {
    pub fn new(exe: PathBuf) -> Self {
        Self {
            exe,
            chroot: PathBuf::from("/"),
            args: Vec::new(),
            stdin_file: None,
            stdout_file: None,
            stderr_file: None,
        }
    }

    pub fn chroot(&mut self, root: PathBuf) -> &mut Self {
        self.chroot = root;
        self
    }

    pub fn arg(&mut self, a: OsString) -> &mut Self {
        self.args.push(a);
        self
    }

    pub fn stdin(&mut self, f: std::fs::File) -> &mut Self {
        self.stdin_file = Some(f);
        self
    }

    pub fn stdout(&mut self, f: std::fs::File) -> &mut Self {
        self.stdout_file = Some(f);
        self
    }

    pub fn stderr(&mut self, f: std::fs::File) -> &mut Self {
        self.stderr_file = Some(f);
        self
    }

    pub async fn run(self) -> Result<WaitStatus> {
        let mut inp = self.stdin_file.map(PipedInFile::new)
            .transpose()?;

        let mut outp = self.stdout_file.map(PipedOutFile::new)
            .transpose()?;

        let mut errp = self.stderr_file.map(PipedOutFile::new)
            .transpose()?;

        let args: Vec<CString> = self.args.into_iter()
            .map(|s| CString::new(s.into_vec()).unwrap())
            .collect();

        let env: Vec<CString> = std::env::vars()
            .map(|(k, v)| format!("{k}={v}"))
            .map(|s| CString::new(s).unwrap())
            .collect();

        match unsafe { nix::unistd::fork()? } {
            ForkResult::Parent{ child, .. } => {
                if let Some(ref mut inp) = inp {
                    inp.close();
                }

                if let Some(ref mut outp) = outp {
                    outp.close();
                }

                if let Some(ref mut errp) = errp {
                    errp.close();
                }

                let status = tokio::task::spawn_blocking(move || {
                    nix::sys::wait::waitpid(child, None)
                }).await??;

                if let Some(inp) = inp {
                    _ = inp.join().await;
                }

                if let Some(outp) = outp {
                    _ = outp.join().await;
                }

                if let Some(errp) = errp {
                    _ = errp.join().await;
                }

                Ok(status)

            },
            ForkResult::Child => {
                // From here to execve, we have to be very careful not to touch anything
                // that may malloc. It's a multi-threaded app and forking
                // in mutli-threaded apps is problematic since we can't know the state
                // of locks at the time of fork.
                if let Some(ref mut inp) = inp {
                    if inp.dup_to(0).is_err() {
                        die("dup2(0) failed");
                    }
                } else if clear_cloexec(0).is_err() {
                    die("clearing FD_CLOEXEC for fd=0 failed");
                }

                if let Some(ref mut outp) = outp {
                    if outp.dup_to(1).is_err() {
                        die("dup2(1) failed");
                    }
                } else if clear_cloexec(1).is_err() {
                    die("clearing FD_CLOEXEC for fd=1 failed");
                }

                if let Some(ref mut errp) = errp {
                    if errp.dup_to(2).is_err() {
                        die("dup2(2) failed");
                    }
                } else if clear_cloexec(2).is_err() {
                    die("clearing FD_CLOEXEC for fd=2 failed");
                }

                if chroot_exec(&self.exe, &self.chroot, &args, &env).is_err() {
                    die("chroot_exec failed");
                }
                panic!("unreachable");
            },
        }
    }

}

// Opens the executable, performs a chroot, executes the opened executable
fn chroot_exec(exe: &Path, chroot: &Path, args: &[CString], env: &[CString]) -> nix::Result<()> {
    let fd = open_file(exe)?;

    if chroot != OsStr::new("/") {
        nix::unistd::chroot(chroot)?;
    }

    nix::unistd::chdir("/")?;
    nix::unistd::execveat(fd.as_raw_fd(), <&CStr>::default(), args, env, AtFlags::AT_EMPTY_PATH)?;
    // never returns

    Ok(())
}

struct PipedInFile {
    inp: Option<PipeRead>,
    task: tokio::task::JoinHandle<Result<PipeWrite>>,
}

impl PipedInFile {
    fn new(file: std::fs::File) -> Result<Self> {
        let (r, mut w) = tokio_pipe::pipe()?;
        clear_cloexec(r.as_raw_fd())?;

        let task = tokio::task::spawn(async move {
            let mut file = tokio::fs::File::from_std(file);
            tokio::io::copy(&mut file, &mut w).await?;
            Ok(w)
        });

        Ok(Self {
            inp: Some(r),
            task,
        })
    }

    fn dup_to(&mut self, newfd: RawFd) -> nix::Result<()> {
        if let Some(ref inp) = self.inp {
            let fd = nix::unistd::dup2(inp.as_raw_fd(), newfd)?;
            self.inp = Some(PipeRead::from_raw_fd_checked(fd).unwrap());
        }

        Ok(())
    }

    fn close(&mut self) {
        self.inp = None;
    }

    async fn join(self) -> Result<()> {
        self.task.await??;
        Ok(())
    }
}
struct PipedOutFile {
    outp: Option<PipeWrite>,
    task: tokio::task::JoinHandle<Result<PipeRead>>,
}

impl PipedOutFile {
    fn new(file: std::fs::File) -> Result<Self> {
        let (mut r, w) = tokio_pipe::pipe()?;
        clear_cloexec(w.as_raw_fd())?;

        let task = tokio::task::spawn(async move {
            let mut file = tokio::fs::File::from_std(file);
            tokio::io::copy(&mut r, &mut file).await?;
            Ok(r)
        });

        Ok(Self {
            outp: Some(w),
            task,
        })
    }

    fn dup_to(&mut self, newfd: RawFd) -> nix::Result<()> {
        if let Some(ref outp) = self.outp {
            let fd = nix::unistd::dup2(outp.as_raw_fd(), newfd)?;
            self.outp = Some(PipeWrite::from_raw_fd_checked(fd).unwrap());
        }

        Ok(())
    }

    fn close(&mut self) {
        self.outp = None;
    }

    async fn join(self) -> Result<()> {
        self.task.await??;
        Ok(())
    }
}

fn open_file(path: &Path) -> nix::Result<OwnedFd> {
    // stdlib File::open insists on setting O_CLOEXEC, which we don't want.
    let fd = nix::fcntl::open(path, nix::fcntl::OFlag::empty(), nix::sys::stat::Mode::empty())?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) } )
}

fn clear_cloexec(fd: RawFd) -> nix::Result<()> {
    let flags = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFD)?;
    let mut flags = FdFlag::from_bits_truncate(flags);
    flags.remove(FdFlag::FD_CLOEXEC);
    nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_SETFD(flags))?;

    Ok(())
}

pub struct TmpFS {
    mountpt: PathBuf,
}

impl TmpFS {
    pub fn mount(mountpt: PathBuf) -> Result<Self> {
        // Mount tmpfs
        nix::mount::mount(
            Some("tmpfs"),
            &mountpt,
            Some("tmpfs"),
            nix::mount::MsFlags::empty(),
            Option::<&Path>::None,
        )?;

        // Disable mount propagation
        nix::mount::mount(
            Some("none"),
            &mountpt,
            Option::<&Path>::None,
            nix::mount::MsFlags::MS_PRIVATE,
            Option::<&Path>::None,
        )?;

        Ok(Self { mountpt })
    }

    pub fn mountpoint(&self) -> &Path {
        &self.mountpt
    }
}

impl Drop for TmpFS {
    fn drop(&mut self) {
        _ = nix::mount::umount(&self.mountpt)
    }
}

fn die(msg: &str) {
    // Can't use print! b/c it'll allocate.
    // Can't use std::io::stderr() b/c it requires taking a lock.
    _ = nix::unistd::write(2, msg.as_bytes());
    std::process::exit(1);
}