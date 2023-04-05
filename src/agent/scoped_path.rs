use std::path::{PathBuf, Path, Display};
use std::ffi::{CStr, OsStr};
use anyhow::Result;

// Relative to the host rootfs
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostPath(PathBuf);

impl HostPath {
    pub fn new(path: &Path) -> Self {
        Self(path.to_path_buf())
    }

    pub fn as_raw(&self) -> &Path {
        &self.0
    }

    pub fn display(&self) -> Display<'_> {
        self.0.display()
    }

    pub fn to_rootfs(&self, prefix: &RootFsPath) -> RootFsPath {
        RootFsPath(join(prefix.as_raw(), &self.0))
    }
}

impl <T: Into<PathBuf>> From<T> for HostPath {
    fn from(p: T) -> Self {
        Self(p.into())
    }
}

// Relative to the FS where the agent is running.
// If it's running in a container, it'll be prefixed
// with /host or similar.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RootFsPath(PathBuf);

impl RootFsPath {
    pub fn new(path: &Path) -> Self {
        Self(path.to_path_buf())
    }

    pub fn as_raw(&self) -> &Path {
        &self.0
    }

    pub fn display(&self) -> Display<'_> {
        self.0.display()
    }

    pub fn join<P: AsRef<Path>>(&self, path: P) -> RootFsPath {
        self.0.join(path).into()
    }

    pub fn realpath(&self) -> Result<Self> {
        // Do not use std::fs::canonicalize() as it uses libc::realpath
        // and musl implements it with open() which causes a feedback loop.
        let rp = realpath_ext::realpath(&self.0, realpath_ext::RealpathFlags::empty())?;
        Ok(RootFsPath::from(rp))
    }
}

impl <T: Into<PathBuf>> From<T> for RootFsPath {
    fn from(p: T) -> Self {
        Self(p.into())
    }
}

// Relative to the workload root
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WorkloadPath(PathBuf);

impl WorkloadPath {
    pub fn new(path: &Path) -> Self {
        Self(path.to_path_buf())
    }

    pub fn from_rootfs(prefix: &RootFsPath, path: &RootFsPath) -> Result<Self> {
        let stripped = path.as_raw()
            .strip_prefix(prefix.as_raw())?;

        Ok(PathBuf::from("/")
            .join(stripped)
            .into())
    }

    pub fn from_cstr(cstr: &CStr) -> Self {
        use std::os::unix::ffi::OsStrExt;

        OsStr::from_bytes(cstr.to_bytes())
            .to_os_string()
            .into()
    }

    pub fn as_raw(&self) -> &Path {
        &self.0
    }

    pub fn to_host(&self, prefix: &Path) -> HostPath {
        HostPath(join(prefix, &self.0))
    }

    pub fn to_rootfs(&self, prefix: &RootFsPath) -> RootFsPath {
        RootFsPath(join(prefix.as_raw(), &self.0))
    }

    pub fn display(&self) -> Display<'_> {
        self.0.display()
    }

    pub fn join(&self, path: &Path) -> WorkloadPath {
        self.0.join(path)
            .into()
    }

    pub fn realpath(&self, prefix: &RootFsPath) -> Result<Self> {
        let rp = self.to_rootfs(prefix)
            .realpath()?;

        Ok(WorkloadPath::from_rootfs(prefix, &rp)?)
    }
}

impl <T: Into<PathBuf>> From<T> for WorkloadPath {
    fn from(p: T) -> Self {
        Self(p.into())
    }
}

fn join(prefix: &Path, suffix: &Path) -> PathBuf {
    if suffix.is_absolute() {
        prefix.join(suffix.strip_prefix("/").unwrap())
    } else {
        prefix.join(suffix)
    }
}