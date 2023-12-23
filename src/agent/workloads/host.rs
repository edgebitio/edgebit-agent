use std::borrow::Cow;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use log::*;
use lru::LruCache;
use uuid::Uuid;

use crate::config::Config;
use crate::open_monitor::FileOpenMonitorArc;
use crate::registry::{PkgRef, Registry};
use crate::scoped_path::*;

use super::PathSet;

const BASEOS_ID_PATH: &str = "/var/lib/edgebit/baseos-id";

const OS_RELEASE_PATHS: [&str; 2] = ["etc/os-release", "usr/lib/os-release"];

const REPORTED_LRU_SIZE: NonZeroUsize = unsafe { NonZeroUsize::new_unchecked(256) };

pub struct HostWorkload {
    pub id: String,
    pub labels: HashMap<String, String>,
    pub hostname: String,
    pub os_pretty_name: String,
    pub image_id: String,
    pkgs: Registry,
    host_root: RootFsPath,
    includes: PathSet,
    reported: LruCache<WorkloadPath, ()>,
    in_use_batch: Vec<PkgRef>,
}

impl HostWorkload {
    pub fn new(
        image_id: String,
        config: Arc<Config>,
        open_mon: FileOpenMonitorArc,
        labels: HashMap<String, String>,
    ) -> Result<Self> {
        let host_root = RootFsPath::from(config.host_root());
        let id = load_baseos_id();

        let os_pretty_name = match get_os_release(&host_root) {
            Ok(mut os_release) => os_release
                .remove("PRETTY_NAME")
                .or_else(|| os_release.remove("NAME"))
                .unwrap_or("Linux".to_string()),
            Err(err) => {
                error!("Failed to retrieve os-release: {err}");
                String::new()
            }
        };

        let mut includes = PathSet::new()?;
        for path in config.host_includes() {
            match WorkloadPath::from(&path).realpath(&host_root) {
                Ok(path) => {
                    let rootfs_path = path.to_rootfs(&host_root);
                    if let Err(err) = open_mon.add_path(&rootfs_path) {
                        error!(
                            "Failed to start monitoring {} for container: {err}",
                            rootfs_path.display()
                        );
                    }

                    includes.add(path);
                }
                Err(err) => {
                    // ignore "no such file or directory" errors
                    if !super::is_not_found(&err) {
                        error!("Failed to add a watch for {}: {err}", path.display());
                    }
                }
            };
        }

        Ok(Self {
            id,
            labels,
            hostname: config.hostname(),
            os_pretty_name,
            image_id,
            pkgs: Registry::new(),
            host_root,
            includes,
            reported: LruCache::new(REPORTED_LRU_SIZE),
            in_use_batch: Vec::new(),
        })
    }

    pub fn file_opened(&mut self, filename: &WorkloadPath) {
        match self.resolve(filename) {
            Ok(Some(filepath)) => {
                // if already reported, no need to do it again
                if !self.check_and_mark_reported(filepath.clone()) {
                    let filenames = vec![filepath];
                    let mut pkgs = self.pkgs.get_packages(filenames);

                    if !pkgs.is_empty() {
                        self.in_use_batch.append(&mut pkgs);
                    }
                }
            }
            Ok(None) => (),
            Err(err) => super::resolve_failed(filename, err),
        }
    }

    pub fn flush_in_use(&mut self) -> (String, Vec<PkgRef>) {
        (self.id.clone(), self.in_use_batch.split_off(0))
    }

    // Checks if the path is not filtered out and returns canonicalized verison
    fn resolve(&self, path: &WorkloadPath) -> Result<Option<WorkloadPath>> {
        let rp = path.to_rootfs(&self.host_root).realpath()?;

        if !super::is_file(&rp) {
            return Ok(None);
        }

        let path = WorkloadPath::from_rootfs(&self.host_root, &rp)?;

        if self.includes.contains(&path) {
            Ok(Some(path))
        } else {
            Ok(None)
        }
    }

    // Returns true if the file was already reported
    fn check_and_mark_reported(&mut self, filename: WorkloadPath) -> bool {
        self.reported.put(filename, ()).is_some()
    }
}

fn load_baseos_id() -> String {
    if let Ok(id) = std::fs::read_to_string(BASEOS_ID_PATH) {
        return id;
    }

    let id = uuid_string();

    if let Err(err) = std::fs::write(BASEOS_ID_PATH, &id) {
        error!("Failed to save BaseOS workload ID to {BASEOS_ID_PATH}: {err}");
    }

    id
}

fn uuid_string() -> String {
    let mut buf = Uuid::encode_buffer();
    Uuid::new_v4()
        .as_hyphenated()
        .encode_lower(&mut buf)
        .to_string()
}

fn get_os_release(
    host_root: &RootFsPath,
) -> rs_release::Result<HashMap<Cow<'static, str>, String>> {
    for file in OS_RELEASE_PATHS {
        let file = host_root.join(&PathBuf::from(file));
        if let Ok(release) = rs_release::parse_os_release(file.as_raw()) {
            return Ok(release);
        }
    }
    Err(rs_release::OsReleaseError::NoFile)
}
