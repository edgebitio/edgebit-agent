use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use log::*;
use lru::LruCache;

use crate::config::Config;
use crate::containers::ContainerInfo;
use crate::open_monitor::FileOpenMonitorArc;
use crate::scoped_path::*;

use super::PathSet;

struct ContainerWorkload {
    root: RootFsPath,
    excludes: PathSet,
    reported: LruCache<WorkloadPath, ()>,
    in_use_batch: Vec<WorkloadPath>,
}

impl ContainerWorkload {
    fn new(root: RootFsPath, excludes: &[PathBuf]) -> Result<Self> {
        let mut exclude_set = PathSet::new()?;
        for path in excludes {
            let path = WorkloadPath::from(path);
            match path.realpath(&root) {
                Ok(path) => {
                    trace!("Excluding container path {}", path.display());
                    exclude_set.add(path);
                }
                Err(err) => {
                    // ignore "no such file or directory" erros
                    if !super::is_not_found(&err) {
                        error!("Failed to get realpath for {}: {err}", path.display());
                    }
                }
            };
        }

        Ok(Self {
            root,
            excludes: exclude_set,
            reported: LruCache::new(super::REPORTED_LRU_SIZE),
            in_use_batch: Vec::new(),
        })
    }

    fn resolve(&self, path: &WorkloadPath) -> Result<Option<WorkloadPath>> {
        let rp = path.to_rootfs(&self.root).realpath()?;

        if !super::is_file(&rp) {
            debug!("{} is not a file", rp.display());
            return Ok(None);
        }

        let path = WorkloadPath::from_rootfs(&self.root, &rp)?;

        if self.excludes.contains(&path) {
            debug!("{} was excluded", path.display());
            Ok(None)
        } else {
            Ok(Some(path))
        }
    }

    fn watchset(&self) -> Vec<RootFsPath> {
        let path = WorkloadPath::from("/").to_rootfs(&self.root);
        vec![path]
    }

    // Returns true if the file was already reported
    fn check_and_mark_reported(&mut self, filename: WorkloadPath) -> bool {
        self.reported.put(filename, ()).is_some()
    }

    fn file_opened(&mut self, path: &WorkloadPath) {
        match self.resolve(path) {
            Ok(Some(filepath)) => {
                // if already reported, no need to do it again
                if !self.check_and_mark_reported(filepath.clone()) {
                    self.in_use_batch.push(filepath);
                }
            }
            Ok(None) => (),
            Err(err) => {
                info!("{}: {err}", path.display());
                super::resolve_failed(path, err);
            }
        }
    }

    fn flush_in_use(&mut self) -> Vec<WorkloadPath> {
        self.in_use_batch.split_off(0)
    }
}

pub struct ContainerWorkloads {
    config: Arc<Config>,
    workloads: HashMap<String, ContainerWorkload>,
    open_monitor: FileOpenMonitorArc,
}

impl ContainerWorkloads {
    pub fn new(config: Arc<Config>, open_mon: FileOpenMonitorArc) -> Self {
        Self {
            config,
            workloads: HashMap::new(),
            open_monitor: open_mon,
        }
    }

    pub fn file_opened(&mut self, id: &str, filename: &WorkloadPath) {
        trace!("Container match: {id} for {}", filename.display());

        if let Some(workload) = self.workloads.get_mut(id) {
            workload.file_opened(filename);
        } else {
            error!("Container workload missing for id={id}");
        }
    }

    pub fn container_started(&mut self, id: String, mut info: ContainerInfo) {
        match &info.rootfs {
            Some(rootfs) => {
                let rootfs = rootfs.to_rootfs(&RootFsPath::from(self.config.host_root()));
                let mut excludes = self.config.container_excludes();
                excludes.append(&mut info.mounts);

                match ContainerWorkload::new(rootfs, &excludes) {
                    Ok(workload) => {
                        for path in workload.watchset() {
                            _ = self.open_monitor.add_path(&path);
                        }

                        self.workloads.insert(id, workload);
                    }
                    Err(err) => error!("Failed to create a container workload: {err}"),
                }
            }
            None => error!("Container {id} started but rootfs missing"),
        }
    }

    pub fn container_stopped(&mut self, id: String, _info: ContainerInfo) {
        let workload = self.workloads.remove(&id);

        if let Some(workload) = workload {
            for path in workload.watchset() {
                _ = self.open_monitor.remove_path(&path);
            }
        }
    }

    pub fn flush_in_use(&mut self) -> Vec<(String, Vec<WorkloadPath>)> {
        let mut in_use = Vec::new();

        for (id, w) in self.workloads.iter_mut() {
            in_use.push((id.clone(), w.flush_in_use()))
        }

        in_use
    }
}
