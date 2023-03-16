use std::collections::HashMap;

use log::*;
use anyhow::Result;

use crate::sbom::Sbom;
use crate::scoped_path::*;

pub struct Registry {
    // Filename to a list of pkg ids
    inner: HashMap<WorkloadPath, Vec<String>>,
}

impl Registry {
    pub fn new() -> Self {
        Self { inner: HashMap::new() }
    }

    pub fn from_sbom(sbom: &Sbom, rootfs: &RootFsPath) -> Result<Self> {
        let mut inner: HashMap<WorkloadPath, Vec<String>> = HashMap::new();

        for pkg in sbom.artifacts() {
            match pkg.files(rootfs) {
                Ok(files) => {
                    for file in files {
                        inner.entry(file)
                            .or_default()
                            .push(pkg.id.to_string());
                    }
                },
                Err(e) => {
                    debug!("'{}': {e}", pkg.id);
                }
            }
        }

        Ok(Self{ inner })
    }

    pub fn get_packages(&self, filenames: Vec<WorkloadPath>) -> Vec<PkgRef> {
        let mut result: HashMap<String, PkgRef> = HashMap::new();

        for f in filenames {
            if let Some(pkg_ids) = self.inner.get(&f) {
                for id in pkg_ids {
                    match result.get_mut(id) {
                        Some(pkg) => pkg.filenames.push(f.clone()),
                        None => {
                            result.insert(id.clone(), PkgRef::new(id.clone(), f.clone()));
                        }
                    }
                }
            }
        }

        result.into_values().collect()
    }
}

pub struct PkgRef {
    pub id: String,
    pub filenames: Vec<WorkloadPath>,
}

impl PkgRef {
    fn new(id: String, filename: WorkloadPath) -> Self {
        Self {
            id,
            filenames: vec![filename],
        }
    }
}
