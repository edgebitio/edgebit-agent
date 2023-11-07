use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use nix::NixPath;
use serde::Deserialize;

pub const CONFIG_PATH: &str = "/etc/edgebit/config.yaml";

const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_DOCKER_HOST: &str = "unix:///run/docker.sock";
const DEFAULT_CONTAINERD_ROOTS: &str = "/run/containerd/io.containerd.runtime.v2.task/k8s.io/";

static DEFAULT_HOST_INCLUDES: &[&str] = &[
    "/bin", "/lib", "/lib32", "/lib64", "/libx32", "/opt", "/sbin", "/usr",
];

static DEFAULT_HOST_EXCLUDES: &[&str] = &[];

static DEFAULT_CONTAINER_EXCLUDES: &[&str] = &[];

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inner {
    pub edgebit_id: Option<String>,

    edgebit_url: Option<String>,

    log_level: Option<String>,

    host_includes: Option<Vec<String>>,

    host_excludes: Option<Vec<String>>,

    container_excludes: Option<Vec<String>>,

    syft_config: Option<PathBuf>,

    syft_path: Option<PathBuf>,

    docker_host: Option<String>,

    containerd_host: Option<String>,

    containerd_roots: Option<PathBuf>,

    pkg_tracking: Option<bool>,

    hostname: Option<String>,

    host_root: Option<PathBuf>,

    labels: Option<HashMap<String, String>>,
}

// TODO: probably worth using Figment or similar to unify yaml and env vars
pub struct Config {
    inner: Inner,
}

impl Config {
    pub fn load<P: AsRef<Path>>(
        path: P,
        hostname: Option<String>,
        host_root: Option<PathBuf>,
    ) -> Result<Self> {
        let mut inner: Inner = match std::fs::File::open(path.as_ref()) {
            Ok(file) => serde_yaml::from_reader(file)?,
            Err(err) => {
                if err.kind() != std::io::ErrorKind::NotFound {
                    // Don't bail since the config can also be provided via env vars.
                    // Do print a warning.
                    eprintln!(
                        "Could not open config file at {}, {err}",
                        path.as_ref().display()
                    );
                }
                Inner::default()
            }
        };

        inner.hostname = hostname;
        inner.host_root = host_root;

        let me = Self { inner };

        // check that the config items are there
        me.try_edgebit_id()?;
        me.try_edgebit_url()?;
        me.try_syft_path()?;
        me.try_syft_config()?;

        Ok(me)
    }

    pub fn edgebit_id(&self) -> String {
        self.try_edgebit_id().unwrap()
    }

    fn try_edgebit_id(&self) -> Result<String> {
        if let Ok(id) = std::env::var("EDGEBIT_ID") {
            Ok(id)
        } else {
            self.inner.edgebit_id.clone().ok_or(anyhow!(
                "$EDGEBIT_ID not set and .edgebit_id missing in config file"
            ))
        }
    }

    pub fn edgebit_url(&self) -> String {
        self.try_edgebit_url().unwrap()
    }

    fn try_edgebit_url(&self) -> Result<String> {
        if let Ok(id) = std::env::var("EDGEBIT_URL") {
            Ok(id)
        } else {
            self.inner.edgebit_url.clone().ok_or(anyhow!(
                "$EDGEBIT_URL not set and .edgebit_url missing in config file"
            ))
        }
    }

    pub fn log_level(&self) -> String {
        if let Ok(level) = std::env::var("EDGEBIT_LOG_LEVEL") {
            level
        } else {
            self.inner
                .log_level
                .clone()
                .unwrap_or_else(|| DEFAULT_LOG_LEVEL.to_string())
        }
    }

    pub fn host_includes(&self) -> Vec<PathBuf> {
        paths(&self.inner.host_includes, DEFAULT_HOST_INCLUDES)
    }

    pub fn host_excludes(&self) -> Vec<PathBuf> {
        paths(&self.inner.host_excludes, DEFAULT_HOST_EXCLUDES)
    }

    pub fn container_excludes(&self) -> Vec<PathBuf> {
        paths(&self.inner.container_excludes, DEFAULT_CONTAINER_EXCLUDES)
    }

    fn try_syft_config(&self) -> Result<PathBuf> {
        if let Ok(syft_conf) = std::env::var("EDGEBIT_SYFT_CONFIG") {
            Ok(PathBuf::from(syft_conf))
        } else {
            self.inner.syft_config.clone().ok_or(anyhow!(
                "$EDGEBIT_SYFT_CONFIG not set and .syft_config missing in config file"
            ))
        }
    }

    pub fn syft_config(&self) -> PathBuf {
        self.try_syft_config().unwrap()
    }

    fn try_syft_path(&self) -> Result<PathBuf> {
        if let Ok(path) = std::env::var("EDGEBIT_SYFT_PATH") {
            Ok(PathBuf::from(path))
        } else {
            self.inner.syft_path.clone().ok_or(anyhow!(
                "$EDGEBIT_SYFT_PATH not set and .syft_path missing in config file"
            ))
        }
    }

    pub fn syft_path(&self) -> PathBuf {
        self.try_syft_path().unwrap()
    }

    pub fn docker_host(&self) -> Option<String> {
        if let Ok(host) = std::env::var("DOCKER_HOST") {
            if host.is_empty() {
                None
            } else {
                Some(host)
            }
        } else {
            self.inner
                .docker_host
                .clone()
                .or_else(|| Some(DEFAULT_DOCKER_HOST.to_string()))
        }
    }

    pub fn containerd_host(&self) -> Option<String> {
        if let Ok(host) = std::env::var("EDGEBIT_CONTAINERD_HOST") {
            if host.is_empty() {
                None
            } else {
                Some(host)
            }
        } else {
            self.inner.containerd_host.clone()
        }
    }

    pub fn containerd_roots(&self) -> PathBuf {
        if let Ok(roots) = std::env::var("EDGEBIT_CONTAINERD_ROOTS") {
            if !roots.is_empty() {
                return roots.into();
            }
        }

        if let Some(ref roots) = self.inner.containerd_roots {
            if !roots.is_empty() {
                return roots.into();
            }
        }

        DEFAULT_CONTAINERD_ROOTS.into()
    }

    pub fn hostname(&self) -> String {
        self.inner
            .hostname
            .clone()
            .or_else(|| std::env::var("EDGEBIT_HOSTNAME").ok())
            .unwrap_or_else(|| gethostname::gethostname().to_string_lossy().into_owned())
    }

    pub fn host_root(&self) -> PathBuf {
        self.inner
            .host_root
            .clone()
            .or_else(|| std::env::var("EDGEBIT_HOSTROOT").ok().map(PathBuf::from))
            .unwrap_or(PathBuf::from("/"))
    }

    pub fn pkg_tracking(&self) -> bool {
        self.inner
            .pkg_tracking
            .or_else(|| {
                std::env::var("EDGEBIT_PKG_TRACKING")
                    .ok()
                    .map(|v| is_yes(&v))
            })
            .unwrap_or(true)
    }

    pub fn labels(&self) -> HashMap<String, String> {
        let mut labels = self.inner.labels.clone().unwrap_or_default();

        if let Ok(labels_str) = std::env::var("EDGEBIT_LABELS") {
            labels.extend(labels_str.split(';').filter_map(|kv| {
                kv.split_once('=')
                    .map(|(k, v)| (k.to_string(), v.to_string()))
            }));
        }

        // remap into the 'user:' namespace
        labels
            .into_iter()
            .map(|(k, v)| ("user:".to_string() + &k, v))
            .collect()
    }
}

fn paths(lst: &Option<Vec<String>>, def: &[&str]) -> Vec<PathBuf> {
    match lst {
        Some(lst) => lst.iter().map(|p| p.into()).collect(),
        None => def.iter().map(|s| s.into()).collect(),
    }
}

fn is_yes(val: &str) -> bool {
    let val = val.to_lowercase();
    val == "1" || val == "yes" || val == "true"
}
