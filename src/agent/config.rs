use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use serde::Deserialize;

pub const CONFIG_PATH: &str = "/etc/edgebit/config.yaml";

const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_DOCKER_HOST: &str = "unix:///run/docker.sock";

static DEFAULT_INCLUDES: &[&str] = &["/bin", "/lib", "/lib32", "/lib64", "/libx32", "/opt", "/sbin", "/usr"];

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inner {
    pub edgebit_id: Option<String>,

    edgebit_url: Option<String>,

    log_level: Option<String>,

    host_includes: Option<Vec<String>>,

    container_includes: Option<Vec<String>>,

    syft_config: Option<PathBuf>,

    syft_path: Option<PathBuf>,

    docker_host: Option<String>,

    hostname: Option<String>,
}

// TODO: probably worth using Figment or similar to unify yaml and env vars
pub struct Config {
    inner: Inner,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P, hostname: Option<String>) -> Result<Self> {
        let mut inner: Inner = match std::fs::File::open(path.as_ref()) {
            Ok(file) => serde_yaml::from_reader(file)?,
            Err(err) => {
                // Don't bail since the config can also be provided via env vars.
                // Do print a warning.
                eprintln!("Could not open config file at {}, {err}", path.as_ref().display());
                Inner::default()
            }
        };

        inner.hostname = hostname;

        let me = Self{
            inner,
        };

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
            self.inner
                .edgebit_id
                .clone()
                .ok_or(anyhow!("$EDGEBIT_ID not set and .edgebit_id missing in config file"))
        }
    }

    pub fn edgebit_url(&self) -> String {
        self.try_edgebit_url().unwrap()
    }

    fn try_edgebit_url(&self) -> Result<String> {
        if let Ok(id) = std::env::var("EDGEBIT_URL") {
            Ok(id)
        } else {
            self.inner
                .edgebit_url
                .clone()
                .ok_or(anyhow!("$EDGEBIT_URL not set and .edgebit_url missing in config file"))
        }
    }

    pub fn log_level(&self) -> String {
        if let Ok(level) = std::env::var("EDGEBIT_LOG_LEVEL") {
            level
        } else {
            self.inner.log_level
                .clone()
                .unwrap_or_else(|| DEFAULT_LOG_LEVEL.to_string())
        }
    }

    pub fn host_includes(&self) -> Vec<String> {
        match &self.inner.host_includes {
            Some(includes) => {
                includes.iter()
                    .map(String::clone)
                    .collect()
            },
            None => {
                DEFAULT_INCLUDES.iter()
                    .map(|s| s.to_string())
                    .collect()
            }
        }
    }

    pub fn container_includes(&self) -> Vec<String> {
        match &self.inner.container_includes {
            Some(includes) => {
                includes.iter()
                    .map(String::clone)
                    .collect()
            },
            None => {
                DEFAULT_INCLUDES.iter()
                    .map(|s| s.to_string())
                    .collect()
            }
        }
    }

    fn try_syft_config(&self) -> Result<PathBuf> {
        if let Ok(syft_conf) = std::env::var("EDGEBIT_SYFT_CONFIG") {
            Ok(PathBuf::from(syft_conf))
        } else {
            self.inner.syft_config
                .clone()
                .ok_or(anyhow!("$EDGEBIT_SYFT_CONFIG not set and .syft_config missing in config file"))
        }
    }

    pub fn syft_config(&self) -> PathBuf {
        self.try_syft_config().unwrap()
    }

    fn try_syft_path(&self) -> Result<PathBuf> {
        if let Ok(path) = std::env::var("EDGEBIT_SYFT_PATH") {
            Ok(PathBuf::from(path))
        } else {
            self.inner.syft_path
                .clone()
                .ok_or(anyhow!("$EDGEBIT_SYFT_PATH not set and .syft_path missing in config file"))
        }
    }

    pub fn syft_path(&self) -> PathBuf {
        self.try_syft_path().unwrap()
    }

    pub fn docker_host(&self) -> String {
        if let Ok(host) = std::env::var("DOCKER_HOST") {
            host
        } else {
            self.inner.docker_host
                .clone()
                .unwrap_or_else(|| DEFAULT_DOCKER_HOST.to_string())
        }
    }

    pub fn hostname(&self) -> String {
        self.inner.hostname
            .clone()
            .or_else(|| std::env::var("EDGEBIT_HOSTNAME").ok())
            .unwrap_or_else(|| {
                gethostname::gethostname()
                    .to_string_lossy()
                    .into_owned()
            })
    }
}