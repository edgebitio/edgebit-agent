use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Deserialize;

pub const CONFIG_PATH: &str = "/etc/edgebit/config.yaml";

const DEFAULT_EDGEBIT_URL: &str = "https://agents.edgebit.io";
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_DOCKER_HOST: &str = "unix:///var/run/docker.sock";

static DEFAULT_INCLUDES: &[&str] = &["/bin", "/lib", "/lib32", "/lib64", "/libx32", "/opt", "/sbin", "/usr"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inner {
    pub edgebit_id: String,

    edgebit_url: Option<String>,

    log_level: Option<String>,

    host_includes: Option<Vec<String>>,

    container_includes: Option<Vec<String>>,

    syft_config: String,

    syft_path: PathBuf,

    docker_socket: Option<String>,
}

pub struct Config {
    inner: Inner,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = std::fs::File::open(path)?;

        let inner = serde_yaml::from_reader(file)?;
        Ok(Self{
            inner,
        })
    }

    pub fn edgebit_id(&self) -> String {
        self.inner.edgebit_id.clone()
    }

    pub fn edgebit_url(&self) -> String {
        self.inner.edgebit_url
            .clone()
            .unwrap_or_else(|| DEFAULT_EDGEBIT_URL.to_string())
    }

    pub fn log_level(&self) -> String {
        if let Ok(level) = std::env::var("RUST_LOG") {
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

    pub fn syft_config(&self) -> String {
        self.inner.syft_config.clone()
    }


    pub fn syft_path(&self) -> PathBuf {
        self.inner.syft_path.clone()
    }

    pub fn docker_host(&self) -> String {
        self.inner.docker_socket
            .clone()
            .or_else(|| std::env::var("DOCKER_HOST").ok())
            .unwrap_or(DEFAULT_DOCKER_HOST.to_string())
    }
}