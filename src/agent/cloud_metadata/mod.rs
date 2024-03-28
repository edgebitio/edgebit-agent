mod azure;
mod ec2;
mod gce;

use std::collections::HashMap;
use std::sync::Arc;

use log::*;

pub(crate) trait MetadataProvider {
    fn host_labels(&self) -> HashMap<String, String>;

    fn container_labels(&self, id: &str) -> HashMap<String, String>;
}

struct NullProvider;

impl MetadataProvider for NullProvider {
    fn host_labels(&self) -> HashMap<String, String> {
        HashMap::new()
    }

    fn container_labels(&self, _id: &str) -> HashMap<String, String> {
        HashMap::new()
    }
}

#[derive(Clone)]
pub struct CloudMetadata {
    provider: Arc<dyn MetadataProvider + Send + Sync>,
}

impl CloudMetadata {
    pub async fn load() -> Self {
        match ec2::Ec2Metadata::load().await {
            Ok(p) => {
                return Self {
                    provider: Arc::new(p),
                }
            }
            Err(err) => debug!("ec2 load metadata: {err}"),
        }

        match gce::GceMetadata::load().await {
            Ok(p) => {
                return Self {
                    provider: Arc::new(p),
                }
            }
            Err(err) => debug!("gce load metadata {err}"),
        }

        match azure::AzureMetadata::load().await {
            Ok(p) => {
                return Self {
                    provider: Arc::new(p),
                }
            }
            Err(err) => debug!("azure load metadata {err}"),
        }

        Self {
            provider: Arc::new(NullProvider),
        }
    }

    pub fn host_labels(&self) -> HashMap<String, String> {
        self.provider.host_labels()
    }

    pub fn container_labels(&self, id: &str) -> HashMap<String, String> {
        self.provider.container_labels(id)
    }
}
