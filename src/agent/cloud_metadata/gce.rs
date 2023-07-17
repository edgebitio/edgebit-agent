use std::collections::HashMap;

use anyhow::{anyhow, Result};
use hyper::{Body, Client, Method, Request, StatusCode};
use lazy_static::lazy_static;
use log::*;
use regex::Regex;
use serde::Deserialize;

use crate::label::*;

const METADATA_SERVICE_HOST: &str = "metadata.google.internal";

lazy_static! {
    // Docker containers will contain the id somewhere in the cgroup name
    static ref ZONE_RE: Regex = Regex::new(r".*/zones/(.*)").unwrap();
}

#[derive(Deserialize)]
struct Instance {
    id: Option<u64>,
    image: Option<String>,
    zone: Option<String>,
}

#[derive(Deserialize)]
struct Project {
    #[serde(rename = "projectId")]
    project_id: Option<String>,
}

#[derive(Deserialize)]
struct MetadataDocument {
    instance: Option<Instance>,
    project: Option<Project>,
}

impl MetadataDocument {
    async fn load(url: &str) -> Result<Self> {
        let client = Client::new();

        let req = Request::builder()
            .method(Method::GET)
            .header("Metadata-Flavor", "Google")
            .uri(url)
            .body(Body::empty())?;

        let resp = client.request(req).await?;
        match resp.status() {
            StatusCode::OK => {
                let bytes = hyper::body::to_bytes(resp.into_body()).await?;
                info!("Loaded metadata: {}", String::from_utf8_lossy(&bytes));

                let doc: MetadataDocument = serde_json::from_slice(&bytes)?;

                Ok(doc)
            }
            code => Err(anyhow!("Non-200 response: {code}")),
        }
    }
}

pub struct GceMetadata {
    doc: MetadataDocument,
}

impl GceMetadata {
    pub async fn load_from_host(host: &str) -> Result<Self> {
        let url = format!("http://{host}/computeMetadata/v1/?recursive=true");
        let doc = MetadataDocument::load(&url).await?;

        Ok(GceMetadata { doc })
    }

    pub async fn load() -> Result<Self> {
        Self::load_from_host(METADATA_SERVICE_HOST).await
    }
}

impl super::MetadataProvider for GceMetadata {
    fn host_labels(&self) -> HashMap<String, String> {
        let mut labels: HashMap<String, String> =
            [(LABEL_CLOUD_PROVIDER.to_string(), "gce".to_string())].into();

        if let Some(ref instance) = self.doc.instance {
            if let Some(ref id) = instance.id {
                labels.insert(LABEL_INSTANCE_ID.to_string(), format!("{id}"));
            }

            if let Some(ref id) = instance.image {
                labels.insert(LABEL_IMAGE_ID.to_string(), id.clone());
            }

            if let Some(ref zone) = instance.zone {
                let (region, zone) = parse_zone(zone);
                if let Some(region) = region {
                    labels.insert(LABEL_CLOUD_REGION.to_string(), region);
                }

                if let Some(zone) = zone {
                    labels.insert(LABEL_CLOUD_ZONE.to_string(), zone);
                }
            }
        }

        if let Some(ref project) = self.doc.project {
            if let Some(ref id) = project.project_id {
                labels.insert(LABEL_CLOUD_PROJECT_ID.to_string(), id.clone());
            }
        }

        labels
    }

    fn container_labels(&self, _id: &str) -> HashMap<String, String> {
        let mut labels = self.host_labels();

        // container has its own image id
        labels.remove(LABEL_IMAGE_ID);

        labels
    }
}

fn parse_zone(val: &str) -> (Option<String>, Option<String>) {
    match ZONE_RE.captures(val) {
        Some(groups) => {
            let zone = groups.get(1).unwrap().as_str();

            // to get the region, strip off the zone at the end
            match zone.rsplit_once('-') {
                Some((region, _)) => (Some(region.to_string()), Some(zone.to_string())),
                None => (None, Some(zone.to_string())),
            }
        }
        None => (None, None),
    }
}
#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use assert2::assert;
    use hyper::service::{make_service_fn, service_fn};
    use hyper::{Response, Server};

    use super::*;

    const TEST_METADATA: &str = r#"
{
  "instance": {
    "attributes": {
      "cluster-location": "us-central1-c",
      "cluster-name": "eugene-cluster",
      "cluster-uid": "4c6f892d16624b2f8e6a5e607010542f235fcc3527274e1281e18be0fd825590",
      "created-by": "projects/518549494526/zones/us-central1-c/instanceGroupManagers/gke-eugene-cluster-default-pool-d8f96253-grp",
      "disable-legacy-endpoints": "true",
      "gci-metrics-enabled": "true",
      "gci-update-strategy": "update_disabled",
      "google-compute-enable-pcid": "true",
      "instance-template": "projects/518549494526/global/instanceTemplates/gke-eugene-cluster-default-pool-31a27d4b"
    },
    "cpuPlatform": "Intel Broadwell",
    "description": "",
    "disks": [
      {
        "deviceName": "persistent-disk-0",
        "index": 0,
        "interface": "SCSI",
        "mode": "READ_WRITE",
        "type": "PERSISTENT-BALANCED"
      }
    ],
    "guestAttributes": {},
    "hostname": "gke-eugene-cluster-default-pool-d8f96253-3irv.us-central1-c.c.sandbox-373114.internal",
    "id": 7857118082129425400,
    "image": "projects/gke-node-images/global/images/gke-12410-gke2300-cos-97-16919-235-13-v230222-c-pre",
    "licenses": [],
    "machineType": "projects/518549494526/machineTypes/e2-medium",
    "maintenanceEvent": "NONE",
    "name": "gke-eugene-cluster-default-pool-d8f96253-3irv",
    "networkInterfaces": [
    ],
    "preempted": "FALSE",
    "remainingCpuTime": -1,
    "scheduling": {
      "automaticRestart": "TRUE",
      "onHostMaintenance": "MIGRATE",
      "preemptible": "FALSE"
    },
    "tags": [
      "gke-eugene-cluster-4c6f892d-node"
    ],
    "virtualClock": {
      "driftToken": "0"
    },
    "zone": "projects/518549494526/zones/us-central1-c"
  },
  "oslogin": {
    "authenticate": {
      "sessions": {}
    }
  },
  "project": {
    "attributes": {
    },
    "numericProjectId": 818579394026,
    "projectId": "sandbox-373114"
  }
}"#;

    async fn mock_metadata_svc(
        req: Request<Body>,
    ) -> std::result::Result<Response<Body>, hyper::Error> {
        let flavor = req
            .headers()
            .get("Metadata-Flavor")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(flavor == "Google");

        assert!(req.uri() == "/computeMetadata/v1/?recursive=true");

        let resp_body = Body::from(TEST_METADATA);

        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(resp_body)
            .unwrap())
    }

    #[tokio::test]
    async fn test_gce() {
        use super::super::MetadataProvider;

        let addr = SocketAddr::V4("127.0.0.1:9992".parse().unwrap());

        let make_svc =
            make_service_fn(|_| async { Ok::<_, hyper::Error>(service_fn(mock_metadata_svc)) });
        let server = Server::bind(&addr).serve(make_svc);
        let server_task = tokio::task::spawn(server);

        let metadata = GceMetadata::load_from_host("localhost:9992").await.unwrap();
        let labels = metadata.host_labels();

        assert!(labels.get(LABEL_CLOUD_PROVIDER).unwrap() == "gce");
        assert!(labels.get(LABEL_INSTANCE_ID).unwrap() == "7857118082129425400");
        assert!(labels.get(LABEL_IMAGE_ID).unwrap() == "projects/gke-node-images/global/images/gke-12410-gke2300-cos-97-16919-235-13-v230222-c-pre");
        assert!(labels.get(LABEL_CLOUD_REGION).unwrap() == "us-central1");
        assert!(labels.get(LABEL_CLOUD_ZONE).unwrap() == "us-central1-c");
        assert!(labels.get(LABEL_CLOUD_PROJECT_ID).unwrap() == "sandbox-373114");

        server_task.abort();
        _ = server_task.await;
    }
}
