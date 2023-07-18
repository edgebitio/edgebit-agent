use std::collections::HashMap;

use anyhow::Result;
use aws_config::imds::client::Client;
use log::*;
use serde::Deserialize;

use crate::label::*;

#[derive(Deserialize)]
struct InstanceIdentityDocument {
    #[serde(rename = "accountId")]
    account_id: Option<String>,

    //architecture: String,
    #[serde(rename = "availabilityZone")]
    availability_zone: Option<String>,

    #[serde(rename = "imageId")]
    image_id: Option<String>,

    #[serde(rename = "instanceId")]
    instance_id: Option<String>,

    //#[serde(rename = "instanceType")]
    //instance_type: String,

    //#[serde(rename = "privateIp")]
    //privateIp: Option<String>,
    region: Option<String>,
}

impl InstanceIdentityDocument {
    fn from_str(doc_str: &str) -> Result<Self> {
        Ok(serde_json::from_str(doc_str)?)
    }

    async fn from_imds() -> Result<Self> {
        let client = Client::builder().build().await?;

        let doc = client
            .get("/2022-09-24/dynamic/instance-identity/document")
            .await?;

        info!("Loaded identity document: {doc}");

        Self::from_str(&doc)
    }
}

pub struct Ec2Metadata {
    doc: InstanceIdentityDocument,
}

impl Ec2Metadata {
    pub async fn load() -> Result<Self> {
        let doc = InstanceIdentityDocument::from_imds().await?;

        Ok(Ec2Metadata { doc })
    }
}

impl super::MetadataProvider for Ec2Metadata {
    fn host_labels(&self) -> HashMap<String, String> {
        let mut labels: HashMap<String, String> =
            [(LABEL_CLOUD_PROVIDER.to_string(), "ec2".to_string())].into();

        if let Some(ref id) = self.doc.instance_id {
            labels.insert(LABEL_INSTANCE_ID.to_string(), id.clone());
        }

        if let Some(ref id) = self.doc.image_id {
            labels.insert(LABEL_IMAGE_ID.to_string(), id.clone());
        }

        if let Some(ref region) = self.doc.region {
            labels.insert(LABEL_CLOUD_REGION.to_string(), region.clone());
        }

        if let Some(ref zone) = self.doc.availability_zone {
            labels.insert(LABEL_CLOUD_ZONE.to_string(), zone.clone());
        }

        if let Some(ref id) = self.doc.account_id {
            labels.insert(LABEL_CLOUD_ACCOUNT_ID.to_string(), id.clone());
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

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use assert2::assert;
    use hyper::service::{make_service_fn, service_fn};
    use hyper::{Body, Request, Response, Server, StatusCode};

    use super::*;

    const TEST_METADATA: &str = r#"
{
  "accountId" : "601263177651",
  "architecture" : "x86_64",
  "availabilityZone" : "us-east-1d",
  "billingProducts" : null,
  "devpayProductCodes" : null,
  "marketplaceProductCodes" : null,
  "imageId" : "ami-0557a15b87f6559cf",
  "instanceId" : "i-01d1e9aa7a573262f",
  "instanceType" : "t2.medium",
  "kernelId" : null,
  "pendingTime" : "2023-04-18T23:02:22Z",
  "privateIp" : "172.31.81.118",
  "ramdiskId" : null,
  "region" : "us-east-1",
  "version" : "2017-09-30"
}"#;

    async fn mock_metadata_svc(
        req: Request<Body>,
    ) -> std::result::Result<Response<Body>, hyper::Error> {
        let resp = match req.uri() {
            uri if uri == "/latest/api/token" => Response::builder()
                .status(StatusCode::OK)
                .header("x-aws-ec2-metadata-token-ttl-seconds", "21600")
                .body(Body::from(
                    "AQAAAID1mYTPepz28ILQ88CZW6r62fL9ur4jSIKniBoIm2YkofZ9Dw==",
                ))
                .unwrap(),
            _ => {
                assert!(req.uri() == "/2022-09-24/dynamic/instance-identity/document");

                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(TEST_METADATA))
                    .unwrap()
            }
        };

        Ok(resp)
    }

    #[tokio::test]
    async fn test_ec2() {
        use super::super::MetadataProvider;

        let addr = SocketAddr::V4("127.0.0.1:9991".parse().unwrap());

        let make_svc =
            make_service_fn(|_| async { Ok::<_, hyper::Error>(service_fn(mock_metadata_svc)) });
        let server = Server::bind(&addr).serve(make_svc);
        let server_task = tokio::task::spawn(server);

        std::env::set_var("AWS_EC2_METADATA_SERVICE_ENDPOINT", "http://localhost:9991");

        let metadata = Ec2Metadata::load().await.unwrap();
        let labels = metadata.host_labels();

        assert!(labels.get(LABEL_CLOUD_PROVIDER).unwrap() == "ec2");
        assert!(labels.get(LABEL_INSTANCE_ID).unwrap() == "i-01d1e9aa7a573262f");
        assert!(labels.get(LABEL_IMAGE_ID).unwrap() == "ami-0557a15b87f6559cf");
        assert!(labels.get(LABEL_CLOUD_REGION).unwrap() == "us-east-1");
        assert!(labels.get(LABEL_CLOUD_ZONE).unwrap() == "us-east-1d");
        assert!(labels.get(LABEL_CLOUD_ACCOUNT_ID).unwrap() == "601263177651");

        server_task.abort();
        _ = server_task.await;
    }
}
