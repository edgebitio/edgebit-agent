use std::collections::HashMap;

use anyhow::{bail, Result};
use hyper::{Body, Client, Method, Request, StatusCode};
use log::*;
use serde::Deserialize;

use crate::label::*;

const METADATA_SERVICE_HOST: &str = "169.254.169.254";

#[derive(Deserialize)]
struct InstanceIdentityDocument {
    #[serde(rename = "name")]
    name: Option<String>,

    #[serde(rename = "location")]
    location: Option<String>,

    #[serde(rename = "vmId")]
    vm_id: Option<String>,

    #[serde(rename = "zone")]
    zone: Option<String>,

    #[serde(rename = "subscriptionId")]
    subscription_id: Option<String>,
}

impl InstanceIdentityDocument {
    async fn load(url: &str) -> Result<Self> {
        let client = Client::new();
        let req = Request::builder()
            .method(Method::GET)
            .header("Metadata", "true")
            .uri(url)
            .body(Body::empty())?;

        let resp = client.request(req).await?;
        match resp.status() {
            StatusCode::OK => {
                let bytes = hyper::body::to_bytes(resp.into_body()).await?;
                info!("Loaded metadata: {}", String::from_utf8_lossy(&bytes));

                let doc: Self = serde_json::from_slice(&bytes)?;
                Ok(doc)
            }
            code => bail!("Non-200 response: {code}"),
        }
    }
}

pub struct AzureMetadata {
    doc: InstanceIdentityDocument,
}

impl AzureMetadata {
    pub async fn load_from_host(host: &str) -> Result<Self> {
        let url = format!("http://{host}/metadata/instance/compute?api-version=2021-12-13");
        let doc = InstanceIdentityDocument::load(&url).await?;

        Ok(AzureMetadata { doc })
    }

    pub async fn load() -> Result<Self> {
        Self::load_from_host(METADATA_SERVICE_HOST).await
    }
}

impl super::MetadataProvider for AzureMetadata {
    fn host_labels(&self) -> HashMap<String, String> {
        let mut labels: HashMap<String, String> =
            [(LABEL_CLOUD_PROVIDER.to_string(), "azure".to_string())].into();

        if let Some(ref id) = self.doc.vm_id {
            labels.insert(LABEL_INSTANCE_ID.to_string(), id.clone());
        }

        if let Some(ref name) = self.doc.name {
            labels.insert(LABEL_INSTANCE_TAG.to_string(), name.clone());
        }

        if let Some(ref location) = self.doc.location {
            labels.insert(LABEL_CLOUD_REGION.to_string(), location.clone());
        }

        if let Some(ref zone) = self.doc.zone {
            labels.insert(LABEL_CLOUD_ZONE.to_string(), zone.clone());
        }

        if let Some(ref id) = self.doc.subscription_id {
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
    use hyper::{Response, Server};

    use super::*;

    const TEST_METADATA: &str = r#"
{
    "azEnvironment": "AZUREPUBLICCLOUD",
    "extendedLocation": {
      "type": "edgeZone",
      "name": "microsoftlosangeles"
    },
    "evictionPolicy": "",
    "additionalCapabilities": {
        "hibernationEnabled": "false"
    },
    "hostGroup": {
      "id": "testHostGroupId"
    },
    "isHostCompatibilityLayerVm": "true",
    "licenseType":  "Windows_Client",
    "location": "westus",
    "name": "myvmname",
    "offer": "UbuntuServer",
    "osProfile": {
        "adminUsername": "admin",
        "computerName": "examplevmname",
        "disablePasswordAuthentication": "true"
    },
    "osType": "Linux",
    "placementGroupId": "f67c14ab-e92c-408c-ae2d-da15866ec79a",
    "plan": {
        "name": "planName",
        "product": "planProduct",
        "publisher": "planPublisher"
    },
    "platformFaultDomain": "36",
    "platformUpdateDomain": "42",
    "Priority": "Regular",
    "publicKeys": [{
            "keyData": "ssh-rsa 0",
            "path": "/home/user/.ssh/authorized_keys0"
        },
        {
            "keyData": "ssh-rsa 1",
            "path": "/home/user/.ssh/authorized_keys1"
        }
    ],
    "publisher": "Canonical",
    "resourceGroupName": "macikgo-test-may-23",
    "resourceId": "/subscriptions/xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx/resourceGroups/macikgo-test-may-23/providers/Microsoft.Compute/virtualMachines/examplevmname",
    "securityProfile": {
        "secureBootEnabled": "true",
        "virtualTpmEnabled": "false",
        "encryptionAtHost": "true",
        "securityType": "TrustedLaunch"
    },
    "sku": "18.04-LTS",
    "storageProfile": {
        "dataDisks": [{
            "bytesPerSecondThrottle": "979202048",
            "caching": "None",
            "createOption": "Empty",
            "diskCapacityBytes": "274877906944",
            "diskSizeGB": "1024",
            "image": {
              "uri": ""
            },
            "isSharedDisk": "false",
            "isUltraDisk": "true",
            "lun": "0",
            "managedDisk": {
              "id": "/subscriptions/xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx/resourceGroups/macikgo-test-may-23/providers/Microsoft.Compute/disks/exampledatadiskname",
              "storageAccountType": "StandardSSD_LRS"
            },
            "name": "exampledatadiskname",
            "opsPerSecondThrottle": "65280",
            "vhd": {
              "uri": ""
            },
            "writeAcceleratorEnabled": "false"
        }],
        "imageReference": {
            "id": "ubuntu-server-1604",
            "offer": "UbuntuServer",
            "publisher": "Canonical",
            "sku": "16.04.0-LTS",
            "version": "latest",
            "communityGalleryImageId": "/CommunityGalleries/testgallery/Images/1804Gen2/Versions/latest",
            "sharedGalleryImageId": "/SharedGalleries/1P/Images/gen2/Versions/latest",
            "exactVersion": "1.1686127202.30113"
        },
        "osDisk": {
            "caching": "ReadWrite",
            "createOption": "FromImage",
            "diskSizeGB": "30",
            "diffDiskSettings": {
                "option": "Local"
            },
            "encryptionSettings": {
              "enabled": "false",
              "diskEncryptionKey": {
                "sourceVault": {
                  "id": "/subscriptions/test-source-guid/resourceGroups/testrg/providers/Microsoft.KeyVault/vaults/test-kv"
                },
                "secretUrl": "https://test-disk.vault.azure.net/secrets/xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx/xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx"
              },
              "keyEncryptionKey": {
                "sourceVault": {
                  "id": "/subscriptions/test-key-guid/resourceGroups/testrg/providers/Microsoft.KeyVault/vaults/test-kv"
                },
                "keyUrl": "https://test-key.vault.azure.net/secrets/xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx/xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx"
              }
            },
            "image": {
                "uri": ""
            },
            "managedDisk": {
                "id": "/subscriptions/xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx/resourceGroups/macikgo-test-may-23/providers/Microsoft.Compute/disks/exampleosdiskname",
                "storageAccountType": "StandardSSD_LRS"
            },
            "name": "exampleosdiskname",
            "osType": "linux",
            "vhd": {
                "uri": ""
            },
            "writeAcceleratorEnabled": "false"
        },
        "resourceDisk": {
            "size": "4096"
        }
    },
    "subscriptionId": "4fbe21fe-ed44-11ee-9f01-1b59acba6c46",
    "tags": "baz:bash;foo:bar",
    "version": "15.05.22",
    "virtualMachineScaleSet": {
      "id": "/subscriptions/xxxxxxxx-xxxxx-xxx-xxx-xxxx/resourceGroups/resource-group-name/providers/Microsoft.Compute/virtualMachineScaleSets/virtual-machine-scale-set-name"
    },
    "vmId": "02aab8a4-74ef-476e-8182-f6d2ba4166a6",
    "vmScaleSetName": "crpteste9vflji9",
    "vmSize": "Standard_A3",
    "zone": "westus-1"
}"#;

    async fn mock_metadata_svc(
        req: Request<Body>,
    ) -> std::result::Result<Response<Body>, hyper::Error> {
        let metadata_hdr = req.headers().get("Metadata").unwrap().to_str().unwrap();
        assert!(metadata_hdr == "true");

        assert!(req.uri() == "/metadata/instance/compute?api-version=2021-12-13");

        let resp_body = Body::from(TEST_METADATA);

        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(resp_body)
            .unwrap())
    }

    #[tokio::test]
    async fn test_azure() {
        use super::super::MetadataProvider;

        let addr = SocketAddr::V4("127.0.0.1:9993".parse().unwrap());

        let make_svc =
            make_service_fn(|_| async { Ok::<_, hyper::Error>(service_fn(mock_metadata_svc)) });
        let server = Server::bind(&addr).serve(make_svc);
        let server_task = tokio::task::spawn(server);

        let metadata = AzureMetadata::load_from_host("localhost:9993")
            .await
            .unwrap();
        let labels = metadata.host_labels();

        assert!(labels.get(LABEL_CLOUD_PROVIDER).unwrap() == "azure");
        assert!(labels.get(LABEL_INSTANCE_ID).unwrap() == "02aab8a4-74ef-476e-8182-f6d2ba4166a6");
        assert!(labels.get(LABEL_INSTANCE_TAG).unwrap() == "myvmname");
        assert!(labels.get(LABEL_CLOUD_REGION).unwrap() == "westus");
        assert!(labels.get(LABEL_CLOUD_ZONE).unwrap() == "westus-1");
        assert!(
            labels.get(LABEL_CLOUD_ACCOUNT_ID).unwrap() == "4fbe21fe-ed44-11ee-9f01-1b59acba6c46"
        );

        server_task.abort();
        _ = server_task.await;
    }
}
