use std::time::{SystemTime, Duration};
use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Result, anyhow};
use log::*;
use serde::Deserialize;
use tonic::transport::channel::Channel;
use tonic::Request;
use containerd_client::with_namespace;
use containerd_client::services::v1::{SubscribeRequest, ListTasksRequest, GetContainerRequest, Container, ListContainersRequest};
use containerd_client::types::v1::Status;
use containerd_client::services::v1::events_client::EventsClient;
use containerd_client::services::v1::containers_client::ContainersClient;
use containerd_client::services::v1::tasks_client::TasksClient;
use containerd_client::events::*;
use oci_spec::runtime::Spec;
use prost::DecodeError;
use prost_types::Any;

use super::{ContainerEventsPtr, ContainerInfo};
use crate::scoped_path::*;
use crate::label::*;

const NAMESPACE: &str = "k8s.io";
const OCI_SPEC_TYPE_NAME: &str = "types.containerd.io/opencontainers/runtime-spec/1/Spec";

const CONTAINER_LABEL_KIND: &str = "io.cri-containerd.kind";
const CONTAINER_LABEL_NAME: &str = "io.kubernetes.container.name";
const CONTAINER_LABEL_POD_NAME: &str = "io.kubernetes.pod.name";
const CONTAINER_LABEL_NAMESPACE: &str = "io.kubernetes.pod.namespace";

const CRI_CONTAINERD_CONTAINER_METADATA: &str = "io.cri-containerd.container.metadata";
const CRI_CONTAINERD_CONTAINER_METADATA_TYPE: &str = "github.com/containerd/cri/pkg/store/container/Metadata";

#[derive(Clone)]
pub struct K8sContainerdTracker {
    containers: ContainersClient<Channel>,
    tasks: TasksClient<Channel>,
    events: EventsClient<Channel>,
}

impl K8sContainerdTracker {
    pub async fn connect(host: &str) -> Self {
        let mut quiet = false;
        let ch = loop {
            match super::grpc_connect(host).await {
                Ok(ch) => {
                    info!("Connected to containerd daemon");
                    break ch;
                },
                Err(err) => {
                    if quiet {
                        debug!("Failed to connect to containerd daemon: {err}");
                    } else {
                        error!("Failed to connect to containerd daemon: {err}");
                        quiet = true;
                    }

                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        };

        Self{
            containers: ContainersClient::new(ch.clone()),
            tasks: TasksClient::new(ch.clone()),
            events: EventsClient::new(ch.clone()),
        }
    }

    pub async fn track(mut self, events: ContainerEventsPtr) -> Result<()> {
        let events_task = tokio::task::spawn(
            self.clone().stream_events(events.clone())
        );

        // Load already running containers
        self.load_running(events.clone()).await?;

        if let Err(err) = events_task.await.unwrap() {
            error!("Events streaming: {err}");
        }
        Ok(())
    }

    async fn stream_events(mut self, events: ContainerEventsPtr) -> Result<()> {
        let req = SubscribeRequest{
            filters: Vec::new(),
        };

        let req = with_namespace!(req, NAMESPACE);

        let mut stream = self.events.subscribe(req)
            .await?
            .into_inner();

        while let Some(msg) = stream.message().await? {
            if let Some(event) = msg.event {
                match ContainerdEvent::try_from(event) {
                    Ok(event) => self.process_event(event, events.clone()).await,
                    Err(err) => error!("Event decoding error: {err}"),
                }
            }
        }

        debug!("containerd event streaming done");
        Ok(())
    }

    async fn process_event(&mut self, event: ContainerdEvent, events: ContainerEventsPtr) {
        match event {
            ContainerdEvent::TaskCreate(msg) => {
                debug!("Container {} created", msg.container_id);
                match self.inspect_container(&msg.container_id).await {
                    Ok(Some(info)) => {
                        events.container_started(msg.container_id, info).await;
                    },
                    Ok(None) => (),
                    Err(err) => {
                        error!("Failed to inspect container(id={}): {err}", msg.container_id);
                        return;
                    }
                }
            },
            ContainerdEvent::TaskDelete(msg) => {
                let end_time = msg.exited_at
                    .and_then(|t| t.try_into().ok())
                    .unwrap_or(SystemTime::now());

                events.container_stopped(msg.container_id, end_time).await;
            },
            _ => (),
        }
    }

    async fn load_running(&mut self, events: ContainerEventsPtr) -> Result<()> {
        let mut containers = self.load_containers().await?;

        let req = ListTasksRequest {
            filter: String::new()
        };

        let req = with_namespace!(req, NAMESPACE);

        let resp = self.tasks.list(req)
            .await?
            .into_inner();

        for t in resp.tasks {
            if Status::from_i32(t.status) == Some(Status::Running) {
                if let Some(info) = containers.remove(&t.id) {
                    events.container_started(t.id, info).await;
                }
            }
        }

        Ok(())
    }

    async fn load_containers(&mut self) -> Result<HashMap<String, ContainerInfo>> {
        let req = ListContainersRequest{
            filters: Vec::new(),
        };

        let req = with_namespace!(req, NAMESPACE);

        let resp = self.containers.list(req)
            .await?
            .into_inner();

        let mut map = HashMap::new();

        for c in resp.containers {
            if !is_container(&c) {
                continue;
            }

            let (id, ci) = self.into_container_info(c).await;
            map.insert(id, ci);
        }

        Ok(map)
    }

    async fn inspect_container(&mut self, id: &str) -> Result<Option<ContainerInfo>> {
        let req = GetContainerRequest{
            id: id.to_string(),
        };

        let req = with_namespace!(req, NAMESPACE);

        let resp = self.containers.get(req)
            .await?
            .into_inner();

        if let Some(c) = resp.container {
            if !is_container(&c) {
                return Ok(None);
            }

            let (_, ci) = self.into_container_info(c).await;

            Ok(Some(ci))

        } else {
            Err(anyhow!("containers.get() missing 'container'"))
        }
    }

    async fn into_container_info(&mut self, mut c: Container) -> (String, ContainerInfo) {
        let image_id = if let Some(meta) = c.extensions.remove(CRI_CONTAINERD_CONTAINER_METADATA) {
            match into_cri_metadata(meta) {
                Ok(meta) => Some(meta.metadata.image_ref),
                Err(err) => {
                    error!("Failed to decode {CRI_CONTAINERD_CONTAINER_METADATA} extension: {err}");
                    None
                }
            }
        } else {
            error!("Container {}: {} extension missing", c.id, CRI_CONTAINERD_CONTAINER_METADATA);
            None
        };

        let name = c.labels.remove(CONTAINER_LABEL_NAME);
        let pod = c.labels.remove(CONTAINER_LABEL_POD_NAME);
        let ns = c.labels.remove(CONTAINER_LABEL_NAMESPACE);

        let mut labels = HashMap::new();

        if let Some(pod) = pod {
            labels.insert(LABEL_KUBE_POD_NAME.to_string(), pod);
        }

        if let Some(ns) = ns {
            labels.insert(LABEL_KUBE_NAMESPACE.to_string(), ns);
        }

        let mounts: Vec<PathBuf> = if let Some(spec) = c.spec {
            if let Some(oci_spec) = into_oci_spec(spec) {
                if let Some(mounts) = oci_spec.mounts() {
                    mounts.iter()
                        .map(|m| m.destination().clone())
                        .collect()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        debug!("Container (id={}) mounts: {mounts:?}", c.id);

        let ci = ContainerInfo{
            name,
            image_id,
            image: Some(c.image),
            rootfs: Some(get_rootfs(&c.id)),
            start_time: c.created_at.and_then(|t| t.try_into().ok()),
            end_time: None,
            mounts,
            labels,
        };

        (c.id, ci)
    }
}

fn get_rootfs(id: &str) -> HostPath {
    // TODO: This is far from ideal and we need to look into how to get this info from the API.
    format!("/run/containerd/io.containerd.runtime.v2.task/k8s.io/{id}/rootfs/").into()
}

// containerd events
#[derive(Debug)]
enum ContainerdEvent {
    Unknown,
    ContainerCreate(ContainerCreate),
    ContainerDelete(ContainerDelete),
    ContainerUpdate(ContainerUpdate),
    ContentDelete(ContentDelete),
    NamespaceCreate(NamespaceCreate),
    NamespaceDelete(NamespaceDelete),
    NamespaceUpdate(NamespaceUpdate),
    SnapshotCommit(SnapshotCommit),
    SnapshotPrepare(SnapshotPrepare),
    SnapshotRemove(SnapshotRemove),
    TaskCheckpointed(TaskCheckpointed),
    TaskCreate(TaskCreate),
    TaskDelete(TaskDelete),
    TaskExecAdded(TaskExecAdded),
    TaskExecStarted(TaskExecStarted),
    TaskExit(TaskExit),
    TaskIo(TaskIo),
    TaskOom(TaskOom),
    TaskPaused(TaskPaused),
    TaskResumed(TaskResumed),
    TaskStart(TaskStart),
}

impl TryFrom<Any> for ContainerdEvent {
    type Error = DecodeError;

    fn try_from(v: Any) -> std::result::Result<Self, DecodeError> {
        use prost::Message;

        let ev = match v.type_url.as_ref() {
            "containerd.events.ContainerCreate" => ContainerdEvent::ContainerCreate(ContainerCreate::decode(v.value.as_ref())?),
            "containerd.events.ContainerDelete" => ContainerdEvent::ContainerDelete(ContainerDelete::decode(v.value.as_ref())?),
            "containerd.events.ContainerUpdate" => ContainerdEvent::ContainerUpdate(ContainerUpdate::decode(v.value.as_ref())?),
            "containerd.events.ContentDelete" => ContainerdEvent::ContentDelete(ContentDelete::decode(v.value.as_ref())?),
            "containerd.events.NamespaceCreate" => ContainerdEvent::NamespaceCreate(NamespaceCreate::decode(v.value.as_ref())?),
            "containerd.events.NamespaceDelete" => ContainerdEvent::NamespaceDelete(NamespaceDelete::decode(v.value.as_ref())?),
            "containerd.events.NamespaceUpdate" => ContainerdEvent::NamespaceUpdate(NamespaceUpdate::decode(v.value.as_ref())?),
            "containerd.events.SnapshotCommit" => ContainerdEvent::SnapshotCommit(SnapshotCommit::decode(v.value.as_ref())?),
            "containerd.events.SnapshotPrepare" => ContainerdEvent::SnapshotPrepare(SnapshotPrepare::decode(v.value.as_ref())?),
            "containerd.events.SnapshotRemove" => ContainerdEvent::SnapshotRemove(SnapshotRemove::decode(v.value.as_ref())?),
            "containerd.events.TaskCheckpointed" => ContainerdEvent::TaskCheckpointed(TaskCheckpointed::decode(v.value.as_ref())?),
            "containerd.events.TaskCreate" => ContainerdEvent::TaskCreate(TaskCreate::decode(v.value.as_ref())?),
            "containerd.events.TaskDelete" => ContainerdEvent::TaskDelete(TaskDelete::decode(v.value.as_ref())?),
            "containerd.events.TaskExecAdded" => ContainerdEvent::TaskExecAdded(TaskExecAdded::decode(v.value.as_ref())?),
            "containerd.events.TaskExecStarted" => ContainerdEvent::TaskExecStarted(TaskExecStarted::decode(v.value.as_ref())?),
            "containerd.events.TaskExit" => ContainerdEvent::TaskExit(TaskExit::decode(v.value.as_ref())?),
            "containerd.events.TaskIo" => ContainerdEvent::TaskIo(TaskIo::decode(v.value.as_ref())?),
            "containerd.events.TaskOom" => ContainerdEvent::TaskOom(TaskOom::decode(v.value.as_ref())?),
            "containerd.events.TaskPaused" => ContainerdEvent::TaskPaused(TaskPaused::decode(v.value.as_ref())?),
            "containerd.events.TaskResumed" => ContainerdEvent::TaskResumed(TaskResumed::decode(v.value.as_ref())?),
            "containerd.events.TaskStart" => ContainerdEvent::TaskStart(TaskStart::decode(v.value.as_ref())?),
            _ => ContainerdEvent::Unknown,
        };

        Ok(ev)
    }
}

fn is_container(c: &Container) -> bool {
    match c.labels.get(CONTAINER_LABEL_KIND) {
        Some(kind) => kind == "container",
        None => false,
    }
}

fn into_oci_spec(spec: Any) -> Option<Spec> {
    if &spec.type_url == OCI_SPEC_TYPE_NAME {
        let oci_spec: Spec = serde_json::from_slice(&spec.value).ok()?;
        if oci_spec.version().starts_with("1.") {
            return Some(oci_spec);
        }
    }

    None
}

#[derive(Deserialize)]
struct CriMetadata {
    #[serde(rename = "Version")]
    version: String,

    #[serde(rename = "Metadata")]
    metadata: Metadata,
}

#[derive(Deserialize)]
struct Metadata {
    #[serde(rename = "ImageRef")]
    image_ref: String,
}

fn into_cri_metadata(any: Any) -> Result<CriMetadata> {
    if any.type_url != CRI_CONTAINERD_CONTAINER_METADATA_TYPE {
        return Err(anyhow!("unexpected CRI metadata extension type: {} instead of {CRI_CONTAINERD_CONTAINER_METADATA_TYPE}", any.type_url));
    }

    let meta: CriMetadata = serde_json::from_slice(&any.value)?;

    if meta.version != "v1" {
        return Err(anyhow!("unexpected CRI metadata version: {}", meta.version));
    }

    Ok(meta)
}
