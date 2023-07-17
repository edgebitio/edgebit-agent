use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

pub mod pb {
    tonic::include_proto!("edgebit.agent.v1alpha");
    pub use ::prost_types::Timestamp;
}

use pb::inventory_service_server::{InventoryService, InventoryServiceServer};
use pb::token_service_server::{TokenService, TokenServiceServer};

#[derive(Debug, Default)]
pub struct Service {}

#[tonic::async_trait]
impl TokenService for Service {
    async fn enroll_agent(
        &self,
        request: Request<pb::EnrollAgentRequest>,
    ) -> Result<Response<pb::EnrollAgentResponse>, Status> {
        println!("enroll_agent: {:?}", request.into_inner());

        let expiration = SystemTime::now() + Duration::from_secs(180);

        let reply = pb::EnrollAgentResponse {
            refresh_token: "REFRESH_TOKEN".to_string(),
            session_token: "SESSION_TOKEN".to_string(),
            session_token_expiration: Some(expiration.into()),
        };
        Ok(Response::new(reply))
    }

    async fn enroll_cluster_agent(
        &self,
        request: Request<pb::EnrollClusterAgentRequest>,
    ) -> Result<Response<pb::EnrollClusterAgentResponse>, Status> {
        println!("enroll_cluster_agent: {:?}", request.into_inner());

        let expiration = SystemTime::now() + Duration::from_secs(180);

        let reply = pb::EnrollClusterAgentResponse {
            session_token: "SESSION_TOKEN".to_string(),
            session_token_expiration: Some(expiration.into()),
        };
        Ok(Response::new(reply))
    }

    async fn get_session_token(
        &self,
        request: Request<pb::GetSessionTokenRequest>,
    ) -> Result<Response<pb::GetSessionTokenResponse>, Status> {
        println!("get_session_token: {:?}", request.into_inner());

        let expiration = SystemTime::now() + Duration::from_secs(180);

        let reply = pb::GetSessionTokenResponse {
            session_token: "SESSION_TOKEN".to_string(),
            session_token_expiration: Some(expiration.into()),
        };
        Ok(Response::new(reply))
    }
}

#[tonic::async_trait]
impl InventoryService for Service {
    async fn upload_sbom(
        &self,
        request: Request<Streaming<pb::UploadSbomRequest>>,
    ) -> Result<Response<pb::UploadSbomResponse>, Status> {
        let mut request = request.into_inner();
        let mut whole = Vec::new();

        loop {
            match request.message().await {
                Ok(Some(msg)) => match msg.kind {
                    Some(pb::upload_sbom_request::Kind::Header(hdr)) => {
                        println!("upload_sbom: {hdr:?}");
                    }

                    Some(pb::upload_sbom_request::Kind::Data(mut part)) => {
                        whole.append(&mut part);
                    }

                    _ => (),
                },

                Ok(None) => {
                    println!("upload_sbom: len={}", whole.len());
                    return Ok(Response::new(pb::UploadSbomResponse {}));
                }

                Err(e) => {
                    return Err(e);
                }
            }
        }
    }

    async fn reset_workloads(
        &self,
        request: Request<pb::ResetWorkloadsRequest>,
    ) -> Result<Response<pb::ResetWorkloadsResponse>, Status> {
        println!("reset_workloads: {:?}", request.into_inner());
        Ok(Response::new(pb::ResetWorkloadsResponse {}))
    }

    async fn upsert_workload(
        &self,
        request: Request<pb::UpsertWorkloadRequest>,
    ) -> Result<Response<pb::UpsertWorkloadResponse>, Status> {
        println!("upsert_workload: {:?}", request.into_inner());
        Ok(Response::new(pb::UpsertWorkloadResponse {}))
    }

    async fn upsert_workloads(
        &self,
        request: Request<pb::UpsertWorkloadsRequest>,
    ) -> Result<Response<pb::UpsertWorkloadsResponse>, Status> {
        println!("upsert_workloads: {:?}", request.into_inner());
        Ok(Response::new(pb::UpsertWorkloadsResponse {}))
    }

    async fn upsert_machines(
        &self,
        request: Request<pb::UpsertMachinesRequest>,
    ) -> Result<Response<pb::UpsertMachinesResponse>, Status> {
        println!("upsert_machines: {:?}", request.into_inner());
        Ok(Response::new(pb::UpsertMachinesResponse {}))
    }

    async fn upsert_clusters(
        &self,
        request: Request<pb::UpsertClustersRequest>,
    ) -> Result<Response<pb::UpsertClustersResponse>, Status> {
        println!("upsert_clusters: {:?}", request.into_inner());
        Ok(Response::new(pb::UpsertClustersResponse {}))
    }

    async fn report_in_use(
        &self,
        request: Request<pb::ReportInUseRequest>,
    ) -> Result<Response<pb::ReportInUseResponse>, Status> {
        println!("report_in_use: {:?}", request.into_inner());
        Ok(Response::new(pb::ReportInUseResponse {}))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "0.0.0.0:7777".parse()?;
    let svc = Arc::new(Service::default());

    Server::builder()
        .add_service(TokenServiceServer::from_arc(svc.clone()))
        .add_service(InventoryServiceServer::from_arc(svc.clone()))
        .serve(addr)
        .await?;

    Ok(())
}
