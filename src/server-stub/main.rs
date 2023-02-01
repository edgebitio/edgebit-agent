use std::sync::Arc;

use anyhow::Result;
use tonic::{Request, Response, Status, Streaming};
use tonic::transport::Server;

pub mod pb {
    tonic::include_proto!("edgebit.v1alpha.enrollment");
    tonic::include_proto!("edgebit.v1alpha.inventory");
}

use pb::enrollment_service_server::{EnrollmentService, EnrollmentServiceServer};
use pb::inventory_service_server::{InventoryService, InventoryServiceServer};

#[derive(Debug, Default)]
pub struct Service {}

#[tonic::async_trait]
impl EnrollmentService for Service {
    async fn enroll_agent(
        &self,
        request: Request<pb::EnrollAgentRequest>,
    ) -> Result<Response<pb::EnrollAgentResponse>, Status> {

        println!("enroll_agent: {:?}", request);

        let reply = pb::EnrollAgentResponse{
            agent_token: "XYZTOKEN".to_string(),
        };
        Ok(Response::new(reply))
    }
}

#[tonic::async_trait]
impl InventoryService for Service {
    async fn upload_sbom(
        &self,
        request: Request<Streaming<pb::UploadSbomRequest>>,
    ) -> Result<Response<pb::Void>, Status> {
        let mut request = request.into_inner();
        let mut whole = Vec::new();

        loop {
            match request.message().await {
                Ok(Some(msg)) => {
                    if let Some(pb::upload_sbom_request::Kind::Data(mut part)) = msg.kind {
                        whole.append(&mut part);
                    }
                },
                Ok(None) => {
                    println!("upload_sbom: len={}", whole.len());
                    return Ok(Response::new(pb::Void{}));
                },
                Err(e) => { return Err(e); },
            }
        }
    }

    async fn report_in_use(
        &self,
        request: Request<pb::ReportInUseRequest>,
    ) -> Result<Response<pb::Void>, Status> {

        println!("report_in_use: {:?}", request);
        Ok(Response::new(pb::Void{}))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "0.0.0.0:7777".parse()?;
    let svc = Arc::new(Service::default());

    Server::builder()
        .add_service(EnrollmentServiceServer::from_arc(svc.clone()))
        .add_service(InventoryServiceServer::from_arc(svc.clone()))
        .serve(addr)
        .await?;

    Ok(())
}