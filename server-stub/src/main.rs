use std::sync::Arc;

use anyhow::Result;
use tonic::{Request, Response, Status};
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
    async fn report_rpm(
        &self,
        request: Request<pb::ReportRpmRequest>,
    ) -> Result<Response<pb::Void>, Status> {

        println!("report_rpm: {:?}", request);
        Ok(Response::new(pb::Void{}))
    }

    async fn report_deb(
        &self,
        request: Request<pb::ReportDebRequest>,
    ) -> Result<Response<pb::Void>, Status> {

        println!("report_deb: {:?}", request);
        Ok(Response::new(pb::Void{}))
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