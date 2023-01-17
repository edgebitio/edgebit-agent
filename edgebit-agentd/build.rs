fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("../edgebitapis/edgebit/v1alpha/enrollment_service.proto")?;
    tonic_build::compile_protos("../edgebitapis/edgebit/v1alpha/inventory_service.proto")?;
    Ok(())
}