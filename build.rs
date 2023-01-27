use libbpf_cargo::SkeletonBuilder;
use std::{env, path::PathBuf};

const SRC: &str = "src/bpf/probes.bpf.c";

fn build_protos() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("edgebitapis/edgebit/v1alpha/enrollment_service.proto")?;
    tonic_build::compile_protos("edgebitapis/edgebit/v1alpha/inventory_service.proto")?;
    Ok(())
}

fn build_bpf() -> Result<(), Box<dyn std::error::Error>> {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("probes.skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .clang("clang-10")
        .clang_args("-D__TARGET_ARCH_x86")
        .build_and_generate(&out)?;
    println!("cargo:rerun-if-changed={}", SRC);
    Ok(())
}

fn build() -> Result<(), Box<dyn std::error::Error>> {
    build_bpf()?;
    build_protos()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = build() {
        eprintln!("{}", e.to_string());
        return Err(e);
    }
    Ok(())
}
