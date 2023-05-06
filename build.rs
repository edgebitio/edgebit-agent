use libbpf_cargo::SkeletonBuilder;
use std::{env, path::PathBuf};

const PROBES_SRC: &str = "src/bpf/probes.bpf.c";

const PROTOS: &[&str] = &[
    "edgebitapis/edgebit/agent/v1alpha/token_service.proto",
    "edgebitapis/edgebit/agent/v1alpha/inventory_service.proto",
];

fn build_protos() -> Result<(), Box<dyn std::error::Error>> {
    let includes: &[&str] = &[];

    tonic_build::configure()
        .compile(PROTOS, includes)?;

    for proto in PROTOS {
        println!("cargo:rerun-if-changed={proto}");
    }

    Ok(())
}

fn build_bpf() -> Result<(), Box<dyn std::error::Error>> {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("probes.skel.rs");
    SkeletonBuilder::new()
        .source(PROBES_SRC)
        .clang("clang")
        .build_and_generate(&out)?;
    println!("cargo:rerun-if-changed={PROBES_SRC}");
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
