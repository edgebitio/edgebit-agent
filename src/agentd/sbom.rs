use std::process::{Command, Stdio};
use std::path::Path;

use anyhow::{Result, anyhow};
use json::JsonValue;
use log::*;

pub fn generate() -> Result<json::object::Object> {
    let syft_path = std::env::var("SYFT_PATH")?;
    let output = Command::new(syft_path)
        .arg("/")
        .stdout(Stdio::piped())
        .spawn()?
        .wait_with_output()?;

    if !output.status.success() {
        return Err(anyhow!("syft failed"));
    }

    let json_buf = std::str::from_utf8(&output.stdout)?;

    info!("SBOM generated: {} bytes", json_buf.len());
    parse(json_buf)
}

pub fn load<P: AsRef<Path>>(path: P) -> Result<json::object::Object> {
    let path = path.as_ref();
    let bytes = std::fs::read_to_string(path)?;

    parse(&bytes)
}

fn parse(source: &str) -> Result<json::object::Object> {
    match json::parse(source)? {
        JsonValue::Object(obj) => Ok(obj),
        _ => Err(anyhow!("syft output returned a non object JSON"))
    }
}