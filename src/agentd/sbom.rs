use std::process::{Command, Stdio};

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

    match json::parse(json_buf)? {
        JsonValue::Object(obj) => Ok(obj),
        _ => Err(anyhow!("syft output returned a non object JSON"))
    }
}