use std::process::Command;
use std::collections::HashMap;

use log::*;
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct RpmPackage {
    pub id: String,
    pub name: String,
    pub version: String,
    pub release: String,
    pub epoch: String,
    pub os: String,
    pub arch: String,
    pub summary: String,
    pub files: Vec<String>,
}

pub fn query_all() -> Result<Vec<RpmPackage>> {
    let mut installed = query_installed_rpms()?;
    let all_files = query_rpm_provided_files()?;

    for (pkg, path) in all_files {
        if let Some(rpm) = installed.get_mut(&pkg) {
            rpm.files.push(path);
        }
    }

    let installed = installed
        .into_values()
        .collect();

    Ok(installed)
}


fn query_installed_rpms() -> Result<HashMap<String, RpmPackage>> {
    let output = Command::new("rpm")
        .arg("-qa")
        .arg("--queryformat=%{NEVRA} %{NAME} %{VERSION} %{RELEASE} %{EPOCH} %{OS} %{ARCH} %{SUMMARY}\\n")
        .output()?;

    if !output.status.success() {
        let err_msg = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("{err_msg}"));
    }

    let pkgs = std::str::from_utf8(&output.stdout)?
        .lines()
        .map(parse_rpm_info)
        .filter_map(|v| v.map(|p| (p.name.clone(), p)))
        .collect();

    Ok(pkgs)
}

fn parse_rpm_info(line: &str) -> Option<RpmPackage> {
    let fields: Vec<&str> = line.splitn(7, ' ').collect();
    if fields.len() != 7 {
        warn!("rpm returned trancated line: {line}");
        return None;
    }

    Some(RpmPackage{
        id: fields[0].to_string(),
        name: fields[1].to_string(),
        version: fields[2].to_string(),
        release: fields[3].to_string(),
        epoch: fields[4].to_string(),
        os: fields[5].to_string(),
        arch: fields[6].to_string(),
        summary: fields[7].to_string(),
        files: Vec::new(),
    })
}

fn query_rpm_provided_files() -> Result<Vec<(String, String)>> {
    let output = Command::new("rpm")
        .arg("-qa")
        .arg("--filesbypkg")
        .output()?;

    if !output.status.success() {
        let err_msg = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("{err_msg}"));
    }

    let files = std::str::from_utf8(&output.stdout)?
        .lines()
        .map(parse_rpm_file)
        .filter_map(|v| v)
        .collect();

    Ok(files)
}

fn parse_rpm_file(line: &str) -> Option<(String, String)> {
    let fields: Vec<&str> = line
        .splitn(2, &[' ', '\t'])
        .collect();

    if fields.len() != 2 {
        warn!("rpm returned trancated line: {line}");
        return None;
    }

    let name = fields[0].to_string();
    let file = fields[1].trim().to_string();

    Some((name, file))
}