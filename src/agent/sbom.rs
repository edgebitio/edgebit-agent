use std::process::{Command};
use std::path::{PathBuf};
use std::io::BufReader;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use log::*;
use serde::Deserialize;
use temp_file::TempFile;

use crate::config::Config;
use crate::scoped_path::*;

pub fn generate(config: Arc<Config>, root: &RootFsPath) -> Result<TempFile> {
    let syft = config.syft_path();
    let tmp = TempFile::new()?;
    let out_path = tmp.path();
    let syft_cfg = config.syft_config();

    let child = Command::new(syft)
        .arg("--file")
        .arg(out_path)
        .arg("--config")
        .arg(syft_cfg)
        .arg(root.as_raw().as_os_str())
        .spawn()?;

    let out = child.wait_with_output()?;

    if !out.status.success() {
        return Err(anyhow!("syft failed"));
    }

    info!("SBOM generated");
    Ok(tmp)
}

pub struct Sbom {
    doc: SbomDoc,
}

impl Sbom {
    pub fn load(path: &RootFsPath) -> Result<Self> {
        let file = std::fs::File::open(path.as_raw())?;
        let reader = BufReader::new(file);

        Ok(Self{
            doc: serde_json::from_reader(reader)?,
        })
    }

    pub fn artifacts(&self) -> &Vec<Artifact> {
        &self.doc.artifacts
    }

    pub fn id(&self) -> String {
        self.doc.source.id.clone()
    }
}

#[derive(Deserialize)]
struct SbomDoc {
    artifacts: Vec<Artifact>,
    source: Source,
}

#[derive(Deserialize)]
pub struct Artifact {
    pub id: String,

    #[serde(rename(deserialize = "type"))]
    type_: String,

    #[serde(rename(deserialize = "metadataType"))]
    metadata_type: Option<String>,

    metadata: Option<Metadata>,
}

impl Artifact {
    pub fn files(&self, host_root: &RootFsPath) -> Result<Vec<WorkloadPath>> {
        // This mapping might not be so one-to-one
        let (type_, expect_meta_type) = match self.type_.as_ref() {
            "deb" => (PackageType::Deb, "DpkgMetadata"),
            "rpm" => (PackageType::Rpm, "RpmMetadata"),
            "python" => (PackageType::Python, "PythonPackageMetadata"),
            _ => return Err(anyhow!("'{}' is an unsupported artifact type", self.type_)),
        };

        let paths = match (&self.metadata, &self.metadata_type) {
            (None, _) => Vec::new(),
            (Some(metadata), Some(metadata_type)) => {
                if metadata_type != expect_meta_type {
                    return Err(anyhow!("'metadataType' has unexpected value {metadata_type}, expected {expect_meta_type}"));
                }

                metadata.file_paths(type_, host_root)?
            },
            (Some(_), None) => return Err(anyhow!("'metadataType' is missing")),
        };

        Ok(paths)
    }
}

#[derive(Deserialize)]
struct Source {
    pub id: String,
}

#[derive(Deserialize)]
struct Metadata {
    files: Option<Vec<File>>,

    #[serde(rename(deserialize = "sitePackagesRootPath"))]
    site_packages_root_path: Option<String>,
}

impl Metadata {
    fn file_paths(&self, pkg_type: PackageType, host_root: &RootFsPath) -> Result<Vec<WorkloadPath>> {
        match self.files {
            Some(ref files) => {
                match pkg_type {
                    PackageType::Rpm | PackageType::Deb => generic_files(files, host_root),
                    PackageType::Python => python_files(files, self, host_root),
                }
            }
            None => Ok(Vec::new()),
        }
    }
}

#[derive(Deserialize)]
struct File {
    path: Option<String>,
}

pub enum PackageType {
    Rpm,
    Deb,
    Python,
}

fn generic_files(files: &[File], host_root: &RootFsPath) -> Result<Vec<WorkloadPath>> {
    let paths = files.iter()
        .filter_map(extract_path)
        .map(|path| normalize(host_root, &path))
        .collect();

    Ok(paths)
}

fn python_files(files: &[File], meta: &Metadata, host_root: &RootFsPath) -> Result<Vec<WorkloadPath>> {
    let site_root: WorkloadPath = meta.site_packages_root_path
        .as_ref()
        .ok_or(anyhow!("'sitePackagesRootPath' is missing"))?
        .into();

    let paths = files.iter()
        .filter_map(extract_path)
        .map(|path| site_root.join(path.as_raw()))
        .map(|path| normalize(host_root, &path))
        .collect();

    Ok(paths)
}

fn extract_path(f: &File) -> Option<WorkloadPath> {
    let path = PathBuf::from(f.path.as_ref()?);
    Some(WorkloadPath::new(&path))
}

fn normalize(host_root: &RootFsPath, path: &WorkloadPath) -> WorkloadPath {
    let host_path = path.to_rootfs(host_root);

    match host_path.realpath() {
        Ok(norm_path) => {
            WorkloadPath::from_rootfs(host_root, &norm_path)
                .unwrap_or_else(|_| path.clone())
        },
        Err(_) => path.clone(),
    }
}