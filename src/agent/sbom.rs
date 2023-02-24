use std::process::{Command};
use std::path::{Path, PathBuf};
use std::io::BufReader;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use log::*;
use serde::Deserialize;
use temp_file::TempFile;

use crate::config::Config;

pub fn generate(config: Arc<Config>) -> Result<TempFile> {
    let syft = syft_path()?;
    let tmp = TempFile::new()?;
    let out_path = tmp.path();
    let syft_cfg = config.syft_config();

    let child = Command::new(syft)
        .arg("--file")
        .arg(out_path)
        .arg("--config")
        .arg(syft_cfg)
        .arg("/")
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
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = std::fs::File::open(path.as_ref())?;
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
    pub fn files(&self) -> Result<Vec<String>> {
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

                metadata.file_paths(type_)?
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
    fn file_paths(&self, pkg_type: PackageType) -> Result<Vec<String>> {
        match self.files {
            Some(ref files) => {
                match pkg_type {
                    PackageType::Rpm | PackageType::Deb => generic_files(files),
                    PackageType::Python => python_files(files, self),
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

fn generic_files(files_arr: &[File]) -> Result<Vec<String>> {
    let paths = files_arr.iter()
        .filter_map(extract_path)
        .map(normalize)
        .collect();

    Ok(paths)
}

fn python_files(files_arr: &[File], meta: &Metadata) -> Result<Vec<String>> {
    let root_path = meta.site_packages_root_path.as_ref()
        .ok_or(anyhow!("'sitePackagesRootPath' is missing"))?;

    let root_path = PathBuf::from(root_path);

    let paths = files_arr.iter()
        .filter_map(extract_path)
        .map(|path| root_path.join(path))
        .map(normalize)
        .collect();

    Ok(paths)
}

fn extract_path(f: &File) -> Option<PathBuf> {
    Some(f.path.as_ref()?.into())
}

fn normalize(path: PathBuf) -> String {
    let path = match std::fs::canonicalize(&path) {
        Ok(path) => path,
        Err(_) => path,
    };

    path.to_string_lossy()
        .into_owned()
}

fn syft_path() -> Result<PathBuf> {
    if let Ok(syft) = std::env::var("SYFT_PATH") {
        return Ok(PathBuf::from(syft));
    }

    let arg0: PathBuf = std::env::args()
        .next()
        .expect("program started without argv[0]")
        .into();

    let my_dir = arg0.parent()
        .expect("argv[0] is empty");

    let syft = my_dir.join("syft");

    if syft.is_file() || syft.is_symlink() {
        Ok(syft)
    } else {
        Err(anyhow!("'syft' not found. Set SYFT_PATH env var with /path/to/syft"))
    }
}