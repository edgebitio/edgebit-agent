use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use log::*;
use nix::sys::wait::WaitStatus;
use serde::Deserialize;
use temp_file::TempFile;

use crate::chroot_cmd::{CommandWithChroot, TmpFS};
use crate::config::Config;
use crate::scoped_path::*;

pub async fn generate(config: Arc<Config>, root: &RootFsPath) -> Result<TempFile> {
    // If the agent is running in a container, the host FS is mounted at
    // at /host or similar. Since some symlinks are absolute, e.g. /usr/bin => /bin,
    // running Syft on /host will not work: /host/usr/bin will resolve to /bin
    // instead of /host/bin.
    // To combat this, we need to chroot into /host and then execute Syft.
    // This is problematic for two reasons:
    // 1. Syft binary is inside the container, not on the host.
    //    We solve this by first opening the binary file, and using execveat
    //    to execute using a FD.
    // 2. We need to provide a config file to Syft which resides inside the container.
    //    FD trick won't work since it needs to be a filename to pass on cmdline.
    //    This is solved by mounting tmpfs at /host/tmp (hoping that /host/tmp exists),
    //    copying the file there and then passing --config /tmp/syft.yaml on cmdline.

    let sbom = if root.as_raw() == Path::new("/") {
        generate_no_chroot(&config.syft_path(), &config.syft_config()).await?
    } else {
        generate_with_chroot(config.syft_path(), &config.syft_config(), root.as_raw()).await?
    };

    info!("SBOM generated");
    Ok(sbom)
}

async fn generate_no_chroot(syft_path: &Path, syft_config: &Path) -> Result<TempFile> {
    let sbom = TempFile::new()?;
    let out_path = sbom.path();

    let child = Command::new(syft_path)
        .arg("-q")
        .arg("--file")
        .arg(out_path)
        .arg("--config")
        .arg(syft_config)
        .arg("/")
        .spawn()?;

    let out = tokio::task::spawn_blocking(move || child.wait_with_output()).await??;

    if !out.status.success() {
        return Err(anyhow!("syft failed"));
    }

    Ok(sbom)
}

async fn generate_with_chroot(
    syft_path: PathBuf,
    syft_config: &Path,
    root: &Path,
) -> Result<TempFile> {
    let sbom = TempFile::new()?;
    let sbom_file = std::fs::File::options().write(true).open(sbom.path())?;

    let tmp = TmpFS::mount(root.join("tmp"))?;
    let syft_config_path = tmp.mountpoint().join("syft.yaml");

    std::fs::copy(syft_config, &syft_config_path)?;

    let mut cmd = CommandWithChroot::new(syft_path);
    cmd.chroot(root.to_path_buf())
        .stdin(std::fs::File::open(syft_config)?)
        .stdout(sbom_file)
        .arg("syft".into())
        .arg("-q".into())
        .arg("--config".into())
        .arg("/tmp/syft.yaml".into())
        .arg("/".into());

    match cmd.run().await? {
        WaitStatus::Exited(_, 0) => (),
        _ => return Err(anyhow!("syft failed")),
    };

    Ok(sbom)
}

pub struct Sbom {
    doc: SbomDoc,
}

impl Sbom {
    pub fn load(path: &RootFsPath) -> Result<Self> {
        let file = std::fs::File::open(path.as_raw())?;
        let reader = BufReader::new(file);

        Ok(Self {
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
            }
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
    fn file_paths(
        &self,
        pkg_type: PackageType,
        host_root: &RootFsPath,
    ) -> Result<Vec<WorkloadPath>> {
        match self.files {
            Some(ref files) => match pkg_type {
                PackageType::Rpm | PackageType::Deb => generic_files(files, host_root),
                PackageType::Python => python_files(files, self, host_root),
            },
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
    let paths = files
        .iter()
        .filter_map(extract_path)
        .map(|path| normalize(host_root, &path))
        .collect();

    Ok(paths)
}

fn python_files(
    files: &[File],
    meta: &Metadata,
    host_root: &RootFsPath,
) -> Result<Vec<WorkloadPath>> {
    let site_root: WorkloadPath = meta
        .site_packages_root_path
        .as_ref()
        .ok_or(anyhow!("'sitePackagesRootPath' is missing"))?
        .into();

    let paths = files
        .iter()
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
            WorkloadPath::from_rootfs(host_root, &norm_path).unwrap_or_else(|_| path.clone())
        }
        Err(_) => path.clone(),
    }
}
