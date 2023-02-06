use std::process::{Command, Stdio};
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use json::JsonValue;
use log::*;
pub struct Sbom {
    doc: json::object::Object,
}

impl Sbom {
    pub fn generate() -> Result<Self> {
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
        Ok(Sbom{
            doc: parse(json_buf)?,
        })
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read_to_string(path)?;

        Ok(Sbom{
            doc: parse(&bytes)?,
        })
    }

    pub fn packages<'a>(&'a self) -> Result<impl Iterator<Item=Package<'a>>> {
        let artifacts = self.doc.get("artifacts")
            .ok_or(anyhow!("'artifacts' missing"))?;

        let artifacts = as_array(artifacts)
            .ok_or(anyhow!("'artifacts' is not an array"))?;

        let iter = artifacts.iter()
            .filter_map(|a| {
                match parse_artifact(a) {
                    Ok(pkg) => { pkg.trace(); Some(pkg) },
                    Err(e) => { warn!("{e}"); None },
                }
            });

        Ok(iter)
    }

    pub fn into_bytes(self) -> Vec<u8> {
        json::stringify(JsonValue::Object(self.doc)).into_bytes()
    }
}

fn parse(source: &str) -> Result<json::object::Object> {
    match json::parse(source)? {
        JsonValue::Object(obj) => Ok(obj),
        _ => Err(anyhow!("syft output returned a non object JSON"))
    }
}

fn parse_artifact(artifact: &JsonValue) -> Result<Package> {
    let artifact = as_object(artifact)
        .ok_or(anyhow!("'artifact' is not an object"))?;

    let type_ = object_get(artifact, "type")?
        .as_str()
        .ok_or(anyhow!("'type' is not a string"))?;

    let meta_type = artifact.get("metadataType")
        .ok_or(anyhow!("'metadataType' missing"))?;

    // This mapping might not be so one-to-one
    let (type_, expect_meta_type) = match type_ {
        "deb" => (PackageType::Deb, "DpkgMetadata"),
        "rpm" => (PackageType::Rpm, "RpmMetadata"),
        "python" => (PackageType::Python, "PythonPackageMetadata"),
        _ => return Err(anyhow!("'{type_}' is an unsupported artifact type")),
    };

    if meta_type != expect_meta_type {
        return Err(anyhow!("'metadataType' has unexpected value {meta_type}, expected {expect_meta_type}"));
    }

    Ok(Package {
        type_,
        artifact,
    })
}

pub enum PackageType {
    Rpm,
    Deb,
    Python,
}

pub struct Package<'a> {
    type_: PackageType,
    artifact: &'a json::object::Object,
}

impl <'a> Package<'a> {
    pub fn id(&self) -> Result<&str> {
        Ok(self.artifact.get("id")
            .ok_or(anyhow!("'id' missing"))?
            .as_str()
            .ok_or(anyhow!("'id' is not a string"))?)
    }

    pub fn files(&self) -> Result<Vec<String>> {
        let meta = as_object(
            object_get(self.artifact, "metadata")?
        ).ok_or(anyhow!("'metadata' is not a string"))?;

        let keys: Vec<_> = meta.iter().map(|(k, _)| k).collect();

        match meta.get("files") {
            Some(files) => {
                let files = as_array(files)
                    .ok_or(anyhow!("'files' is not an array"))?;

                match self.type_ {
                    PackageType::Rpm | PackageType::Deb => generic_files(files),
                    PackageType::Python => python_files(files, meta),
                }
            },
            None => Ok(Vec::new())
        }
    }

    fn trace(&self) {
        trace!("{:?}: {:?}", self.id(), self.files());
    }
}

fn generic_files(files_arr: &json::Array) -> Result<Vec<String>> {
    let paths = files_arr.iter()
        .filter_map(extract_path)
        .map(normalize)
        .collect();

    Ok(paths)
}

fn python_files(files_arr: &json::Array, meta: &json::object::Object) -> Result<Vec<String>> {
    let root_path = meta.get("sitePackagesRootPath")
        .ok_or(anyhow!("'sitePackagesRootPath' is missing"))?
        .as_str()
        .ok_or(anyhow!("'sitePackagesRootPath' is not a string"))?;

    let root_path = PathBuf::from(root_path);

    let paths = files_arr.iter()
        .filter_map(extract_path)
        .map(|path| root_path.join(path))
        .map(normalize)
        .collect();

    Ok(paths)
}

fn extract_path(f: &JsonValue) -> Option<PathBuf> {
    use std::str::FromStr;

    PathBuf::from_str(as_object(f)?
        .get("path")?
        .as_str()?)
        .ok()
}

fn normalize(path: PathBuf) -> String {
    let path = match std::fs::canonicalize(&path) {
        Ok(path) => path,
        Err(_) => path,
    };

    path.to_string_lossy()
        .into_owned()
}

fn as_object(val: &JsonValue) -> Option<&json::object::Object> {
    match val {
        JsonValue::Object(o) => Some(o),
        _ => None,
    }
}

fn as_array(val: &JsonValue) -> Option<&json::Array> {
    match val {
        JsonValue::Array(a) => Some(a),
        _ => None,
    }
}

fn object_get<'a>(obj: &'a json::object::Object, key: &str) -> Result<&'a JsonValue> {
    obj.get(key)
        .ok_or(anyhow!("'{key}' is missing"))
}
