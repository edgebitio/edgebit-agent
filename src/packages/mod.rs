use std::collections::HashMap;

use anyhow::{Result, anyhow};
use log::*;
use json::JsonValue;

pub struct Registry {
    // Filename to a list of pkg ids
    inner: HashMap<String, Vec<String>>,
}

impl Registry {
    pub fn new() -> Self {
        Self { inner: HashMap::new() }
    }

    pub fn from_sbom(sbom: &json::object::Object) -> Self {
        let inner = if let Some(artifacts) = sbom.get("artifacts") {
            let pkgs = artifacts.members()
                .filter_map(|a| {
                    let a = as_object(a)?;
                    let type_ = a.get("type")?.as_str()?;
                    match type_ {
                        "deb" => {
                            match parse_artifact(a, "DpkgMetadata") {
                                Ok(pkg) => { trace_pkg(&pkg); Some(pkg) },
                                Err(e) => { warn!("{e}"); None }
                            }
                        },
                        "rpm" => {
                            match parse_artifact(a, "RpmMetadata") {
                                Ok(pkg) => { trace_pkg(&pkg); Some(pkg) },
                                Err(e) => { warn!("{e}"); None }
                            }
                        },
                        _ => None,
                    }
                });

            let mut inner: HashMap<String, Vec<String>> = HashMap::new();

            for (id, files) in pkgs {
                for file in files {
                    inner.entry(file)
                        .or_default()
                        .push(id.clone());
                }
            }

            inner
        } else {
            HashMap::new()
        };

        Self { inner }
    }

    pub fn add(&mut self, filename: impl Into<String>, pkg: impl Into<String>) {
        let filename: String = filename.into();
        match self.inner.get_mut(&filename) {
            Some(v) => v.push(pkg.into()),
            None => {
                _ = self.inner.insert(filename, vec![pkg.into()]);
            }
        }
    }

    pub fn add_pkg(&mut self, id: &str, files: &[String]) {
        for f in files {
            self.add(f, id)
        }
    }

    pub fn get_packages(&self, filenames: Vec<String>) -> Vec<PkgRef> {
        let mut result: HashMap<String, PkgRef> = HashMap::new();

        for f in filenames {
            match self.inner.get(&f) {
                Some(pkg_ids) => {
                    for id in pkg_ids {
                        match result.get_mut(id) {
                            Some(pkg) => pkg.filenames.push(f.to_string()),
                            None => {
                                result.insert(id.clone(), PkgRef::new(id.clone(), f.to_string()));
                            }
                        }
                    }
                },
                None => {
                    result.insert(String::new(), PkgRef::new(String::new(), f.to_string()));
                }
            }
        }

        result.into_values().collect()
    }
}

pub struct PkgRef {
    pub id: String,
    pub filenames: Vec<String>,
}

impl PkgRef {
    fn new(id: String, filename: String) -> Self {
        Self {
            id,
            filenames: vec![filename],
        }
    }
}

fn parse_artifact(artifact: &json::object::Object, expect_meta_type: &str) -> Result<(String, Vec<String>)> {
    let id = artifact.get("id")
        .ok_or(anyhow!("'id' missing"))?
        .as_str()
        .ok_or(anyhow!("'id' is not a string"))?;
    
    let meta_type = artifact.get("metadataType")
        .ok_or(anyhow!("'metadataType' missing"))?;

    if meta_type != expect_meta_type {
        return Err(anyhow!("'metadataType' has unexpected value {meta_type}, expected {expect_meta_type}"));
    }

    let meta = as_object(
        artifact.get("metadata")
            .ok_or(anyhow!("'metadata"))?
    ).ok_or(anyhow!("'metadata' is not a string"))?;

    let files = meta.get("files")
        .ok_or(anyhow!("'files' missing"))?;

    let files = as_array(files)
        .ok_or(anyhow!("'files' is not an array"))?;

    let paths = files.iter()
        .filter_map(|f| {
            Some(as_object(f)?
                .get("path")?
                .as_str()?
                .to_string())
        })
        .map(|path| {
            match std::fs::canonicalize(&path) {
                Ok(path) => {
                    path.to_string_lossy()
                    .into_owned()
                },
                Err(_) => path,
            }
        })
        .collect();

    Ok((id.to_string(), paths))
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

fn trace_pkg(pkg: &(String, Vec<String>)) {
    trace!("{}: {:?}", pkg.0, pkg.1);
}