pub mod rpm;

use std::collections::HashMap;

pub struct Registry {
    // Filename to a list of pkg ids
    inner: HashMap<String, Vec<String>>,
}

impl Registry {
    pub fn new() -> Self {
        Self { inner: HashMap::new() }
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
