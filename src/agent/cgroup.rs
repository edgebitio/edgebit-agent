/*
// Tracks cgroup_id -> cgroup path
pub struct CgroupRegistry {
    root_path: PathBuf,
    mapping: RefCell<HashMap<u64, PathBuf>>,
}

impl CgroupRegistry {
    pub fn new() -> Self {
        Self {
            root_path: DEFAULT_CGROUP_FS_PATH,
            mapping: HashMap::new(),
        }
    }

    pub fn with_cgroup_path(path: PathBuf) {
        Self {
            root_path: path,
            mapping:: HashMap::new(),
        }
    }

    pub fn lookup_path(&self, cgroup_id: u64) -> Option<PathBuf> {
        if let Some(path) = self.mapping.get(cgroup_id) {
            return Some(path);
        }

        if let Err(err) = rebuild() {
            error!("Re-building cgroup registry: {err}");
            return None;
        }

        self.mapping.get(cgroup_id)
    }

    pub fn lookup_unit(&self, cgroup_id: u64) -> Option<String> {

    }

    fn rebuild(&self) -> Result<()> {
        let mut cache = HashMap::new();

        traverse_cgroups(cgroup_root_path, &cache)?;

        self.mapping = cache;

        Ok(())
    }
}

fn traverse_cgroups(path: &Path, cache: &mut HashMap<u64, PathBuf>) -> Result<()> {
    for dirent in std::fs::read_dir(path)? {
        if let Ok(dirent) = dirent {
            if let Ok(file_type) = dirent.file_type() {
                let mut full_name = path.to_path_buf();
                full_name.push(dirent.file_name());
                if file_type.is_dir() {
                    build_cgroup_cache_(&full_name, cache)?;

                    let handle = handle_from_name(full_name)?;
                    cache.insert(handle, full_name);
                }
            }
        }
    }

    Ok(())
}

fn handle_from_name(path: PathBuf) -> Result<u64> {
    let (handle, _) = name_to_handle_at(0, path, 0)?;
    handle
}

#[repr(C)]
struct FileHandle {
    handle_bytes: u32,
    handle_type: i32,
    f_handle: u64,
}

fn name_to_handle_at(dirfd: i32, pathname: PathBuf, flags: i32) -> Result<(FileHandle, i32)> {
    let mut fh = FileHandle{
        handle_bytes: 8,
        handle_type: 0,
        f_handle: 0,
    };

    unsafe {
        let ret = libc::syscall(libc::SYS_name_to_handle_at,
            dirfd as c_int,
            CString::new(pathname)?.as_ptr(),
            &mut fh as *mut FileHandle,
            &mut mount_id as *mut c_int,
            flags as c_int
        );
    }

    let ret = ret as i32;

    if ret == 0 {
        Ok((fh, mount_id as i32))
    } else {
        Err(std::io::Error::from_raw_os_error(-ret))
    }
}
*/