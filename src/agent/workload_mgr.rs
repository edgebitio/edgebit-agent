use std::borrow::Cow;
use std::sync::{Arc, Mutex};
use std::collections::{HashMap, VecDeque};
use std::path::{PathBuf};
use std::time::{Instant, Duration};

use anyhow::{Result};
use log::*;
use tokio::sync::mpsc::{Sender, Receiver};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::config::Config;
use crate::registry::{Registry, PkgRef};
use crate::containers::{Containers, ContainerInfo, ContainerEvent};
use crate::open_monitor::{OpenMonitor, OpenEvent};
use crate::sbom::Sbom;
use crate::scoped_path::*;

const BASEOS_ID_PATH: &str = "/var/lib/edgebit/baseos-id";

const OS_RELEASE_PATHS: [&str; 2] = ["etc/os-release", "usr/lib/os-release"];

const OPEN_EVENT_LAG: Duration = Duration::from_secs(1);

pub enum Event {
    ContainerStarted(String, ContainerInfo),
    ContainerStopped(String, ContainerInfo),
    PackageInUse(String, Vec<PkgRef>),
}

struct OpenEventQueueItem {
    timestamp: Instant,
    evt: OpenEvent,
}

struct Inner {
    config: Arc<Config>,
    host_root: RootFsPath,
    containers: Containers,
    open_monitor: OpenMonitor,
    host_workload: Mutex<HostWorkload>,
    container_workloads: Mutex<HashMap<String, ContainerWorkload>>,
    events: Sender<Event>,
    open_event_q: Mutex<VecDeque<OpenEventQueueItem>>,
}

pub struct WorkloadManager {
    inner: Arc<Inner>,
    run_task: JoinHandle<()>,
    open_event_task: JoinHandle<()>,
}

impl WorkloadManager {
    pub fn start(config: Arc<Config>, host_root: &RootFsPath, host_workload: HostWorkload, events: Sender<Event>) -> Result<Self> {
        let (open_tx, open_rx) = tokio::sync::mpsc::channel::<OpenEvent>(1000);
        let open_monitor = OpenMonitor::start(open_tx)?;

        host_workload.start_monitoring(&open_monitor);

        let (cont_tx, cont_rx) = tokio::sync::mpsc::channel::<ContainerEvent>(10);
        let mut containers = Containers::new(cont_tx);
        if let Some(host) = config.docker_host() {
            containers.track_docker(host);
        }
        if let Some(host) = config.containerd_host() {
            containers.track_k8s(host);
        }

        let inner = Arc::new(Inner{
            config,
            host_root: host_root.clone(),
            containers,
            open_monitor,
            host_workload: Mutex::new(host_workload),
            container_workloads: Mutex::new(HashMap::new()),
            events,
            open_event_q: Mutex::new(VecDeque::new()),
        });

        let run_task = tokio::task::spawn(
            run(inner.clone(), open_rx, cont_rx)
        );

        let open_event_task = tokio::task::spawn(
            service_open_event_queue(inner.clone())
        );

        Ok(Self{
            inner,
            run_task,
            open_event_task,
        })
    }
}

async fn run(inner: Arc<Inner>, mut open_rx: Receiver<OpenEvent>, mut cont_rx: Receiver<ContainerEvent>) {
    loop {
        tokio::select!{
            evt = open_rx.recv() => {
                match evt {
                    Some(evt) => queue_open_event(&inner, evt),
                    None => break,
                }
            },
            evt = cont_rx.recv() => {
                match evt {
                    Some(evt) => handle_container_event(&inner, evt).await,
                    None => break,
                }
            }
        }
    }
}

fn queue_open_event(inner: &Inner, evt: OpenEvent) {
    inner.open_event_q.lock()
        .unwrap()
        .push_back(OpenEventQueueItem{
                timestamp: Instant::now(),
                evt,
            });
}

fn pop_open_event(inner: &Inner, cutoff: Instant) -> Option<OpenEventQueueItem> {
    let mut q = inner.open_event_q.lock().unwrap();
    if q.front()?.timestamp > cutoff {
        None
    } else {
        q.pop_front()
    }
}

async fn service_open_event_queue(inner: Arc<Inner>) {
    loop {
        let cutoff = Instant::now()
            .checked_sub(OPEN_EVENT_LAG)
            .unwrap();

        while let Some(item) = pop_open_event(&inner, cutoff) {
            handle_open_event(&inner, item.evt).await;
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn handle_open_event(inner: &Inner, evt: OpenEvent) {
    let cgroup = evt.cgroup_name.unwrap_or(String::new());
    trace!("[{cgroup}]: {}", evt.filename.display());

    let in_use = match inner.containers.id_from_cgroup(&cgroup) {
        Some(id) => {
            trace!("Container match: {id}");

            let container_workloads = inner.container_workloads.lock().unwrap();
            if let Some(ref workload) = container_workloads.get(&id) {
                match workload.resolve(&evt.filename) {
                    Ok(Some(filepath)) => {
                        let pkg = PkgRef{
                            id: String::new(),
                            filenames: vec![filepath],
                        };

                        Event::PackageInUse(id, vec![pkg])
                    },
                    Ok(None) => return,
                    Err(err) => {
                        resolve_failed(&evt.filename, err);
                        return;
                    }
                }
            } else {
                error!("Container workload missing for id={id}");
                return;
            }
        },
        None => {
            let host_workload = inner.host_workload.lock().unwrap();

            match host_workload.resolve(&evt.filename) {
                Ok(Some(filepath)) => {
                    let filenames = vec![filepath];
                    let pkgs = host_workload.pkgs.get_packages(filenames);

                    if pkgs.is_empty() {
                        return;
                    }

                    Event::PackageInUse(host_workload.id.clone(), pkgs)
                },
                Ok(None) => {
                    return;
                },
                Err(err) => {
                    resolve_failed(&evt.filename, err);
                    return;
                }
            }
        }
    };

    if let Err(err) = inner.events.send(in_use).await {
        error!("Failed to send events on a channel: {err}");
    }
}

async fn handle_container_event(inner: &Inner, evt: ContainerEvent) {
    match evt {
        ContainerEvent::Started(id, info) => {
            match &info.rootfs {
                Some(rootfs) => {
                    let rootfs = rootfs.to_rootfs(&inner.host_root);

                    match ContainerWorkload::new(rootfs, &inner.config.container_includes()) {
                        Ok(workload) => {
                            workload.start_monitoring(&inner.open_monitor);

                            inner.container_workloads
                                .lock()
                                .unwrap()
                                .insert(id.clone(), workload);
                        },
                        Err(err) => error!("Failed to create a container workload: {err}"),
                    }
                },
                None => error!("Container {id} started but rootfs missing"),
            }

            if let Err(err) = inner.events.send(Event::ContainerStarted(id, info)).await {
                error!("Failed to send events on a channel: {err}");
            }
        },
        ContainerEvent::Stopped(id, info) => {
            let workload = inner.container_workloads.lock()
                .unwrap()
                .remove(&id);

            if let Some(workload) = workload {
                workload.stop_monitoring(&inner.open_monitor);
            }

            if let Err(err) = inner.events.send(Event::ContainerStopped(id, info)).await {
                error!("Failed to send events on a channel: {err}");
            }
        }
    };
}

pub struct HostWorkload {
    pub id: String,
    pub group: Vec<String>,
    pub hostname: String,
    pub os_pretty_name: String,
    pub image_id: String,
    pkgs: Registry,
    includes: PathSet,
}

impl HostWorkload {
    pub fn new(sbom: Sbom, config: Arc<Config>, host_root: &RootFsPath, hostname: String) -> Result<Self> {
        let id = load_baseos_id();

        let os_pretty_name = match get_os_release(host_root) {
            Ok(mut os_release) => {
                os_release.remove("PRETTY_NAME")
                    .or_else(|| os_release.remove("NAME"))
                    .unwrap_or("Linux".to_string())
            },
            Err(err) => {
                error!("Failed to retrieve os-release: {err}");
                String::new()
            }
        };

        let mut includes = PathSet::new(&host_root)?;
        for path in config.host_includes() {
            if let Err(err) = includes.add(&WorkloadPath::from(&path)) {
                // ignore "no such file or directory" erros
                if !is_not_found(&err) {
                    error!("Failed to add a watch for {}: {err}", path);
                }
            }
        }

        Ok(Self{
            id,
            group: Vec::new(),
            hostname,
            os_pretty_name,
            image_id: sbom.id(),
            pkgs: Registry::from_sbom(&sbom, &host_root)?,
            includes,
        })
    }

    fn start_monitoring(&self, monitor: &OpenMonitor) {
        for path in self.includes.all() {
            let path = path.to_rootfs(&self.includes.base);

            if let Err(err) = monitor.add_path(&path) {
                error!("Failed to start monitoring {} for container: {err}", path.display());
            }
        }
    }

    fn stop_monitoring(&self, monitor: &OpenMonitor) {
        for path in self.includes.all() {
            let path = path.to_rootfs(&self.includes.base);
            _ = monitor.remove_path(&path);
        }
    }

    // Checks if the path is not filtered out and returns canonicalized verison
    fn resolve(&self, path: &WorkloadPath) -> Result<Option<WorkloadPath>> {
        self.includes.resolve(path)
    }
}

fn load_baseos_id() -> String {
    if let Ok(id) = std::fs::read_to_string(BASEOS_ID_PATH) {
        return id;
    }

    let id = uuid_string();

    if let Err(err) = std::fs::write(BASEOS_ID_PATH, &id) {
        error!("Failed to save BaseOS workload ID to {BASEOS_ID_PATH}: {err}");
    }

    id
}

fn uuid_string() -> String {
    let mut buf = Uuid::encode_buffer();
    Uuid::new_v4()
        .as_hyphenated()
        .encode_lower(&mut buf)
        .to_string()
}
struct ContainerWorkload {
    includes: PathSet,
}

impl ContainerWorkload {
    fn new(host_root: RootFsPath, includes: &[String]) -> Result<Self> {
        let mut includes_set = PathSet::new(&host_root)?;
        for path in includes {
            // ignore the error as it's most likely from a missing path (which is ok)
            _ = includes_set.add(&WorkloadPath::from(path));
        }

        Ok(Self{
            includes: includes_set,
        })
    }

    fn resolve(&self, path: &WorkloadPath) -> Result<Option<WorkloadPath>> {
        self.includes.resolve(path)
    }

    fn start_monitoring(&self, monitor: &OpenMonitor) {
        for path in self.includes.all() {
            let path = path.to_rootfs(&self.includes.base);

            if let Err(err) = monitor.add_path(&path) {
                error!("Failed to start monitoring {} for container: {err}", path.display());
            }
        }
    }

    fn stop_monitoring(&self, monitor: &OpenMonitor) {
        for path in self.includes.all() {
            let path = path.to_rootfs(&self.includes.base);
            _ = monitor.remove_path(&path);
        }
    }
}

struct PathSet {
    base: RootFsPath,
    members: HashMap<WorkloadPath, ()>,
}

impl PathSet {
    fn new(base: &RootFsPath) -> Result<Self> {
        Ok(Self {
            base: base.realpath()?,
            members: HashMap::new(),
        })
    }

    fn to_rootfs(&self, path: &WorkloadPath) -> RootFsPath {
        path.to_rootfs(&self.base)
    }

    // adds the path, resolving the symlinks first
    fn add(&mut self, path: &WorkloadPath) -> Result<()> {
        let rp = self.to_rootfs(path)
            .realpath()?;

        let wp = WorkloadPath::from_rootfs(&self.base, &rp)?;

        self.members.insert(wp, ());
        Ok(())
    }

    fn contains(&self, path: &WorkloadPath) -> bool {
        self.members
            .keys()
            .any(|f| path.as_raw().starts_with(f.as_raw()))
    }

    fn resolve(&self, path: &WorkloadPath) -> Result<Option<WorkloadPath>> {
        let rp = self.to_rootfs(path)
            .realpath()?;

        if !is_file(&rp) {
            return Ok(None);
        }

        let path = WorkloadPath::from_rootfs(&self.base, &rp)?;

        if self.contains(&path) {
            Ok(Some(path))
        } else {
            Ok(None)
        }
    }

    fn all<'a>(&'a self) -> impl Iterator<Item=&WorkloadPath> + 'a {
        self.members.keys()
    }
}

fn resolve_failed(filepath: &WorkloadPath, err: anyhow::Error) {
    match err.downcast::<std::io::Error>() {
        Ok(io_err) => {
            // File not found is ok as it was a transient file that got deleted
            // This almost exclusively occurs on data files
            if io_err.kind() != std::io::ErrorKind::NotFound {
                info!("Failed to canonicalize {}: {io_err}", filepath.display());
            }
        },
        Err(err) => {
            info!("Failed to canonicalize {}: {err}", filepath.display());
        }
    }
}

#[inline]
fn is_file(path: &RootFsPath) -> bool {
    match std::fs::metadata(path.as_raw()) {
        Ok(md) => md.is_file(),
        Err(_) => false,
    }
}

fn get_os_release(host_root: &RootFsPath) -> rs_release::Result<HashMap<Cow<'static, str>, String>> {
    for file in OS_RELEASE_PATHS {
        let file = host_root.join(&PathBuf::from(file));
        if let Ok(release) = rs_release::parse_os_release(file.as_raw()) {
            return Ok(release);
        }
    }
    Err(rs_release::OsReleaseError::NoFile)
}

fn is_not_found(err: &anyhow::Error) -> bool {
    if let Some(err) = err.downcast_ref::<std::io::Error>() {
        err.kind() == std::io::ErrorKind::NotFound
    } else {
        false
    }
}