pub mod open_monitor;
pub mod control_plane;

use anyhow::{Result, anyhow};

use open_monitor::OpenEvent;

use edgebit_agent::packages::{Registry, rpm};

#[tokio::main]
async fn main() {
    pretty_env_logger::init();
    match run().await {
        Ok(_) => {},
        Err(err) => {
            eprintln!("err: {err}");
            eprintln!("src: {}", err.source().unwrap());
        }
    }
}

async fn run() -> Result<()> {
    let url = std::env::var("EDGEBIT_URL")
        .map_err(|_| anyhow!("Is EDGEBIT_URL env var set?"))?;

    let token = std::env::var("EDGEBIT_ID")
        .map_err(|_| anyhow!("Is EDGEBIT_ID env var set?"))?;

    let mut client = control_plane::Client::connect(
        url.try_into()?,
        token.try_into()?,
    ).await?;

    let mut pkg_registry = Registry::new();

    let rpms = rpm::query_all()
        .unwrap_or(Vec::new());
    for r in &rpms {
        pkg_registry.add_pkg(&r.id, &r.files)
    }

    client.report_rpms(rpms).await?;

    report_in_use(&mut client, &mut pkg_registry).await?;
    Ok(())
}

async fn report_in_use(client: &mut control_plane::Client, pkg_registry: &mut Registry) -> Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<OpenEvent>(1000);
    let monitor_task = tokio::task::spawn_blocking(move || open_monitor::run(tx));

    // batch in 1s intervals

    while let Some(evt) = rx.recv().await {
        match evt.filename.into_string() {
            Ok(filename) => {
                let filenames = vec![filename];
                let pkgs = pkg_registry.get_packages(filenames);
                _ = client.report_in_use(pkgs).await;
            },

            Err(_) => (),
        }
    }

    monitor_task.await.unwrap().unwrap();

    Ok(())
}
