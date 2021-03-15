use tracing::info_span;
use tracing_subscriber::EnvFilter;

use keyd::agent::KeyDAgent;
use keyd::store::KeyStore;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("keyd=INFO".parse()?))
        .init();

    let path = {
        match std::env::var("AGENT_SOCK") {
            Ok(path) => std::path::PathBuf::from(path),
            Err(_) => std::env::temp_dir().join(format!("keyd-agent.{}", std::process::id())),
        }
    };

    // {
    //     // todo: gracefully stop
    //     let path = path.clone();
    //     ctrlc::set_handler(move || {
    //         info!("ctrl-c received, remove {}", &path.display());
    //         std::fs::remove_file(&path).ok();
    //         std::process::exit(0);
    //     })?;
    // }

    let store = KeyStore::new("sqlite://key.db").await?;
    store.init().await?;

    let agent = KeyDAgent::new(store).unwrap();
    let _span = info_span!("Server");

    {
        let path = path.clone();
        tokio::spawn(async move {
            agent.run(path).await.ok();
        });
    }

    tokio::signal::ctrl_c().await.unwrap();

    std::fs::remove_file(path).ok();

    Ok(())
}
