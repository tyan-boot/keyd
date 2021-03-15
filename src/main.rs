use tracing_subscriber::EnvFilter;

use keyd::keyd::KeyD;
use keyd::store::KeyStore;

mod cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("keyd=INFO".parse()?))
        .init();

    let store = KeyStore::new("sqlite://key.db").await?;
    store.init().await?;

    let keyd = KeyD::new(store)?;

    cli::run(keyd).await?;

    Ok(())
}
