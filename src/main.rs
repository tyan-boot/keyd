use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tracing::{error, info, info_span};
use tracing_subscriber::EnvFilter;

use keyd::agent::KeyDAgent;
use keyd::parse::{parse_packet, Reply};
use keyd::store::KeyStore;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("keyd=INFO".parse()?))
        .init();

    let span = info_span!("Init");
    let g = span.enter();

    let path = std::env::temp_dir().join(format!("keyd-agent.{}", std::process::id()));
    // {
    //     // todo: gracefully stop
    //     let path = path.clone();
    //     ctrlc::set_handler(move || {
    //         info!("ctrl-c received, remove {}", &path.display());
    //         std::fs::remove_file(&path).ok();
    //         std::process::exit(0);
    //     })?;
    // }

    info!("listen on: {}", &path.display());
    info!(
        "run `export SSH_AUTH_SOCK={}` to use agent",
        &path.display()
    );

    let store = KeyStore::new("sqlite://key.db").await?;

    let listener = UnixListener::bind(&path)?;
    let mut agent = KeyDAgent::new(store).unwrap();

    drop(g);

    let span = info_span!("Server");
    let _g = span.enter();
    loop {
        match listener.accept().await {
            Ok((mut stream, _addr)) => {
                info!("client connect");
                let mut buf = vec![0u8; 4096];
                'handle: loop {
                    let r = stream.read(&mut buf).await;

                    match r {
                        Ok(r) => {
                            if r == 0 {
                                break 'handle;
                            }
                        }
                        Err(_e) => break 'handle,
                    }

                    let req = parse_packet(&buf);

                    match req {
                        Ok(req) => {
                            let reply =
                                agent.process(req).await.unwrap_or_else(|_| Reply::failed());

                            stream.write(&reply).await.ok();
                        }
                        Err(e) => {
                            error!("failed read request: {}", e);
                            let reply = Reply::failed();
                            stream.write(&reply).await.ok();
                        }
                    }
                }
            }
            Err(_e) => {}
        }
    }
}
