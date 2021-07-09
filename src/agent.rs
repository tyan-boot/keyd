use std::path::Path;

use libsshkey::key::HashType;
use notify_rust::Notification;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(target_os = "unix")]
use tokio::net::{UnixListener, UnixStream};

#[cfg(target_os = "windows")]
use tokio::net::windows;

use crate::error::Result;
use crate::keyd::KeyD;
use crate::parse::{parse_packet, Reply, Request};

#[derive(Debug, Clone)]
pub struct KeyDAgent {
    pub keyd: KeyD,
}

impl KeyDAgent {
    pub fn new(keyd: KeyD) -> Result<KeyDAgent> {
        Ok(KeyDAgent { keyd })
    }

    #[instrument(name = "Agent", skip(self, request))]
    pub async fn process(&mut self, request: Request) -> Result<Reply> {
        match request {
            Request::List => {
                info!("list keys");
                let keys: Vec<_> = self
                    .keyd
                    .get_all()
                    .await?
                    .into_iter()
                    .map(|it| it.raw)
                    .collect();
                Ok(Reply::list(&keys))
            }
            Request::Add(key) => {
                info!("add key: {}", key.fingerprint(HashType::SHA256)?);
                self.keyd.add(None, None::<&str>, key).await?;
                Ok(Reply::success())
            }
            Request::Sign(fingerprint, data, _flags) => {
                let item = self.keyd.get(&fingerprint).await?;

                cfg_if::cfg_if! {
                    if #[cfg(target_os = "unix")] {
                        let mut action = Default::default();
                        Notification::new()
                            .summary("KeyD sign request")
                            .body(&format!("sign data with key {}", item.item.name))
                            .appname("KeyD")
                            .action("approve", "approve")
                            .action("reject", "reject")
                            .timeout(5000)
                            .show()
                            .unwrap()
                            .wait_for_action(|it| {
                                action = it.to_owned();
                            });

                            match &*action {
                                "approve" => {
                                    info!("sign data with key {}", &fingerprint);
                                    let sig = self.keyd.sign(&fingerprint, data).await?;
                                    let key = self.keyd.get(&fingerprint).await?;

                                    Ok(Reply::sign(&key.raw, sig))
                                }
                                _ => Ok(Reply::failed()),
                            }
                    } else {
                        let sig = self.keyd.sign(&fingerprint, data).await?;
                        let key = self.keyd.get(&fingerprint).await?;

                        Ok(Reply::sign(&key.raw, sig))
                    }
                }
            }
        }
    }

    #[cfg(target_os = "unix")]
    pub async fn run(self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let listener = UnixListener::bind(path)?;
        info!("listen on: {}", path.display());
        info!("run `export SSH_AUTH_SOCK={}` to use agent", path.display());

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let agent = self.clone();

                    tokio::spawn(async move {
                        handle(stream, agent).await.ok();
                    });
                }
                Err(e) => {
                    error!("failed accept connection: {:?}", e);
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    pub async fn run(self, path: impl AsRef<Path>) -> Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "unix")]
async fn handle(mut stream: UnixStream, mut agent: KeyDAgent) -> Result<()> {
    let mut buf = vec![0u8; 4096];

    loop {
        let r = stream.read(&mut buf).await?;
        if r == 0 {
            break;
        }

        let req = parse_packet(&buf[0..r])?;
        let reply = agent.process(req).await.unwrap_or_else(|e| {
            error!("agent failed: {:?}", e);
            Reply::failed()
        });

        stream.write(&reply).await.ok();
    }

    Ok(())
}
