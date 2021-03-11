use libsshkey::key::HashType;

use crate::error::Result;
use crate::keyd::KeyD;
use crate::parse::{Reply, Request};
use crate::store::KeyStore;

#[derive(Debug)]
pub struct KeyDAgent {
    keyd: KeyD,
}

impl KeyDAgent {
    pub fn new(store: KeyStore) -> Result<KeyDAgent> {
        Ok(KeyDAgent {
            keyd: KeyD::new(store)?,
        })
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
                info!("sign data with key {}", &fingerprint);
                let sig = self.keyd.sign(&fingerprint, data).await?;
                let key = self.keyd.get(&fingerprint).await?;

                Ok(Reply::sign(&key.raw, sig))
            }
        }
    }
}
