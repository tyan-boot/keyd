use crate::error::Result;
use crate::keyd::KeyD;
use crate::parse::{Reply, Request};
use libsshkey::key::HashType;

#[derive(Debug)]
pub struct KeyDAgent {
    keyd: KeyD,
}

impl KeyDAgent {
    pub fn new() -> Result<KeyDAgent> {
        Ok(KeyDAgent { keyd: KeyD::new()? })
    }

    #[instrument(name = "Agent", skip(self, request))]
    pub fn process(&mut self, request: Request) -> Result<Reply> {
        match request {
            Request::List => {
                info!("list keys");
                let keys = self.keyd.get_all()?;
                Ok(Reply::list(&keys))
            }
            Request::Add(key) => {
                info!("add key: {}", key.fingerprint(HashType::SHA256)?);
                self.keyd.add(key)?;
                Ok(Reply::success())
            }
            Request::Sign(fingerprint, data, _flags) => {
                info!("sign data with key {}", &fingerprint);
                let sig = self.keyd.sign(&fingerprint, data)?;
                let key = self.keyd.get(&fingerprint)?;

                Ok(Reply::sign(key, sig))
            }
        }
    }
}
