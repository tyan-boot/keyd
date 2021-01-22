use crate::error::Result;
use crate::keyd::KeyD;
use crate::parse::{Reply, Request};

#[derive(Debug)]
pub struct KeyDAgent {
    keyd: KeyD,
}

impl KeyDAgent {
    pub fn new() -> Result<KeyDAgent> {
        Ok(KeyDAgent { keyd: KeyD::new()? })
    }

    pub fn process(&mut self, request: Request) -> Result<Reply> {
        match request {
            Request::List => {
                let keys = self.keyd.get_all()?;
                Ok(Reply::list(&keys))
            }
            Request::Add(key) => {
                self.keyd.add(key)?;
                Ok(Reply::success())
            }
            Request::Sign(fingerprint, data, _flags) => {
                let sig = self.keyd.sign(&fingerprint, data)?;
                let key = self.keyd.get(&fingerprint)?;

                Ok(Reply::sign(key, sig))
            }
        }
    }
}
