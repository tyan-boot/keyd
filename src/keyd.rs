use crate::error::{Error, Result};
use libsshkey::key::{HashType, Key};
use std::collections::HashMap;

#[derive(Debug)]
pub struct KeyD {
    /// fingerprint -> key
    keys: HashMap<String, Key>,
}

impl KeyD {
    pub fn new() -> Result<KeyD> {
        Ok(KeyD {
            keys: HashMap::new(),
        })
    }

    pub fn add(&mut self, key: Key) -> Result<()> {
        let fingerprint = key.fingerprint(HashType::SHA256)?;

        self.keys.insert(fingerprint, key);

        Ok(())
    }

    pub fn remove(&mut self, key: &Key) -> Result<()> {
        let fingerprint = key.fingerprint(HashType::SHA256)?;

        self.keys.remove(&fingerprint);

        Ok(())
    }

    pub fn clear(&mut self) {
        self.keys.clear();
    }

    pub fn get_all(&self) -> Result<Vec<&Key>> {
        Ok(self.keys.values().collect())
    }

    pub fn sign(&self, fingerprint: &str, data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let key = self.keys.get(fingerprint).ok_or(Error::KeyNotfound)?;

        let sig = key.sign(data)?;
        Ok(sig)
    }

    pub fn get(&self, fingerprint: &str) -> Result<&Key> {
        self.keys.get(fingerprint).ok_or(Error::KeyNotfound)
    }
}
