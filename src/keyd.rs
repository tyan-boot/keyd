use libsshkey::key::{Ecdsa, HashType, Key as RawKey, Rsa};
use rand::RngCore;

use crate::error::{Error, Result};
use crate::store::models::{Key, KeyItem, KeyType};
use crate::store::KeyStore;

#[derive(Debug)]
pub struct KeyD {
    store: KeyStore,
}

impl KeyD {
    pub fn new(store: KeyStore) -> Result<KeyD> {
        Ok(KeyD { store })
    }

    /// add raw ssh key into keyd store, return wrapped database item and origin `RawKey`
    pub async fn add(
        &mut self,
        group_id: Option<i64>,
        name: Option<impl AsRef<str>>,
        key: RawKey,
    ) -> Result<Key> {
        let fingerprint = key.fingerprint(HashType::SHA256)?;

        let item = self.store.get_key_by_fingerprint(&fingerprint).await?;
        if let Some(item) = item {
            return Ok(Key { item, raw: key });
        }

        let public_key = key.export_public_ssh()?;
        let private_key = key.export_private_pem()?;
        let name = match name {
            Some(name) => name.as_ref().to_owned(),
            None => {
                let mut rng = rand::thread_rng();
                let mut buf = [0u8; 3];
                rng.fill_bytes(&mut buf);

                format!("key-{}", hex::encode_upper(&buf))
            }
        };

        let key_type = match &key {
            RawKey::Rsa(_) => KeyType::Rsa,
            RawKey::EcdsaP256(_) => KeyType::EcdsaP256,
            RawKey::EcdsaP384(_) => KeyType::EcdsaP384,
            RawKey::EcdsaP521(_) => KeyType::EcdsaP521,
            _ => unimplemented!(),
        };

        let item = KeyItem {
            id: 0,
            name,
            fingerprint,
            public_key,
            private_key,
            key_type,
            group_id,
        };

        self.store.add_key(group_id.unwrap_or(1), &item).await?;

        Ok(Key { item, raw: key })
    }

    /// remove key with id from keyd store
    pub async fn remove(&mut self, id: i64) -> Result<()> {
        self.store.remove_key(id).await?;
        Ok(())
    }

    pub fn clear(&mut self) {}

    pub async fn get_all(&self) -> Result<Vec<Key>> {
        let keys: Result<Vec<_>> = self
            .store
            .list_keys()
            .await?
            .into_iter()
            .map(|it| item_to_raw(&it).map(|raw| Key { item: it, raw }))
            .collect();

        keys
    }

    /// sign data using key, fingerprint is SHA256 format.
    pub async fn sign(&self, fingerprint: &str, data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let key = self.get(fingerprint).await?;

        let sig = key.raw.sign(data)?;

        Ok(sig)
    }

    /// get ssh key by SHA256 fingerprint
    pub async fn get(&self, fingerprint: &str) -> Result<Key> {
        let item = self
            .store
            .get_key_by_fingerprint(fingerprint)
            .await?
            .ok_or(Error::KeyNotfound)?;
        let key = item_to_raw(&item)?;

        Ok(Key { item, raw: key })
    }
}

/// map database `KeyItem` to `libsshkey::key::Key`
fn item_to_raw(item: &KeyItem) -> Result<RawKey> {
    let key = match item.key_type {
        KeyType::Rsa => RawKey::Rsa(Rsa::import_private_pem(&item.private_key, None::<&str>)?),
        KeyType::EcdsaP256 => {
            RawKey::EcdsaP256(Ecdsa::import_private_pem(&item.private_key, None::<&str>)?)
        }
        KeyType::EcdsaP384 => {
            RawKey::EcdsaP384(Ecdsa::import_private_pem(&item.private_key, None::<&str>)?)
        }
        KeyType::EcdsaP521 => {
            RawKey::EcdsaP521(Ecdsa::import_private_pem(&item.private_key, None::<&str>)?)
        }
        _ => unimplemented!(),
    };

    Ok(key)
}
