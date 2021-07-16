use std::sync::Arc;

use libsshkey::key::{EcGroup, Ecdsa, HashType, Key as RawKey, Rsa};
use libsshkey::SSHBuffer;
use rand::RngCore;

use crate::error::{Error, Result};
use crate::store::models::{Key, KeyGroup, KeyType};
use crate::store::models::{KeyItem, KeyMeta, KeyPrivate, KeySource};
use crate::store::KeyStore;

#[derive(Clone)]
pub struct KeyD {
    store: Arc<dyn KeyStore>,
}

pub enum GenerateParam {
    Rsa(u32),
    Ed25519,
    Ecdsa(EcGroup),
}

impl KeyD {
    pub fn new<T: KeyStore + 'static>(store: T) -> Result<KeyD> {
        Ok(KeyD {
            store: Arc::new(store),
        })
    }

    /// add raw managed ssh key to keyd store.
    /// return wrapped database item and origin `RawKey`
    pub async fn add(
        &mut self,
        group_id: Option<i64>,
        name: Option<impl AsRef<str>>,
        raw: RawKey,
    ) -> Result<Key> {
        let fingerprint = raw.fingerprint(HashType::SHA256)?;

        let item = self.store.get_key_by_fingerprint(&fingerprint).await?;
        if let Some(item) = item {
            return Ok(Key { item });
        }

        let public = raw.export_public_ssh()?;
        let private = raw.export_private_pem()?;
        let meta = KeyMeta {
            public,
            fingerprint,
        };
        let private = KeyPrivate::Managed { private };

        let name = match name {
            Some(name) => name.as_ref().to_owned(),
            None => {
                let mut rng = rand::thread_rng();
                let mut buf = [0u8; 3];
                rng.fill_bytes(&mut buf);

                format!("key-{}", hex::encode_upper(&buf))
            }
        };

        let key_type = match &raw {
            RawKey::Rsa(_) => KeyType::Rsa,
            RawKey::EcdsaP256(_) => KeyType::EcdsaP256,
            RawKey::EcdsaP384(_) => KeyType::EcdsaP384,
            RawKey::EcdsaP521(_) => KeyType::EcdsaP521,
            _ => unimplemented!(),
        };

        let item = KeyItem {
            id: 0,
            name,
            source: KeySource::Managed,
            key_type,
            group_id,
            meta,
            private,
        };

        self.store.add_key(group_id.unwrap_or(1), &item).await?;

        Ok(Key { item })
    }

    pub async fn add_tpm(&mut self) -> Result<()> {
        todo!()
    }

    pub async fn add_pkcs11(&mut self) -> Result<()> {
        todo!()
    }

    pub async fn generate_managed(
        &mut self,
        param: GenerateParam,
        comment: Option<String>,
    ) -> Result<RawKey> {
        match param {
            GenerateParam::Rsa(bits) => {
                let rsa = Rsa::generate(bits, comment)?;

                Ok(RawKey::Rsa(rsa))
            }

            GenerateParam::Ed25519 => {
                todo!()
            }
            GenerateParam::Ecdsa(group) => {
                let ecdsa = Ecdsa::generate(group, comment)?;

                match group {
                    EcGroup::P256 => Ok(RawKey::EcdsaP256(ecdsa)),
                    EcGroup::P384 => Ok(RawKey::EcdsaP384(ecdsa)),
                    EcGroup::P521 => Ok(RawKey::EcdsaP521(ecdsa)),
                }
            }
        }
    }

    pub async fn generate_pkcs11(&mut self) -> Result<()> {
        todo!()
    }

    pub async fn generate_tpm(&mut self) -> Result<()> {
        todo!()
    }

    /// remove key with id from keyd store
    pub async fn remove(&mut self, id: i64) -> Result<()> {
        self.store.remove_key(id).await?;
        Ok(())
    }

    pub fn clear(&mut self) {
        todo!()
    }

    pub async fn get_all(&self) -> Result<Vec<Key>> {
        let keys: Vec<_> = self
            .store
            .list_keys()
            .await?
            .into_iter()
            .map(|it| Key { item: it })
            .collect();

        Ok(keys)
    }

    /// get keys in group id
    pub async fn list_group_keys(&self, id: i64) -> Result<Vec<Key>> {
        let keys: Vec<_> = self
            .store
            .list_group_keys(id)
            .await?
            .into_iter()
            .map(|it| Key { item: it })
            .collect();

        Ok(keys)
    }

    /// get ssh key by SHA256 fingerprint
    pub async fn get(&self, fingerprint: &str) -> Result<Key> {
        let item = self
            .store
            .get_key_by_fingerprint(fingerprint)
            .await?
            .ok_or(Error::KeyNotfound)?;
        Ok(Key { item })
    }

    /// create a key group
    pub async fn create_group(&self, name: &str) -> Result<i64> {
        Ok(self.store.create_group(name).await?)
    }

    /// delete a key group by id
    pub async fn delete_group(&self, id: i64) -> Result<()> {
        Ok(self.store.delete_group(id).await?)
    }

    /// rename a key group to `new_name`
    pub async fn rename_group(&self, id: i64, new_name: &str) -> Result<()> {
        Ok(self.store.rename_group(id, new_name).await?)
    }

    /// get all groups
    pub async fn list_groups(&self) -> Result<Vec<KeyGroup>> {
        Ok(self.store.list_groups().await?)
    }
}

impl Key {
    pub fn public_blob(&self) -> Result<SSHBuffer> {
        match &self.item.private {
            KeyPrivate::Managed { private } => {
                let key = libsshkey::key::parse_private_pem(&private, None::<&[u8]>)?;
                Ok(key.export_public_blob()?)
            }
            _ => todo!(),
        }
    }

    pub fn public(&self) -> &str {
        &self.item.meta.public
    }

    pub fn comment(&self) -> Option<&str> {
        // todo
        None
    }

    fn sign_managed(&self, data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        match &self.item.private {
            KeyPrivate::Managed { private } => {
                let key = libsshkey::key::parse_private_pem(&private, None::<&[u8]>)?;
                Ok(key.sign(data)?)
            }
            _ => unreachable!(),
        }
    }

    fn sign_pkcs11(&self, _data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        todo!()
    }

    fn sign_tpm(&self, _data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        todo!()
    }

    pub fn sign(&self, data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        match self.item.source {
            KeySource::Managed => self.sign_managed(data),
            KeySource::ExternPKCS11 => self.sign_pkcs11(data),
            KeySource::ExternTPM => self.sign_tpm(data),
        }
    }
}
