use libsshkey::key::{Ecdsa, EcGroup, HashType, Key as RawKey, Rsa};
use rand::RngCore;

use crate::error::{Error, Result};
use crate::store_v2::{KeyStore, StoreError};
use crate::store::models::{KeyGroup, KeyType, KeyV2};
use crate::store::models::v2::{self, KeyMeta, KeyPrivate, KeySource, KeyItem};

#[derive(Debug, Clone)]
pub struct KeyD {
    store: KeyStore,
}

pub enum GenerateParam {
    Rsa(u32),
    Ed25519,
    Ecdsa(EcGroup),
}

impl KeyD {
    pub fn new(store: KeyStore) -> Result<KeyD> {
        Ok(KeyD { store })
    }

    /// add raw managed ssh key to keyd store.
    /// return wrapped database item and origin `RawKey`
    pub async fn add_v2(
        &mut self,
        group_id: Option<i64>,
        name: Option<impl AsRef<str>>,
        raw: RawKey,
    ) -> Result<KeyV2> {
        let fingerprint = raw.fingerprint(HashType::SHA256)?;

        let item = self.store.get_key_by_fingerprint(&fingerprint).await?;
        if let Some(item) = item {
            return Ok(KeyV2 { item });
        }

        let public = raw.export_public_ssh()?;
        let private = raw.export_private_pem()?;
        let meta = KeyMeta {
            public,
            fingerprint,
        };
        let private = KeyPrivate::Managed {
            private
        };

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

        let item = crate::store::models::v2::KeyItem {
            id: 0,
            name,
            source: KeySource::Managed,
            key_type,
            group_id,
            meta,
            private,
        };

        self.store.add_key(group_id.unwrap_or(1), &item).await?;

        Ok(KeyV2 {
            item
        })
    }

    pub async fn generate_managed(&mut self, param: GenerateParam, comment: Option<String>) -> Result<RawKey> {
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

    /// add raw ssh key into keyd store, return wrapped database item and origin `RawKey`
    pub async fn add(
        &mut self,
        group_id: Option<i64>,
        name: Option<impl AsRef<str>>,
        key: RawKey,
    ) -> Result<KeyV2> {
        let fingerprint = key.fingerprint(HashType::SHA256)?;

        let item = self.store.get_key_by_fingerprint(&fingerprint).await?;
        if let Some(item) = item {
            return Ok(KeyV2 { item });
        }

        let public = key.export_public_ssh()?;
        let private = key.export_private_pem()?;
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
            source: KeySource::Managed,
            key_type,
            group_id,
            meta: KeyMeta {
                public,
                fingerprint
            },
            private: KeyPrivate::Managed {
                private
            }
        };

        self.store.add_key(group_id.unwrap_or(1), &item).await?;

        Ok(KeyV2 { item })
    }

    /// remove key with id from keyd store
    pub async fn remove(&mut self, id: i64) -> Result<()> {
        self.store.remove_key(id).await?;
        Ok(())
    }

    pub fn clear(&mut self) {
        todo!()
    }

    pub async fn get_all(&self) -> Result<Vec<KeyV2>> {
        let keys: Vec<_> = self
            .store
            .list_keys()
            .await?
            .into_iter()
            .map(|it| KeyV2 { item: it })
            .collect();

        Ok(keys)
    }

    /// get keys in group id
    pub async fn list_group_keys(&self, id: i64) -> Result<Vec<KeyV2>> {
        let keys: Vec<_> = self
            .store
            .list_group_keys(id)
            .await?
            .into_iter()
            .map(|it| KeyV2 { item: it } )
            .collect();

        Ok(keys)
    }

    /// get ssh key by SHA256 fingerprint
    pub async fn get(&self, fingerprint: &str) -> Result<KeyV2> {
        let item = self
            .store
            .get_key_by_fingerprint(fingerprint)
            .await?
            .ok_or(Error::KeyNotfound)?;
        Ok(KeyV2 { item })
    }

    /// create a key group
    pub async fn create_group(&self, name: impl AsRef<str>) -> Result<i64> {
        Ok(self.store.create_group(name).await?)
    }

    /// delete a key group by id
    pub async fn delete_group(&self, id: i64) -> Result<()> {
        Ok(self.store.delete_group(id).await?)
    }

    /// rename a key group to `new_name`
    pub async fn rename_group(&self, id: i64, new_name: impl AsRef<str>) -> Result<()> {
        Ok(self.store.rename_group(id, new_name).await?)
    }

    /// get all groups
    pub async fn list_groups(&self) -> Result<Vec<KeyGroup>> {
        Ok(self.store.list_groups().await?)
    }
}

/// map database `KeyItem` to `libsshkey::key::Key`
// fn item_to_raw(item: &KeyItem) -> Result<RawKey> {
//     let key = match item.key_type {
//         KeyType::Rsa => RawKey::Rsa(Rsa::import_private_pem(&item.private, None::<&str>)?),
//         KeyType::EcdsaP256 => {
//             RawKey::EcdsaP256(Ecdsa::import_private_pem(&item.private_key, None::<&str>)?)
//         }
//         KeyType::EcdsaP384 => {
//             RawKey::EcdsaP384(Ecdsa::import_private_pem(&item.private_key, None::<&str>)?)
//         }
//         KeyType::EcdsaP521 => {
//             RawKey::EcdsaP521(Ecdsa::import_private_pem(&item.private_key, None::<&str>)?)
//         }
//         _ => unimplemented!(),
//     };
//
//     Ok(key)
// }


impl KeyV2 {
    pub fn sign(&self, data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        todo!()
    }
}