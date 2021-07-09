use std::fmt::{Display, Formatter};

use libsshkey::key::Key as RawKey;

mod v2 {
    use crate::store::models::KeyType;

    #[derive(Copy, Clone, Debug)]
    pub enum KeySource {
        Managed,
        ExternPKCS11,
        ExternTPM,
    }

    #[derive(Clone, Debug)]
    pub struct KeyMeta {
        pub public: String,
        pub fingerprint: String,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum KeyPrivate {
        Managed {
            private: String,
        },
        ExternPKCS11,
        ExternTPM,
    }

    #[derive(Clone, Debug)]
    pub struct KeyItem {
        pub id: i64,
        pub name: String,
        pub meta: KeyMeta,
        pub private: KeyPrivate,
        pub source: KeySource,
        pub key_type: KeyType,
        pub group_id: Option<i64>,
    }
}

#[derive(Debug, Clone, sqlx::FromRow, Eq, PartialEq)]
pub struct KeyGroup {
    pub id: i64,
    pub name: String,
}

#[derive(Debug, Clone, sqlx::FromRow, Eq, PartialEq)]
pub struct KeyItem {
    pub id: i64,
    pub name: String,
    pub fingerprint: String,
    pub public_key: String,
    pub private_key: String,
    pub key_type: KeyType,

    pub group_id: Option<i64>,
}

#[derive(Debug, Clone, Eq, PartialEq, Copy, sqlx::Type)]
#[sqlx(rename_all = "lowercase")]
pub enum KeyType {
    Rsa,
    Dss,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
}

impl Display for KeyType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::Rsa => write!(f, "rsa"),
            KeyType::Dss => write!(f, "dss"),
            KeyType::EcdsaP256 => write!(f, "ecdsa-p256"),
            KeyType::EcdsaP384 => write!(f, "ecdsa-p384"),
            KeyType::EcdsaP521 => write!(f, "ecdsa-p521"),
        }
    }
}

#[derive(Debug)]
pub struct Key {
    pub item: KeyItem,
    pub raw: RawKey,
}
