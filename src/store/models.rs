use libsshkey::key::Key as RawKey;

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

#[derive(Debug)]
pub struct Key {
    pub item: KeyItem,
    pub raw: RawKey,
}
