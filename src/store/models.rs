use std::fmt::{Display, Formatter};

use libsshkey::key::Key as RawKey;

pub mod v2 {
    use serde::{Deserialize, Serialize};
    use sqlx::{Database, Error, FromRow, Row, Type, Value, ValueRef};
    use sqlx::database::{HasValueRef, HasArguments};
    use sqlx::decode::Decode;
    use sqlx::error::BoxDynError;

    use crate::store::models::KeyType;
    use sqlx::encode::{Encode, IsNull};

    #[derive(Debug, Clone, Eq, PartialEq, Copy, sqlx::Type)]
    #[sqlx(rename_all = "lowercase")]
    pub enum KeySource {
        Managed,
        ExternPKCS11,
        ExternTPM,
    }

    #[derive(Clone, Debug, sqlx::Type, Serialize, Deserialize)]
    pub struct KeyMeta {
        pub public: String,
        pub fingerprint: String,
    }

    impl<DB: Database> Type<DB> for KeyMeta
        where String: Type<DB> {
        fn type_info() -> <DB as Database>::TypeInfo {
            <String as Type<DB>>::type_info()
        }
    }

    impl<'r, DB: Database> Decode<'r, DB> for KeyMeta
        where &'r str: Decode<'r, DB> + Type<DB> {
        fn decode(value: <DB as HasValueRef<'r>>::ValueRef) -> Result<Self, BoxDynError> {
            let v = <&'r str as Decode<'r, DB>>::decode(value)?;
            let this: KeyMeta = serde_json::from_str(v)?;
            Ok(this)
        }
    }

    impl <'q, DB: Database> Encode<'q, DB> for KeyMeta
    where String : Encode<'q, DB> + Type<DB> {
        fn encode_by_ref(&self, buf: &mut <DB as HasArguments<'q>>::ArgumentBuffer) -> IsNull {
            let this = serde_json::to_string(&self);
            match this {
                Ok(this) => {
                    this.encode_by_ref(buf)
                },
                Err(_) => {
                    IsNull::No
                }
            }
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum KeyPrivate {
        Managed {
            private: String,
        },
        ExternPKCS11,
        ExternTPM,
    }

    impl<DB: Database> Type<DB> for KeyPrivate
        where String: Type<DB> {
        fn type_info() -> <DB as Database>::TypeInfo {
            <String as Type<DB>>::type_info()
        }
    }

    impl<'r, DB: Database> Decode<'r, DB> for KeyPrivate
        where &'r str: Decode<'r, DB> + Type<DB> {
        fn decode(value: <DB as HasValueRef<'r>>::ValueRef) -> Result<Self, BoxDynError> {
            let v = <&'r str as Decode<'r, DB>>::decode(value)?;
            let this: KeyPrivate = serde_json::from_str(v)?;
            Ok(this)
        }
    }

    impl <'q, DB: Database> Encode<'q, DB> for KeyPrivate
        where String : Encode<'q, DB> + Type<DB> {
        fn encode_by_ref(&self, buf: &mut <DB as HasArguments<'q>>::ArgumentBuffer) -> IsNull {
            let this = serde_json::to_string(&self);
            match this {
                Ok(this) => {
                    this.encode_by_ref(buf)
                },
                Err(_) => {
                    IsNull::No
                }
            }
        }
    }

    #[derive(Clone, Debug, sqlx::FromRow)]
    pub struct KeyItem {
        pub id: i64,
        pub name: String,
        pub source: KeySource,
        pub key_type: KeyType,
        pub group_id: Option<i64>,

        pub meta: KeyMeta,
        pub private: KeyPrivate,
    }
    //
    // impl <'r, R: Row> FromRow<'r, R> for KeyItem {
    //     fn from_row(row: &'r R) -> Result<Self, Error> {
    //         let id = row.try_get("id")?;
    //         let name = row.try_get("name")?;
    //         let source = row.try_get("source")?;
    //         let key_type = row.try_get("key_type")?;
    //         let group_id = row.try_get("group_id")?;
    //
    //         let meta = row.try_get("meta")
    //     }
    // }
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
