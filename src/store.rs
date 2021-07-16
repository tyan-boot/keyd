use crate::store::models::KeyGroup;
use crate::store::models::KeyItem;

pub mod models;
pub mod sqlite;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("{}", _0)]
    Generic(#[from] sqlx::Error),

    #[error("cannot delete group not empty")]
    GroupNotEmpty,

    #[error("group id {} not exist", _0)]
    GroupIdNotExist(i64),

    #[error("key id {} not exist", _0)]
    KeyIdNotExist(i64),

    #[error("serde json: {}", _0)]
    SerdeJsonError(#[from] serde_json::Error),
}

type Result<T, E = StoreError> = std::result::Result<T, E>;

#[async_trait::async_trait]
pub trait KeyStore: Sync + Send {
    async fn create_group(&self, name: &str) -> Result<i64>;
    async fn delete_group(&self, id: i64) -> Result<()>;
    async fn rename_group(&self, id: i64, new_name: &str) -> Result<()>;
    async fn list_groups(&self) -> Result<Vec<KeyGroup>>;
    async fn get_group(&self, id: i64) -> Result<Option<KeyGroup>>;

    async fn add_key(&self, group_id: i64, key: &KeyItem) -> Result<i64>;
    async fn remove_key(&self, id: i64) -> Result<()>;
    async fn change_group(&self, key_id: i64, group_id: i64) -> Result<()>;
    async fn update_key(&self, id: i64, key: &KeyItem) -> Result<()>;
    async fn list_group_keys(&self, id: i64) -> Result<Vec<KeyItem>>;
    async fn list_keys(&self) -> Result<Vec<KeyItem>>;
    async fn get_key(&self, id: i64) -> Result<Option<KeyItem>>;
    async fn get_key_by_name(&self, name: &str) -> Result<Option<KeyItem>>;
    async fn get_key_by_fingerprint(&self, fingerprint: &str) -> Result<Option<KeyItem>>;
}
//
// #[cfg(test)]
// mod test {
//     use anyhow::Result;
//
//     use crate::store::models::KeyGroup;
//     use crate::store::KeyStore;
//     use crate::store::models::v2::{KeyItem, KeySource, KeyMeta, KeyPrivate};
//     use crate::store::models::KeyType;
//
//     #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
//     async fn group_ops() -> Result<()> {
//         let store = KeyStore::new("sqlite::memory:").await?;
//         store.init().await?;
//
//         let id_delete = store.create_group("group1").await?;
//         let id_rename = store.create_group("group2").await?;
//         let id3 = store.create_group("group3").await?;
//
//         store.rename_group(id_rename, "group22").await?;
//         store.delete_group(id_delete).await?;
//
//         let mut groups = store.list_groups().await?;
//         groups.sort_by(|lhs, rhs| lhs.id.cmp(&rhs.id));
//
//         assert_eq!(
//             groups,
//             vec![
//                 KeyGroup {
//                     id: id_rename,
//                     name: "group22".into(),
//                 },
//                 KeyGroup {
//                     id: id3,
//                     name: "group3".into(),
//                 }
//             ]
//         );
//
//         Ok(())
//     }
//
//     #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
//     async fn keys_ops() -> Result<()> {
//         let store = super::KeyStore::new("sqlite::key2.db").await?;
//         store.init().await?;
//         let key_item = KeyItem {
//             id: 0,
//             name: "11111".to_string(),
//             source: KeySource::Managed,
//             key_type: KeyType::Rsa,
//             group_id: Some(1),
//             meta: KeyMeta { public: "11".to_string(), fingerprint: "222".to_string() },
//             private: KeyPrivate::ExternPKCS11
//         };
//
//         store.add_key(1, &key_item).await?;
//
//         Ok(())
//     }
// }
