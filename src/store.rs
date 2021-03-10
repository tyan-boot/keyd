use std::str::FromStr;

use sqlx::{sqlite::SqliteConnectOptions, sqlite::SqlitePoolOptions, SqlitePool};

use crate::store::models::{KeyGroup, KeyItem};

mod models;

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
}

type Result<T, E = StoreError> = std::result::Result<T, E>;

pub(crate) struct KeyStore {
    pool: SqlitePool
}

impl KeyStore {
    pub async fn new(url: impl AsRef<str>) -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .connect_with(SqliteConnectOptions::from_str(url.as_ref())?.create_if_missing(true))
            .await?;

        Ok(KeyStore {
            pool
        })
    }

    pub async fn init(&self) -> Result<()> {
        const INIT_SQL: &'static str = r#"
            create table if not exists db_version (
                version   integer
            );

            create table if not exists key_groups (
                id        integer primary key autoincrement,
                name      text
            );

            create table if not exists key_items (
                id             integer primary key autoincrement,
                name           text,
                fingerprint    text,
                public_key     text,
                private_key    text,
                group_id       integer
            );
        "#;

        let _ = sqlx::query(INIT_SQL).execute(&self.pool).await?;

        Ok(())
    }

    pub async fn create_group(&self, name: impl AsRef<str>) -> Result<i64> {
        const SQL: &'static str = r#"
            insert into key_groups (name) values (?);
        "#;

        let r = sqlx::query(SQL).bind(name.as_ref()).execute(&self.pool).await?;

        Ok(r.last_insert_rowid())
    }

    pub async fn delete_group(&self, id: i64) -> Result<()> {
        const Q_SQL: &'static str = r#"
            select count(1) from key_items where group_id = ?;
        "#;
        const DEL_SQL: &'static str = r#"
            delete from key_groups where id = ?;
        "#;

        let (items, ) = sqlx::query_as::<_, (i64, )>(Q_SQL).bind(id).fetch_one(&self.pool).await?;
        if items != 0 {
            return Err(StoreError::GroupNotEmpty);
        }

        let _ = sqlx::query(DEL_SQL).bind(id).execute(&self.pool).await?;

        Ok(())
    }

    pub async fn rename_group(&self, id: i64, new_name: impl AsRef<str>) -> Result<()> {
        const SQL: &'static str = r#"
            update key_groups set name = ? where id = ?;
        "#;

        let _ = sqlx::query(SQL).bind(new_name.as_ref()).bind(id).execute(&self.pool).await?;

        Ok(())
    }

    pub async fn list_groups(&self) -> Result<Vec<KeyGroup>> {
        const SQL: &'static str = r#"
            select id, name from key_groups;
        "#;

        let results = sqlx::query_as(SQL).fetch_all(&self.pool).await?;

        Ok(results)
    }

    pub async fn get_group(&self, id: i64) -> Result<Option<KeyGroup>> {
        const SQL: &'static str = r#"
            select id, name from key_groups where id = ?;
        "#;

        let group = sqlx::query_as(SQL).fetch_optional(&self.pool).await?;

        Ok(group)
    }
}

impl KeyStore {
    pub async fn add_key(&self, group_id: i64, key: &KeyItem) -> Result<()> {
        const SQL: &'static str = r#"
            insert into key_items (name, fingerprint, public_key, private_key, group_id) (?, ?, ?, ?, ?);
        "#;

        let _ = sqlx::query(SQL)
            .bind(&key.name)
            .bind(&key.fingerprint)
            .bind(&key.public_key)
            .bind(&key.private_key)
            .bind(&key.group_id.unwrap_or_default())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn remove_key(&self, id: i64) -> Result<()> {
        const SQL: &'static str = r#"
            delete from key_items where id = ?;
        "#;

        let _ = sqlx::query(SQL)
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn change_group(&self, key_id: i64, group_id: i64) -> Result<()> {
        const SQL: &'static str = r#"
            update key_items set group_id = ? where id = ?;
        "#;

        let _group = self.get_group(group_id).await?.ok_or(StoreError::GroupIdNotExist(group_id))?;

        let _ = sqlx::query(SQL)
            .bind(group_id)
            .bind(key_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn update_key(&self, id: i64, key: &KeyItem) -> Result<()> {
        const Q_SQL: &'static str = r#"
            select count(1) from key_items where id = ?;
        "#;
        const SQL: &'static str = r#"
            update key_items set
              name = ?,
              fingerprint = ?,
              public_key = ?,
              private_key = ?,
              group_id = ?
            where id = ?;
        "#;
        let (count, ) = sqlx::query_as::<_, (i64, )>(Q_SQL).bind(id).fetch_one(&self.pool).await?;
        if count != 1 {
            return Err(StoreError::KeyIdNotExist(id));
        }

        let _ = sqlx::query(SQL).bind(&key.name)
            .bind(&key.fingerprint)
            .bind(&key.public_key)
            .bind(&key.private_key)
            .bind(key.group_id.unwrap_or_default())
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn list_group_keys(&self, id: i64) -> Result<Vec<KeyItem>> {
        const SQL: &'static str = r#"
            select id, name, fingerprint, public_key, private_key, group_id from key_items where group_id = ?;
        "#;

        let results = sqlx::query_as(SQL)
            .bind(id)
            .fetch_all(&self.pool)
            .await?;

        Ok(results)
    }

    pub async fn list_keys(&self) -> Result<Vec<KeyItem>> {
        const SQL: &'static str = r#"
            select id, name, fingerprint, public_key, private_key, group_id from key_items;
        "#;

        let results = sqlx::query_as(SQL)
            .fetch_all(&self.pool)
            .await?;

        Ok(results)
    }

    pub async fn get_key_by_name(&self, name: impl AsRef<str>) -> Result<KeyItem> {
        todo!()
    }
    pub async fn get_key_by_fingerprint(&self, fingerprint: impl AsRef<str>) -> Result<KeyItem> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use anyhow::Result;

    use crate::store::KeyStore;
    use crate::store::models::KeyGroup;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn group_ops() -> Result<()> {
        let store = KeyStore::new("sqlite::memory:").await?;
        store.init().await?;

        let id_delete = store.create_group("group1").await?;
        let id_rename = store.create_group("group2").await?;
        let id3 = store.create_group("group3").await?;

        store.rename_group(id_rename, "group22").await?;
        store.delete_group(id_delete).await?;

        let mut groups = store.list_groups().await?;
        groups.sort_by(|lhs, rhs| lhs.id.cmp(&rhs.id));

        assert_eq!(groups, vec![
            KeyGroup {
                id: id_rename,
                name: "group22".into(),
            },
            KeyGroup {
                id: id3,
                name: "group3".into(),
            }
        ]);

        Ok(())
    }
}