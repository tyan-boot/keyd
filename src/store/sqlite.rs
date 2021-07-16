use super::{KeyStore, Result, StoreError};
use crate::store::models::KeyGroup;
use crate::store::models::KeyItem;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    pub async fn new(url: impl AsRef<str>) -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .connect_with(SqliteConnectOptions::from_str(url.as_ref())?.create_if_missing(true))
            .await?;

        Ok(SqliteStore { pool })
    }

    /// init store
    /// create sqlite tables
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
                source         text,
                key_type       text,
                group_id       integer,

                meta           json,
                private        json
            );
        "#;

        let _ = sqlx::query(INIT_SQL).execute(&self.pool).await?;

        {
            // init default group
            const Q_SQL: &'static str = r#"
                select count(1) from key_groups where id = 1;
            "#;
            const C_SQL: &'static str = r#"
                insert into key_groups (name) values ('default');
            "#;
            let (count,) = sqlx::query_as::<_, (i64,)>(Q_SQL)
                .fetch_one(&self.pool)
                .await?;
            if count == 0 {
                let _ = sqlx::query(C_SQL).execute(&self.pool).await?;
            }
        }
        Ok(())
    }
}

/// group operations
#[async_trait::async_trait]
impl KeyStore for SqliteStore {
    /// create key group
    async fn create_group(&self, name: &str) -> Result<i64> {
        const SQL: &'static str = r#"
            insert into key_groups (name) values (?);
        "#;

        let r = sqlx::query(SQL).bind(name).execute(&self.pool).await?;

        Ok(r.last_insert_rowid())
    }

    /// delete key group by id
    /// group must be empty
    async fn delete_group(&self, id: i64) -> Result<()> {
        const Q_SQL: &'static str = r#"
            select count(1) from key_items where group_id = ?;
        "#;
        const DEL_SQL: &'static str = r#"
            delete from key_groups where id = ?;
        "#;

        let (items,) = sqlx::query_as::<_, (i64,)>(Q_SQL)
            .bind(id)
            .fetch_one(&self.pool)
            .await?;
        if items != 0 {
            return Err(StoreError::GroupNotEmpty);
        }

        let _ = sqlx::query(DEL_SQL).bind(id).execute(&self.pool).await?;

        Ok(())
    }

    /// rename a group to new name
    async fn rename_group(&self, id: i64, new_name: &str) -> Result<()> {
        const SQL: &'static str = r#"
            update key_groups set name = ? where id = ?;
        "#;

        let _ = sqlx::query(SQL)
            .bind(new_name)
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// get all groups
    async fn list_groups(&self) -> Result<Vec<KeyGroup>> {
        const SQL: &'static str = r#"
            select id, name from key_groups;
        "#;

        let results = sqlx::query_as(SQL).fetch_all(&self.pool).await?;

        Ok(results)
    }

    /// get group by id
    async fn get_group(&self, id: i64) -> Result<Option<KeyGroup>> {
        const SQL: &'static str = r#"
            select id, name from key_groups where id = ?;
        "#;

        let group = sqlx::query_as(SQL)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(group)
    }

    /// add `crate::store::models::KeyItem` to store
    /// return id
    async fn add_key(&self, group_id: i64, key: &KeyItem) -> Result<i64> {
        const SQL: &'static str = r#"
            insert into key_items
            (name, source, key_type, group_id, meta, private)
            values (?, ?, ?, ?, ?, ?);
        "#;

        let r = sqlx::query(SQL)
            .bind(&key.name)
            .bind(&key.source)
            .bind(&key.key_type)
            .bind(group_id)
            .bind(&key.meta)
            .bind(&key.private)
            .execute(&self.pool)
            .await?;

        Ok(r.last_insert_rowid())
    }

    /// remove `KeyItem` from store by id
    async fn remove_key(&self, id: i64) -> Result<()> {
        const SQL: &'static str = r#"
            delete from key_items where id = ?;
        "#;

        let _ = sqlx::query(SQL).bind(id).execute(&self.pool).await?;

        Ok(())
    }

    /// move `KeyItem` to new group
    /// new group must exist
    async fn change_group(&self, key_id: i64, group_id: i64) -> Result<()> {
        const SQL: &'static str = r#"
            update key_items set group_id = ? where id = ?;
        "#;

        let _group = self
            .get_group(group_id)
            .await?
            .ok_or(StoreError::GroupIdNotExist(group_id))?;

        let _ = sqlx::query(SQL)
            .bind(group_id)
            .bind(key_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// **overwrite** an old `KeyItem` with new one
    async fn update_key(&self, id: i64, key: &KeyItem) -> Result<()> {
        const Q_SQL: &'static str = r#"
            select count(1) from key_items where id = ?;
        "#;
        const SQL: &'static str = r#"
            update key_items set
              name = ?,
              source = ?,
              key_type = ?,
              group_id = ?,

              meta = ?,
              private = ?
            where id = ?;
        "#;
        let (count,) = sqlx::query_as::<_, (i64,)>(Q_SQL)
            .bind(id)
            .fetch_one(&self.pool)
            .await?;
        if count != 1 {
            return Err(StoreError::KeyIdNotExist(id));
        }

        let _ = sqlx::query(SQL)
            .bind(&key.name)
            .bind(&key.source)
            .bind(&key.key_type)
            .bind(key.group_id.unwrap_or_default())
            .bind(&key.meta)
            .bind(&key.private)
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// get keys in group
    async fn list_group_keys(&self, id: i64) -> Result<Vec<KeyItem>> {
        const SQL: &'static str = r#"
            select id, name, source, key_type, group_id, meta, private from key_items where group_id = ?;
        "#;

        let results = sqlx::query_as(SQL).bind(id).fetch_all(&self.pool).await?;

        Ok(results)
    }

    /// get all keys
    async fn list_keys(&self) -> Result<Vec<KeyItem>> {
        const SQL: &'static str = r#"
            select id, name, source, key_type, group_id, meta, private from key_items;
        "#;

        let results = sqlx::query_as(SQL).fetch_all(&self.pool).await?;

        Ok(results)
    }

    /// get key by name
    async fn get_key_by_name(&self, name: &str) -> Result<Option<KeyItem>> {
        const SQL: &'static str = r#"
            select id, name, source, key_type, group_id, meta, private from key_items where name = ?;
        "#;

        let key = sqlx::query_as(SQL)
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        Ok(key)
    }

    /// get key by fingerprint, default sha256
    async fn get_key_by_fingerprint(&self, fingerprint: &str) -> Result<Option<KeyItem>> {
        const SQL: &'static str = r#"
            select id, name, source, key_type, group_id, meta, private from key_items
            where json_extract(meta, '$.fingerprint') = ?;
        "#;

        let key = sqlx::query_as(SQL)
            .bind(fingerprint)
            .fetch_optional(&self.pool)
            .await?;
        Ok(key)
    }
}
