use crate::error::Result;
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions, sqlite::SqliteConnectOptions};
use std::str::FromStr;

mod models;

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
}