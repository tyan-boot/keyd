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

    pub group_id: Option<i64>,
}