#[derive(Debug, Clone)]
pub struct KeyGroup {
    pub id: i64,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct KeyItem {
    id: i64,
    name: String,
    fingerprint: String,
    public_key: String,
    private_key: String,

    group_id: Option<i64>,
}