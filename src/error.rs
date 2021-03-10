use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("ssh key error: {}", _0)]
    LibSSHKey(#[from] libsshkey::error::Error),

    #[error("request key not found")]
    KeyNotfound,

    #[error("{}", _0)]
    Generic(#[from] anyhow::Error),

    #[error("{}", _0)]
    SqlxError(#[from] sqlx::Error)
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
