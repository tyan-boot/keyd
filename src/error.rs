use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("ssh key error: {}", _0)]
    LibSSHKey(#[from] libsshkey::error::Error),

    #[error("request key not found")]
    KeyNotfound,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
