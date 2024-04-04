use redb::{CommitError, StorageError, TableError, TransactionError};
use redis::RedisError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("deserialization err: {0}")]
    Deser(#[from] serde_json::Error),
    #[error(transparent)]
    ReDB(#[from] redb::Error),
    #[error("{0}")]
    Redis(#[from] RedisError),
    #[error("{0}")]
    Bb8(#[from] bb8::RunError<RedisError>),
}

impl From<CommitError> for Error {
    fn from(e: CommitError) -> Self {
        Error::ReDB(e.into())
    }
}

impl From<TransactionError> for Error {
    fn from(e: TransactionError) -> Self {
        Error::ReDB(e.into())
    }
}

impl From<StorageError> for Error {
    fn from(e: StorageError) -> Self {
        Error::ReDB(e.into())
    }
}

impl From<TableError> for Error {
    fn from(e: TableError) -> Self {
        Error::ReDB(e.into())
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
