use enum_dispatch::enum_dispatch;
use serde::{de::DeserializeOwned, Serialize};
mod error;
pub use error::*;
pub mod redb_kv;
pub mod redis_kv;

#[allow(async_fn_in_trait)]
#[enum_dispatch]
pub trait KVStore: Send {
    async fn read(&self, key: String) -> Result<Option<String>>;
    async fn read_metadata<T: DeserializeOwned + Send + 'static>(
        &self,
        key: String,
    ) -> Result<Option<T>>;

    async fn write(&self, key: String, value: String) -> Result<()>;
    async fn write_metdata<T: Serialize + Send + 'static>(
        &self,
        key: String,
        metadata: T,
    ) -> Result<()>;
}

#[derive(Clone)]
#[enum_dispatch(KVStore)]
pub enum KVStoreImpl {
    ReDB(redb_kv::ReDBKV),
    Redis(redis_kv::RedisKV),
}
