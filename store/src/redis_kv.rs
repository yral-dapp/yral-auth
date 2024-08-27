use bb8_redis::RedisConnectionManager;
use redis::{AsyncCommands, RedisError};

use super::{KVStore, Result};

#[derive(Clone)]
pub struct RedisKV(bb8::Pool<RedisConnectionManager>);

impl RedisKV {
    pub async fn new(redis_url: &str) -> Result<Self, bb8::RunError<RedisError>> {
        let manager = RedisConnectionManager::new(redis_url)?;
        Ok(Self(bb8::Pool::builder().build(manager).await?))
    }
}

const AUTH_FIELD: &str = "auth";
const METADATA_FIELD: &str = "metadata";

impl KVStore for RedisKV {
    async fn read(&self, key: String) -> Result<Option<String>> {
        let mut con = self.0.get().await?;
        let value: Option<String> = con.hget(key, AUTH_FIELD).await?;
        Ok(value)
    }

    async fn read_metadata<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        key: String,
    ) -> Result<Option<T>> {
        let mut con = self.0.get().await?;
        let raw_value: Option<Box<[u8]>> = con.hget(key, METADATA_FIELD).await?;
        let meta = if let Some(meta_raw) = raw_value {
            Some(serde_json::from_slice(&meta_raw)?)
        } else {
            None
        };
        Ok(meta)
    }

    async fn write(&self, key: String, value: String) -> Result<()> {
        let mut con = self.0.get().await?;
        con.hset::<_, _, _, ()>(key, AUTH_FIELD, value).await?;
        Ok(())
    }

    async fn write_metdata<T: serde::Serialize + Send + 'static>(
        &self,
        key: String,
        metadata: T,
    ) -> Result<()> {
        let mut con = self.0.get().await?;
        let meta_raw = serde_json::to_vec(&metadata)?;
        let _replaced: bool = con.hset(key, METADATA_FIELD, meta_raw).await?;
        Ok(())
    }
}
