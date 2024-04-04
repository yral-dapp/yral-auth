use std::sync::Arc;

use redb::{Database, TableDefinition};
use serde::{de::DeserializeOwned, Serialize};
use tokio::task::spawn_blocking;

use super::{KVStore, Result};

const TABLE: TableDefinition<&str, &str> = TableDefinition::new("kv");
const RAW_METADATA_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("kv-meta");

#[derive(Clone)]
pub struct ReDBKV(Arc<Database>);

impl ReDBKV {
    pub fn new() -> Result<Self, redb::Error> {
        let db = Database::create("./redb-kv.db")?;
        let write_txn = db.begin_write()?;
        {
            write_txn.open_table(TABLE)?;
            write_txn.open_table(RAW_METADATA_TABLE)?;
        }
        write_txn.commit()?;
        Ok(Self(Arc::new(db)))
    }

    fn spawn_blocking<F, R>(&self, f: F) -> tokio::task::JoinHandle<Result<R>>
    where
        F: FnOnce(&Database) -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let db = self.0.clone();
        spawn_blocking(move || f(&db))
    }
}

impl KVStore for ReDBKV {
    async fn read(&self, key: String) -> Result<Option<String>> {
        self.spawn_blocking(move |db| {
            let read_txn = db.begin_read()?;
            let value = {
                let table = read_txn.open_table(TABLE)?;
                let v = table.get(key.as_str())?;
                v.map(|ag| ag.value().to_string())
            };
            Ok(value)
        })
        .await
        .unwrap()
    }

    async fn read_metadata<T: DeserializeOwned + Send + 'static>(
        &self,
        key: String,
    ) -> Result<Option<T>> {
        self.spawn_blocking(move |db| {
            let read_txn = db.begin_read()?;
            let raw_value = {
                let table = read_txn.open_table(RAW_METADATA_TABLE)?;
                let v = table.get(key.as_str())?;
                if let Some(ag) = v {
                    let raw_value = ag.value();
                    Some(serde_json::from_slice(raw_value)?)
                } else {
                    None
                }
            };
            Ok(raw_value)
        })
        .await
        .unwrap()
    }

    async fn write(&self, key: String, value: String) -> Result<()> {
        self.spawn_blocking(move |db| {
            let write_txn = db.begin_write()?;
            {
                let mut table = write_txn.open_table(TABLE)?;
                table.insert(key.as_str(), value.as_str())?;
            }
            write_txn.commit()?;
            Ok(())
        })
        .await
        .unwrap()
    }

    async fn write_metdata<T: Serialize + Send + 'static>(
        &self,
        key: String,
        metadata: T,
    ) -> Result<()> {
        self.spawn_blocking(move |db| {
            let write_txn = db.begin_write()?;
            {
                let mut table = write_txn.open_table(RAW_METADATA_TABLE)?;
                let raw_value = serde_json::to_vec(&metadata)?;
                table.insert(key.as_str(), raw_value.as_slice())?;
            }
            write_txn.commit()?;
            Ok(())
        })
        .await
        .unwrap()
    }
}
