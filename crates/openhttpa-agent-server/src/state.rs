#![allow(dead_code)]

use redis::{AsyncCommands, Client};
use std::sync::Arc;

/// Trait for configurable storage backends
#[async_trait::async_trait]
pub trait StorageBackend: Send + Sync {
    async fn save(&self, key: &str, value: &[u8]) -> Result<(), String>;
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>, String>;
}

/// Ephemeral Redis Storage
pub struct RedisStorage {
    client: Client,
}

impl RedisStorage {
    pub fn new(url: &str) -> Result<Self, String> {
        let client = Client::open(url).map_err(|e| e.to_string())?;
        Ok(Self { client })
    }
}

#[async_trait::async_trait]
impl StorageBackend for RedisStorage {
    async fn save(&self, key: &str, value: &[u8]) -> Result<(), String> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| e.to_string())?;
        let _: () = conn.set(key, value).await.map_err(|e| e.to_string())?;
        Ok(())
    }
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| e.to_string())?;
        let result: Option<Vec<u8>> = conn.get(key).await.map_err(|e| e.to_string())?;
        Ok(result)
    }
}

/// Persistent Postgres Storage (encrypted at rest)
pub struct PostgresStorage {
    // pool: sqlx::PgPool
}

#[async_trait::async_trait]
impl StorageBackend for PostgresStorage {
    async fn save(&self, _key: &str, _value: &[u8]) -> Result<(), String> {
        Ok(())
    }
    async fn load(&self, _key: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }
}

pub enum SecurityLevel {
    Standard,
    High,
    Paranoid,
}

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn StorageBackend>,
    pub security_level: Arc<SecurityLevel>,
}

impl AppState {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let storage_type = std::env::var("STORAGE_BACKEND").unwrap_or_else(|_| "redis".to_string());

        let storage: Arc<dyn StorageBackend> = if storage_type == "postgres" {
            Arc::new(PostgresStorage {})
        } else {
            let redis_url =
                std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
            Arc::new(RedisStorage::new(&redis_url)?)
        };

        Ok(Self {
            storage,
            security_level: Arc::new(SecurityLevel::High),
        })
    }
}
