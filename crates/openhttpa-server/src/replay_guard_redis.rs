// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use openhttpa_core::replay_guard::{DistributedReplayGuard, ReplayError};
use redis::AsyncCommands;
use std::time::Duration;

/// A Redis-backed implementation of `DistributedReplayGuard`.
///
/// All replay decisions are made with a **single** `SET NX PX` round-trip,
/// eliminating the TOCTOU race that would exist if check and accept were
/// separate operations (SEC-03).
pub struct RedisReplayGuard {
    client: redis::Client,
    ttl: Duration,
}

impl RedisReplayGuard {
    /// Create a new Redis-backed replay guard.
    ///
    /// # Errors
    /// Returns a Redis error if the client could not be created.
    pub fn new(url: &str, ttl: Duration) -> redis::RedisResult<Self> {
        let client = redis::Client::open(url)?;
        Ok(Self { client, ttl })
    }

    /// Internal helper: single atomic `SET NX PX` round-trip.
    async fn set_nx(&self, key: &str, nonce: u64) -> Result<bool, ReplayError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| ReplayError::StorageError(e.to_string()))?;
        let redis_key = format!("replay:{key}:{nonce}");
        let ttl_ms = u64::try_from(self.ttl.as_millis()).unwrap_or(u64::MAX);
        let result: Option<String> = redis::cmd("SET")
            .arg(&redis_key)
            .arg(1u8)
            .arg("NX")
            .arg("PX")
            .arg(ttl_ms)
            .query_async(&mut conn)
            .await
            .map_err(|e| ReplayError::StorageError(e.to_string()))?;
        // SET NX returns "OK" on insert, None when the key already existed.
        Ok(result.is_some())
    }
}

impl DistributedReplayGuard for RedisReplayGuard {
    /// Atomically check and record `nonce` in a single `SET NX PX` round-trip.
    ///
    /// This is the only method that should be called in hot-path request
    /// processing. It eliminates the TOCTOU race of a separate check + accept
    /// pair by delegating the entire decision to a Redis atomic command.
    fn check_and_accept(
        &self,
        key: &str,
        nonce: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ReplayError>> + Send + '_>>
    {
        let key = key.to_string();
        Box::pin(async move {
            let start = std::time::Instant::now();
            let inserted = self.set_nx(&key, nonce).await?;
            // [Security Mitigation: Constant-Time Delay]
            // Pad to a minimum latency so response timing does not reveal whether
            // the key pre-existed (i.e. this was a replay).
            let target = Duration::from_millis(2);
            if let Some(delay) = target.checked_sub(start.elapsed()) {
                tokio::time::sleep(delay).await;
            }
            if inserted {
                Ok(())
            } else {
                Err(ReplayError::Replay(nonce))
            }
        })
    }

    /// Read-only existence probe. Does **not** commit the nonce.
    ///
    /// Not suitable for request authentication — use `check_and_accept` instead.
    fn check(
        &self,
        key: &str,
        nonce: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ReplayError>> + Send + '_>>
    {
        let key = key.to_string();
        Box::pin(async move {
            let mut conn = self
                .client
                .get_multiplexed_async_connection()
                .await
                .map_err(|e| ReplayError::StorageError(e.to_string()))?;
            let redis_key = format!("replay:{key}:{nonce}");
            let exists: bool = conn
                .exists(redis_key)
                .await
                .map_err(|e| ReplayError::StorageError(e.to_string()))?;
            if exists {
                Err(ReplayError::Replay(nonce))
            } else {
                Ok(())
            }
        })
    }

    /// Unconditionally record `nonce` (no prior existence check).
    ///
    /// Not suitable for request authentication — use `check_and_accept` instead.
    fn accept(
        &self,
        key: &str,
        nonce: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ReplayError>> + Send + '_>>
    {
        let key = key.to_string();
        Box::pin(async move { self.set_nx(&key, nonce).await.map(|_| ()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redis_guard_new_valid_url() {
        let guard = RedisReplayGuard::new("redis://127.0.0.1/", Duration::from_secs(60));
        assert!(guard.is_ok());
    }

    #[test]
    fn test_redis_guard_new_invalid_url() {
        let guard = RedisReplayGuard::new("not-a-redis-url", Duration::from_secs(60));
        assert!(guard.is_err());
    }

    #[tokio::test]
    async fn test_redis_guard_connection_failure() {
        // Use a port that is guaranteed not to have a redis server running.
        let guard =
            RedisReplayGuard::new("redis://127.0.0.1:65535/", Duration::from_secs(60)).unwrap();

        let result = guard.check_and_accept("test_key", 1).await;
        assert!(matches!(result, Err(ReplayError::StorageError(_))));

        let check_result = guard.check("test_key", 1).await;
        assert!(matches!(check_result, Err(ReplayError::StorageError(_))));

        let accept_result = guard.accept("test_key", 1).await;
        assert!(matches!(accept_result, Err(ReplayError::StorageError(_))));
    }
}
