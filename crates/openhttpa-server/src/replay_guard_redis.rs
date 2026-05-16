// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

use async_trait::async_trait;
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

#[async_trait]
impl DistributedReplayGuard for RedisReplayGuard {
    /// Atomically check and record `nonce` in a single `SET NX PX` round-trip.
    ///
    /// This is the only method that should be called in hot-path request
    /// processing. It eliminates the TOCTOU race of a separate check + accept
    /// pair by delegating the entire decision to a Redis atomic command.
    async fn check_and_accept(&self, key: &str, nonce: u64) -> Result<(), ReplayError> {
        let start = std::time::Instant::now();
        let inserted = self.set_nx(key, nonce).await?;
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
    }

    /// Read-only existence probe. Does **not** commit the nonce.
    ///
    /// Not suitable for request authentication — use `check_and_accept` instead.
    async fn check(&self, key: &str, nonce: u64) -> Result<(), ReplayError> {
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
    }

    /// Unconditionally record `nonce` (no prior existence check).
    ///
    /// Not suitable for request authentication — use `check_and_accept` instead.
    async fn accept(&self, key: &str, nonce: u64) -> Result<(), ReplayError> {
        self.set_nx(key, nonce).await.map(|_| ())
    }
}
