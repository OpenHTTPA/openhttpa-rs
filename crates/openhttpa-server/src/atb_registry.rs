// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! In-memory registry for live `OpenHTTPA` Attestation Bases (`AtBs`).
//!
//! An **Attestation Base** (`AtB`) is the session context established after a
//! successful `AtHS` handshake.  It carries the negotiated session keys,
//! expiry time, and the server's TEE attestation quote.
//!
//! The [`AtbRegistry`] is a cheap-to-clone (`Arc`-backed) hash map that maps
//! [`AtbId`] → [`AttestSession`].  Expired sessions are pruned lazily on
//! every [`get`](AtbRegistry::get) call and eagerly by the background
//! eviction task started with [`start_eviction_task`](AtbRegistry::start_eviction_task).
//!
//! ## Thread Safety
//!
//! [`AtbRegistry`] uses a [`DashMap`] internally and is safe to share across
//! async tasks without external locking.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
// Use tracing via absolute paths or import correctly.

use openhttpa_core::session::AttestSession;
use openhttpa_proto::AtbId;

/// Thread-safe registry of live `AttestSession`s, keyed by `AtbId`.
///
/// Expired sessions are lazily evicted on lookup.
#[derive(Clone)]
pub struct AtbRegistry {
    sessions: Arc<DashMap<AtbId, AttestSession>>,
    max_sessions: usize,
    /// Monotonically-tracked live count used for the capacity check.
    ///
    /// SEC-10: `DashMap::len()` + a separate `insert` is not atomic. Using an
    /// `AtomicUsize` with a `fetch_update` CAS loop ensures we never exceed
    /// `max_sessions` even under heavy concurrent insert pressure.
    live_count: Arc<AtomicUsize>,
}

impl Default for AtbRegistry {
    fn default() -> Self {
        Self::with_capacity(10_000)
    }
}

impl AtbRegistry {
    /// Create an empty registry with a default capacity of 10,000 sessions.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty registry with the specified maximum capacity.
    #[must_use]
    pub fn with_capacity(max_sessions: usize) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            max_sessions,
            live_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Insert a newly established session.
    ///
    /// If the registry is at capacity, the session is rejected.
    ///
    /// SEC-10: The capacity check is performed via an atomic `fetch_update`
    /// CAS loop, so no two concurrent inserts can both pass the limit check.
    ///
    /// # Errors
    /// Returns `Err` if the registry is full.
    pub fn insert(&self, session: AttestSession) -> Result<(), &'static str> {
        let id = session.state().id;
        // Atomically claim a slot. If the CAS fails because we are already at
        // capacity, reject the session without inserting into the DashMap.
        let claimed = self
            .live_count
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                if current < self.max_sessions {
                    Some(current + 1)
                } else {
                    None
                }
            });
        if claimed.is_err() {
            tracing::error!(%id, "AtB registry full — rejecting session establishment");
            return Err("AtB registry full");
        }
        tracing::info!(%id, "AtB registered in registry");
        self.sessions.insert(id, session);
        Ok(())
    }

    /// Look up a session by ID.
    ///
    /// Returns `None` if the session is not found **or** has expired (the
    /// expired entry is evicted eagerly).
    pub fn get(&self, id: &AtbId) -> Option<AttestSession> {
        let session = self.sessions.get(id).map(|e| e.value().clone())?;
        if !session.is_alive() {
            tracing::warn!(%id, "AtB expired — evicting");
            // R-02: only decrement live_count if we actually removed the entry.
            // If evict_expired() raced us and already removed it, `remove`
            // returns None and we must NOT double-decrement the counter.
            if self.sessions.remove(id).is_some() {
                self.live_count.fetch_sub(1, Ordering::SeqCst);
            }
            return None;
        }
        tracing::info!(%id, "AtB found in registry");
        Some(session)
    }

    /// Evict all expired sessions.  Call this from a background task.
    pub fn evict_expired(&self) {
        let before = self.sessions.len();
        self.sessions.retain(|_id, session| session.is_alive());
        let after = self.sessions.len();
        // Reclaim slots for the evicted sessions so the atomic counter stays
        // in sync with the actual DashMap length.
        if before > after {
            self.live_count.fetch_sub(before - after, Ordering::SeqCst);
        }
    }

    /// Return the number of live sessions (includes sessions that may have
    /// expired but not yet been lazily evicted).
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Returns `true` if there are no registered sessions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Spawn a background `tokio` task that calls [`Self::evict_expired`]
    /// at the given `interval`.
    ///
    /// The task stops automatically when the last strong reference to the
    /// underlying [`DashMap`] is dropped (i.e. when all registry clones are
    /// dropped).
    /// if all strong references are dropped.
    #[must_use]
    pub fn start_eviction_task(
        &self,
        interval: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        // DRIFT-01: clone the whole registry (not just the inner DashMap) so
        // that evict_expired() can correctly decrement live_count.  Using
        // inner.retain() directly would bypass the atomic counter and cause
        // live_count to drift permanently high, eventually blocking all new
        // session establishment.
        let registry = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                // Stop if no external owner holds a reference.
                if Arc::strong_count(&registry.sessions) <= 1 {
                    break;
                }
                registry.evict_expired();
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openhttpa_core::session::{AttestSession, ReplayStrategy};
    use openhttpa_crypto::hkdf::SessionKeys;
    use openhttpa_proto::{CipherSuite, ProtocolVersion};
    use std::time::{Duration, Instant};

    fn make_session(ttl: Duration) -> AttestSession {
        let keys = SessionKeys::derive(&[0u8; 64], &[0u8; 48]).unwrap();
        AttestSession::new(
            AtbId::new(),
            CipherSuite::X25519MlKem768Aes256GcmSha384,
            ProtocolVersion::V2,
            keys,
            Instant::now() + ttl,
            ReplayStrategy::default(),
            None,
        )
    }

    #[test]
    fn insert_and_get() {
        let reg = AtbRegistry::new();
        let sess = make_session(Duration::from_secs(3600));
        let id = sess.state().id;
        reg.insert(sess).unwrap();
        assert!(reg.get(&id).is_some());
    }

    #[test]
    fn expired_session_not_returned() {
        let reg = AtbRegistry::new();
        let sess = make_session(Duration::from_nanos(1));
        let id = sess.state().id;
        reg.insert(sess).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(reg.get(&id).is_none());
    }

    #[tokio::test]
    async fn background_eviction_task_runs() {
        let reg = AtbRegistry::new();
        let sess = make_session(Duration::from_nanos(1));
        let id = sess.state().id;
        reg.insert(sess).unwrap();
        let _handle = reg.start_eviction_task(Duration::from_millis(10));
        tokio::time::sleep(Duration::from_millis(50)).await;
        // After eviction the session should be gone from the map.
        assert!(reg.sessions.get(&id).is_none());
    }
}
