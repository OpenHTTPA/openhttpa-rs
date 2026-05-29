// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Nonce management for `OpenHTTPA` sessions.
//!
//! For `AtR` (Attest Request) messages random nonces are used. For `TrR`
//! (Trusted Request) messages a **strictly monotonically increasing** 64-bit
//! counter is used so that replayed requests can be detected.

use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

/// Nonce management errors.
// MED-06: non_exhaustive prevents breaking changes when new variants are added.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum NonceError {
    /// A replay attack was detected. The received nonce was not strictly greater than the last seen.
    #[error("replay detected: received nonce {received} is not greater than last seen {last}")]
    Replay {
        /// The nonce that was received.
        received: u64,
        /// The highest nonce seen so far.
        last: u64,
    },
    /// The 64-bit nonce counter overflowed. The session must be renegotiated.
    #[error("nonce counter overflowed — session must be renegotiated")]
    Overflow,
    /// An underlying storage error occurred.
    #[error("storage error: {0}")]
    Storage(String),
}

/// Pluggable storage for durable nonces.
pub trait NonceStorage: Send + Sync + std::fmt::Debug {
    /// Save the current nonce state.
    ///
    /// # Errors
    /// Returns [`Err`] if the state cannot be persisted.
    fn save(&self, next_send: u64, last_seen: u64) -> Result<(), NonceError>;

    /// Load the last saved nonce state.
    ///
    /// # Errors
    /// Returns [`Err`] if storage is inaccessible or corrupted.
    ///
    /// # Errors
    /// Returns [`Err`] if storage is inaccessible or corrupted.
    fn load(&self) -> Result<(u64, u64), NonceError>;
}

/// A simple file-backed nonce storage implementation.
#[derive(Debug)]
pub struct FileNonceStorage {
    path: std::path::PathBuf,
}

impl FileNonceStorage {
    /// Create a new `FileNonceStorage` at `path`.
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl NonceStorage for FileNonceStorage {
    fn save(&self, next_send: u64, last_seen: u64) -> Result<(), NonceError> {
        let data = serde_json::json!({
            "next_send": next_send,
            "last_seen": last_seen,
        });
        let content =
            serde_json::to_string(&data).map_err(|e| NonceError::Storage(e.to_string()))?;

        // SEC-04: Use an atomic write-to-temp-then-rename pattern so a crash
        // mid-write never leaves a truncated nonce file. A corrupted file
        // would reset the counter to (1, 0) on restart, enabling replay of
        // every historical nonce.
        let mut tmp = self.path.clone();
        tmp.set_extension("tmp");

        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true).mode(0o600);
            let mut file = opts
                .open(&tmp)
                .map_err(|e| NonceError::Storage(e.to_string()))?;
            file.write_all(content.as_bytes())
                .map_err(|e| NonceError::Storage(e.to_string()))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&tmp, &content).map_err(|e| NonceError::Storage(e.to_string()))?;
        }

        std::fs::rename(&tmp, &self.path).map_err(|e| NonceError::Storage(e.to_string()))?;
        Ok(())
    }

    fn load(&self) -> Result<(u64, u64), NonceError> {
        if !self.path.exists() {
            return Ok((1, 0));
        }
        let content =
            std::fs::read_to_string(&self.path).map_err(|e| NonceError::Storage(e.to_string()))?;
        let data: serde_json::Value =
            serde_json::from_str(&content).map_err(|e| NonceError::Storage(e.to_string()))?;
        let next = data["next_send"].as_u64().unwrap_or(1);
        let last = data["last_seen"].as_u64().unwrap_or(0);
        Ok((next, last))
    }
}

/// A per-session nonce manager for `TrR` messages.
///
/// The sender increments `next_send` before each request. The receiver
/// validates that the incoming nonce is strictly greater than `last_seen`.
///
/// Thread-safe via atomic operations.
pub struct NonceManager {
    next_send: AtomicU64,
    last_seen: AtomicU64,
    storage: Option<Box<dyn NonceStorage>>,
}

impl NonceManager {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_send: AtomicU64::new(1),
            last_seen: AtomicU64::new(0),
            storage: None,
        }
    }

    /// Construct a `NonceManager` with persistence.
    ///
    /// # Errors
    /// Returns [`Err`] if the initial state cannot be loaded from storage.
    pub fn with_storage(storage: Box<dyn NonceStorage>) -> Result<Self, NonceError> {
        let (next, last) = storage.load()?;
        Ok(Self {
            next_send: AtomicU64::new(next),
            last_seen: AtomicU64::new(last),
            storage: Some(storage),
        })
    }

    /// Acquire the next send nonce.  Fails if the counter would overflow.
    ///
    /// # Errors
    /// Returns [`Err`] if the nonce counter has overflowed.
    pub fn next_send_nonce(&self) -> Result<u64, NonceError> {
        let prev = self.next_send.fetch_add(1, Ordering::SeqCst);
        if prev == u64::MAX {
            return Err(NonceError::Overflow);
        }
        if let Some(ref storage) = self.storage {
            storage.save(prev + 1, self.last_seen.load(Ordering::SeqCst))?;
        }
        Ok(prev)
    }

    /// Validate an incoming nonce from the peer.
    ///
    /// The nonce must be strictly greater than the last accepted nonce.
    ///
    /// # Errors
    /// Returns [`Err`] if the nonce is a replay or out-of-order.
    pub fn validate_recv(&self, nonce: u64) -> Result<(), NonceError> {
        // Use a compare-and-exchange loop for thread safety.
        loop {
            let last = self.last_seen.load(Ordering::SeqCst);
            if nonce <= last {
                return Err(NonceError::Replay {
                    received: nonce,
                    last,
                });
            }
            // Try to advance; if someone else advanced concurrently, retry.
            if self
                .last_seen
                .compare_exchange(last, nonce, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                if let Some(ref storage) = self.storage {
                    storage.save(self.next_send.load(Ordering::SeqCst), nonce)?;
                }
                return Ok(());
            }
        }
    }

    /// Build a 12-byte AEAD nonce from a 64-bit counter, XOR'd with a
    /// 12-byte base IV.
    ///
    /// This follows TLS 1.3 nonce construction: XOR the sequence number
    /// (right-aligned, big-endian) with the write IV.
    #[must_use]
    pub fn build_aead_nonce(counter: u64, write_iv: &[u8; 12]) -> [u8; 12] {
        let mut nonce = *write_iv;
        let counter_bytes = counter.to_be_bytes();
        // XOR the 8 counter bytes into the last 8 bytes of the 12-byte IV.
        for (n, c) in nonce[4..].iter_mut().zip(counter_bytes.iter()) {
            *n ^= c;
        }
        nonce
    }
}

impl Default for NonceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequential_nonces_accepted() {
        let mgr = NonceManager::new();
        mgr.validate_recv(1).unwrap();
        mgr.validate_recv(2).unwrap();
        mgr.validate_recv(100).unwrap();
    }

    #[test]
    fn duplicate_nonce_rejected() {
        let mgr = NonceManager::new();
        mgr.validate_recv(5).unwrap();
        assert!(mgr.validate_recv(5).is_err());
    }

    #[test]
    fn out_of_order_nonce_rejected() {
        let mgr = NonceManager::new();
        mgr.validate_recv(10).unwrap();
        assert!(mgr.validate_recv(9).is_err());
    }

    #[test]
    fn send_nonces_monotonically_increasing() {
        let mgr = NonceManager::new();
        let n1 = mgr.next_send_nonce().unwrap();
        let n2 = mgr.next_send_nonce().unwrap();
        assert!(n2 > n1);
    }

    #[test]
    fn aead_nonce_construction() {
        let iv = std::array::from_fn::<u8, 12, _>(|_| rand::random());
        let nonce = NonceManager::build_aead_nonce(1, &iv);
        // Bytes 0..4 unchanged; bytes 4..12 XOR'd with counter=1 big-endian
        assert_eq!(&nonce[..4], &iv[..4]);
        assert_ne!(&nonce[4..], &iv[4..]);
    }

    #[test]
    fn nonce_overflow_detected() {
        let mgr = NonceManager::new();
        // Manually set next_send to max
        mgr.next_send.store(u64::MAX, Ordering::SeqCst);
        assert!(matches!(mgr.next_send_nonce(), Err(NonceError::Overflow)));
    }

    #[test]
    fn file_nonce_storage_persistence() {
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join("nonce_test.json");
        let storage = Box::new(FileNonceStorage::new(path.clone()));

        let mgr = NonceManager::with_storage(storage).unwrap();
        mgr.next_send_nonce().unwrap(); // next_send becomes 2
        mgr.validate_recv(5).unwrap(); // last_seen becomes 5

        // Reload from same storage
        let storage2 = Box::new(FileNonceStorage::new(path.clone()));
        let mgr2 = NonceManager::with_storage(storage2).unwrap();
        assert_eq!(mgr2.next_send.load(Ordering::SeqCst), 2);
        assert_eq!(mgr2.last_seen.load(Ordering::SeqCst), 5);

        std::fs::remove_file(path).ok();
    }
}
