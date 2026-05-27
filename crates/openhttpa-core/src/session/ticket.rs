// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! `OpenHTTPA` Session Ticket (`AtST`) implementation.
//!
//! Provides high-assurance sealing and unsealing of session state for
//! `Attest-Ticket-Resumption`.

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use crate::session::DurableSessionState;
use openhttpa_crypto::aead::{AeadAlgorithm, AeadError, AeadKey, AeadNonce, NONCE_LEN};
use openhttpa_proto::types::SessionTicket;
use tracing::{info, instrument, warn};

use zeroize::{Zeroize, ZeroizeOnDrop};

/// The server-side key used to seal and unseal resumption tickets.
///
/// Addresses SEC-01 (Nonce-Reuse Risk) by using a monotonic counter.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct TicketKey {
    pub key: [u8; 32],
    #[serde(with = "atomic_u64_serde")]
    #[zeroize(skip)]
    counter: AtomicU64,
}

mod atomic_u64_serde {
    use std::sync::atomic::{AtomicU64, Ordering};

    pub fn serialize<S>(val: &AtomicU64, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde::Serialize::serialize(&val.load(Ordering::SeqCst), s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<AtomicU64, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let val: u64 = serde::Deserialize::deserialize(d)?;
        Ok(AtomicU64::new(val))
    }
}

impl Clone for TicketKey {
    fn clone(&self) -> Self {
        Self {
            key: self.key,
            counter: AtomicU64::new(self.counter.load(Ordering::SeqCst)),
        }
    }
}

impl TicketKey {
    /// Create a `TicketKey` from existing bytes and counter.
    #[must_use]
    pub const fn from_parts(key: [u8; 32], counter: u64) -> Self {
        Self {
            key,
            counter: AtomicU64::new(counter),
        }
    }

    /// Export the key and current counter.
    pub fn to_parts(&self) -> ([u8; 32], u64) {
        (self.key, self.counter.load(Ordering::SeqCst))
    }

    /// Generate a new random ticket encryption key with a fresh counter.
    ///
    /// # Panics
    /// Panics if the system entropy source fails.
    #[must_use]
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        let rng = openhttpa_crypto::rand::SystemRandom::new();
        openhttpa_crypto::rand::SecureRandom::fill(&rng, &mut key).expect("entropy failure");
        Self {
            key,
            counter: AtomicU64::new(1),
        }
    }

    /// Increment and return the next nonce counter.
    pub fn next_nonce(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::SeqCst)
    }
}

/// Orchestrates the lifecycle of resumption tickets with rotation support.
///
/// Addresses SEC-03 (Ticket Key Rotation).
#[derive(Clone, Serialize, Deserialize)]
pub struct TicketEngine {
    current_key: TicketKey,
    previous_key: Option<TicketKey>,
}

impl TicketEngine {
    /// Create a new engine with the provided key.
    #[must_use]
    pub const fn new(key: TicketKey) -> Self {
        Self {
            current_key: key,
            previous_key: None,
        }
    }

    /// Create an engine from serialized parts.
    #[must_use]
    pub const fn from_parts(current: TicketKey, previous: Option<TicketKey>) -> Self {
        Self {
            current_key: current,
            previous_key: previous,
        }
    }

    /// Export the engine state.
    pub fn to_parts(&self) -> (TicketKey, Option<TicketKey>) {
        (self.current_key.clone(), self.previous_key.clone())
    }

    /// Save the engine state to a file atomically with strict permissions.
    ///
    /// # Errors
    /// Returns an IO error if saving fails.
    ///
    /// # Panics
    /// Panics if serialization fails.
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let path = path.as_ref();
        let tmp_path = path.with_extension("tmp");

        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);

        #[cfg(unix)]
        options.mode(0o600);

        let mut file = options.open(&tmp_path)?;
        let json = serde_json::to_vec(self).expect("serialization failure");
        file.write_all(&json)?;
        file.sync_all()?;
        drop(file);

        std::fs::rename(tmp_path, path)?;
        info!(path = ?path, "TicketEngine state saved atomically");
        Ok(())
    }

    /// Load the engine state from a file.
    ///
    /// # Errors
    /// Returns an IO error if loading or deserialization fails.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let mut file = OpenOptions::new().read(true).open(path)?;
        let mut json = Vec::new();
        file.read_to_end(&mut json)?;
        let engine: Self = serde_json::from_slice(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(engine)
    }

    /// Rotate the current key to previous and install a new key.
    pub fn rotate(&mut self) {
        self.previous_key = Some(self.current_key.clone());
        self.current_key = TicketKey::generate();
        info!("TicketKey rotated: current counter reset to 1");
    }

    /// Seal a session into an opaque `SessionTicket`.
    ///
    /// # Errors
    /// Returns [`AeadError`] if encryption fails.
    #[instrument(skip_all)]
    pub fn seal_session(
        &self,
        state: &DurableSessionState,
        lifetime: Duration,
    ) -> Result<SessionTicket, AeadError> {
        let mut data = postcard::to_allocvec(state)
            .map_err(|e| AeadError::IoError(format!("ticket serialisation failed: {e}")))?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        let counter = self.current_key.next_nonce();
        nonce_bytes[4..].copy_from_slice(&counter.to_be_bytes());
        let nonce = AeadNonce(nonce_bytes);

        let key = AeadKey::new(AeadAlgorithm::Aes256Gcm, &self.current_key.key)?;
        key.seal_in_place(&nonce, &[], &mut data)?;

        // Combine nonce + ciphertext for the opaque blob
        let mut ticket_blob = Vec::with_capacity(NONCE_LEN + data.len());
        ticket_blob.extend_from_slice(&nonce_bytes);
        ticket_blob.extend_from_slice(&data);

        Ok(SessionTicket {
            ticket: ticket_blob,
            lifetime: u32::try_from(lifetime.as_secs()).unwrap_or(u32::MAX),
            cipher_suite: state.cipher_suite,
            rtt0_eligible: true, // Tickets are eligible for 0-RTT by default in this implementation
        })
    }

    /// Unseal an opaque ticket blob into a `DurableSessionState`.
    ///
    /// # Errors
    /// Returns [`AeadError`] if decryption or deserialisation fails.
    #[instrument(skip_all)]
    pub fn unseal_session(&self, ticket: &[u8]) -> Result<DurableSessionState, AeadError> {
        if ticket.len() < NONCE_LEN {
            return Err(AeadError::IoError("ticket too short".to_owned()));
        }

        let (nonce_raw, ciphertext) = ticket.split_at(NONCE_LEN);
        let nonce = AeadNonce::from_slice(nonce_raw)?;

        // Attempt unseal with current key
        let mut data = ciphertext.to_vec();
        let key = AeadKey::new(AeadAlgorithm::Aes256Gcm, &self.current_key.key)?;
        let state: DurableSessionState = match key.open_in_place(&nonce, &[], &mut data) {
            Ok(pt) => postcard::from_bytes(pt)
                .map_err(|e| AeadError::IoError(format!("ticket deserialisation failed: {e}")))?,
            Err(_) => {
                // Fallback to previous key if available
                if let Some(prev) = &self.previous_key {
                    let mut data = ciphertext.to_vec();
                    let key = AeadKey::new(AeadAlgorithm::Aes256Gcm, &prev.key)?;
                    let pt = key.open_in_place(&nonce, &[], &mut data)?;
                    postcard::from_bytes(pt).map_err(|e| {
                        AeadError::IoError(format!("ticket deserialisation failed: {e}"))
                    })?
                } else {
                    return Err(AeadError::OpenFailed);
                }
            }
        };

        // Verify expiry
        if SystemTime::now() > state.expires_at {
            warn!("Unsealed session ticket has expired");
            return Err(AeadError::IoError("ticket expired".to_owned()));
        }

        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::sealed::SealedSessionKeys;
    use openhttpa_crypto::hkdf::SessionKeys;
    use openhttpa_proto::types::{AtbId, CipherSuite, ProtocolVersion};

    fn mock_state() -> DurableSessionState {
        DurableSessionState {
            id: AtbId::new(),
            cipher_suite: CipherSuite::X25519MlKem768Aes256GcmSha384,
            version: ProtocolVersion::V2,
            phase: crate::state::ProtocolPhase::Attested,
            keys: SealedSessionKeys::new(SessionKeys::derive(&[0u8; 64], &[0u8; 48]).unwrap()),
            resumption_secret: vec![0u8; 48],
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            client_counter: 1,
            server_counter: 1,
            replay_highest: 0,
            replay_window: vec![0u64; 64],
            attestation_result: None,
        }
    }

    #[test]
    fn ticket_rotation_works() {
        let key = TicketKey::generate();
        let mut engine = TicketEngine::new(key);
        let state = mock_state();

        let ticket1 = engine
            .seal_session(&state, Duration::from_secs(3600))
            .unwrap();

        // Rotate key
        engine.rotate();

        // Should still be able to unseal with old ticket (using previous_key)
        let unsealed = engine.unseal_session(&ticket1.ticket).unwrap();
        assert_eq!(unsealed.id, state.id);

        // New tickets use new key
        let ticket2 = engine
            .seal_session(&state, Duration::from_secs(3600))
            .unwrap();
        assert_ne!(ticket1.ticket, ticket2.ticket);

        let unsealed2 = engine.unseal_session(&ticket2.ticket).unwrap();
        assert_eq!(unsealed2.id, state.id);
    }

    #[test]
    fn expired_ticket_rejected() {
        let key = TicketKey::generate();
        let engine = TicketEngine::new(key);
        let mut state = mock_state();
        state.expires_at = SystemTime::now() - Duration::from_secs(1);

        let ticket = engine
            .seal_session(&state, Duration::from_secs(3600))
            .unwrap();
        let res = engine.unseal_session(&ticket.ticket);
        assert!(res.is_err());
    }

    #[test]
    fn ticket_persistence_works() {
        let key = TicketKey::generate();
        let engine = TicketEngine::new(key);
        let path = std::env::temp_dir().join(format!("ticket_test_{}.json", uuid::Uuid::new_v4()));

        // Save
        engine.save_to_file(&path).unwrap();

        // Verify permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::metadata(&path).unwrap();
            let mode = metadata.mode() & 0o777;
            assert_eq!(mode, 0o600, "Ticket file must have 0600 permissions");
        }

        // Load
        let loaded = TicketEngine::load_from_file(&path).unwrap();
        assert_eq!(loaded.current_key.key, engine.current_key.key);
        assert_eq!(
            loaded.current_key.counter.load(Ordering::SeqCst),
            engine.current_key.counter.load(Ordering::SeqCst)
        );

        std::fs::remove_file(path).ok();
    }
}
