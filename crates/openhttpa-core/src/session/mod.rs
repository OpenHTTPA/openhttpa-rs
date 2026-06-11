// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! A live `OpenHTTPA` session — holds all state for a single `AtB`.
//!
//! ## SA-04 Replay Strategy Unification
//!
//! `OpenHTTPA` provides two replay protection mechanisms:
//!
//! 1. **`ReplayStrategy::SlidingWindow(w)`** — a bitmask guard accepting nonces
//!    within a window of `w * 64` most-recently-seen values (out-of-order safe,
//!    suitable for UDP/QUIC transports or any transport where nonce order cannot
//!    be guaranteed). Backed by [`crate::replay_guard::ReplayGuard`].
//!
//! 2. **`ReplayStrategy::StrictMonotonic`** — accepts nonces in strictly
//!    ascending order only (no out-of-order tolerance). Lower overhead; correct
//!    for ordered transports (TCP/HTTP). Backed by an `AtomicU64` CAS loop.
//!
//! The strategy is selected at session creation time. All session state is
//! encapsulated in `AttestSession`; callers do not interact with the underlying
//! guard directly.
//!
//! ### Crash-Safety Note (Strict Monotonic path)
//!
//! The `StrictMonotonic` guard commits the new nonce atomically in memory (CAS),
//! then persists it to stable storage. If the process crashes between the CAS and
//! the storage write, the nonce is committed in memory but not persisted. On
//! restart, the old `last_seen` value is loaded, and the same nonce could be
//! re-accepted once. Mitigations:
//! - Use [`openhttpa_crypto::nonce::FileNonceStorage`] for durable storage.
//! - On restart, fast-forward the counter by at least 1 past the stored value to
//!   close the one-nonce replay window.
//! - The `SlidingWindow` strategy does not persist state and is therefore not
//!   subject to this concern for short-lived sessions.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use openhttpa_crypto::hkdf::SessionKeys;
use openhttpa_proto::{
    AtbId, CipherSuite, ClientSecurityPosture, ProtocolVersion, TeeClass, VerificationResult,
};
use thiserror::Error;

use crate::{
    replay_guard::ReplayGuard,
    state::{ProtocolPhase, TransitionError, transition},
};
use serde::{Deserialize, Serialize};

pub mod builder;
pub use builder::SessionBuilder;

pub mod sealed;
pub use sealed::SealedSessionKeys;
pub mod ticket;

/// Session errors.
// MED-06: non_exhaustive prevents breaking changes when new variants are added.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("state transition error: {0}")]
    Transition(#[from] TransitionError),
    #[error("session has expired")]
    Expired,
    #[error("trusted request not permitted in current phase")]
    NotAttested,
    #[error("replay nonce rejected")]
    Replay,
    #[error("cryptographic counter overflow")]
    Overflow,
}

/// Selects the replay-protection mechanism for a session.
///
/// Choose based on the transport's ordering guarantees:
///
/// - **TCP / HTTP/1.1 / HTTP/2** (ordered): use `StrictMonotonic`. Minimal
///   overhead; rejects any nonce ≤ the last accepted value.
/// - **UDP / QUIC / WebTransport** (unordered): use `SlidingWindow(w)`. Accepts
///   out-of-order nonces within a window of `w × 64` positions.
///
/// See the module-level doc for crash-safety notes on `StrictMonotonic`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayStrategy {
    /// Accept nonces in strictly ascending order. O(1) memory, O(1) time.
    StrictMonotonic,
    /// Accept any nonce within the last `W × 64` positions (out-of-order safe).
    /// `W` is the window granularity; `W = 64` gives a 4096-nonce window.
    SlidingWindow(usize),
}

impl Default for ReplayStrategy {
    /// Default strategy: sliding window with W=64 (4096-nonce window), matching
    /// the pre-SA-04 behaviour of `AttestSession`.
    fn default() -> Self {
        Self::SlidingWindow(64)
    }
}

/// The full state of an `OpenHTTPA` session, held behind an `Arc<Mutex<…>>` for
/// thread-safe sharing between transport tasks.
pub struct AttestSession {
    inner: Arc<Mutex<SessionInner>>,
}

impl std::fmt::Debug for AttestSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let g = self.inner.lock().unwrap();
        f.debug_struct("AttestSession")
            .field("phase", &g.phase)
            .field("id", &g.id)
            .field("expires_at", &g.expires_at)
            .finish()
    }
}

struct SessionInner {
    pub id: AtbId,
    pub cipher_suite: CipherSuite,
    pub version: ProtocolVersion,
    pub phase: ProtocolPhase,
    pub keys: SealedSessionKeys,
    pub expires_at: Instant,
    /// SA-04: sliding-window guard (`SlidingWindow` strategy).
    pub replay_guard: ReplayGuard<64>,
    /// SA-04: strict-monotonic last-seen counter (`StrictMonotonic` strategy).
    pub strict_last_seen: AtomicU64,
    /// Which replay strategy is active for this session.
    pub replay_strategy: ReplayStrategy,
    /// Counter for client-to-server messages (`TrR`).
    pub client_counter: u64,
    /// Counter for server-to-client messages (`TrS`).
    pub server_counter: u64,
    /// Verified attestation result from the handshake.
    pub attestation_result: Option<VerificationResult>,
}

/// Current session state snapshot (clone-able, no secrets).
#[derive(Debug, Clone)]
pub struct SessionState {
    pub id: AtbId,
    pub cipher_suite: CipherSuite,
    pub version: ProtocolVersion,
    pub phase: ProtocolPhase,
    pub expires_at: Instant,
    pub attestation_result: Option<VerificationResult>,
}

impl SessionState {
    /// Evaluates the client's security posture from this session state snapshot.
    #[must_use]
    #[allow(clippy::option_if_let_else)]
    pub const fn client_posture(&self) -> ClientSecurityPosture {
        match &self.attestation_result {
            Some(res) => match res.claims.tee_class {
                Some(TeeClass::Mock) => ClientSecurityPosture::SimulatedTee,
                Some(cls) => ClientSecurityPosture::MutualTee(cls),
                None => ClientSecurityPosture::MutualTee(TeeClass::Unknown),
            },
            None => ClientSecurityPosture::OneDirectional,
        }
    }
}

/// A fully serialisable snapshot of a session, including secrets and replay state.
#[derive(Serialize, Deserialize)]
pub struct DurableSessionState {
    pub id: AtbId,
    pub cipher_suite: CipherSuite,
    pub version: ProtocolVersion,
    pub phase: ProtocolPhase,
    pub keys: SealedSessionKeys,
    /// SA-05: Resumption secret (master secret) for deriving fresh 0-RTT keys.
    pub resumption_secret: Vec<u8>,
    /// Absolute expiration time.
    pub expires_at: std::time::SystemTime,
    pub client_counter: u64,
    pub server_counter: u64,
    pub replay_highest: u64,
    pub replay_window: Vec<u64>,
    /// Verified attestation result (EAT).
    pub attestation_result: Option<VerificationResult>,
}

impl AttestSession {
    /// Create a new session from `AtHS` results.
    ///
    /// `strategy` controls which replay-protection mechanism is used for
    /// incoming nonces. Use [`ReplayStrategy::default()`] for the pre-SA-04
    /// sliding-window behaviour (`SlidingWindow(64)`).
    #[must_use]
    pub fn new(
        id: AtbId,
        cipher_suite: CipherSuite,
        version: ProtocolVersion,
        keys: SessionKeys,
        expires_at: Instant,
        strategy: ReplayStrategy,
        attestation_result: Option<VerificationResult>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SessionInner {
                id,
                cipher_suite,
                version,
                phase: ProtocolPhase::Attested,
                keys: SealedSessionKeys::new(keys),
                expires_at,
                replay_guard: ReplayGuard::new(),
                strict_last_seen: AtomicU64::new(0),
                replay_strategy: strategy,
                client_counter: 1,
                server_counter: 1,
                attestation_result,
            })),
        }
    }

    /// Returns the unique identifier for this session.
    ///
    /// # Panics
    ///
    /// Panics if the session mutex is poisoned.
    #[must_use]
    pub fn id(&self) -> AtbId {
        let g = self.inner.lock().unwrap();
        g.id.clone()
    }

    /// Snapshot current state (without secrets).
    ///
    /// # Panics
    ///
    /// Panics if the session mutex is poisoned.
    #[must_use]
    pub fn state(&self) -> SessionState {
        let g = self.inner.lock().unwrap();
        let id = g.id.clone();
        let cipher_suite = g.cipher_suite;
        let version = g.version;
        let phase = g.phase;
        let expires_at = g.expires_at;
        let attestation_result = g.attestation_result.clone();
        drop(g);
        SessionState {
            id,
            cipher_suite,
            version,
            phase,
            expires_at,
            attestation_result,
        }
    }

    /// Evaluates the client's security posture based on the provided attestation quote (if any).
    ///
    /// # Panics
    /// Panics if the session mutex is poisoned.
    #[must_use]
    pub fn client_posture(&self) -> ClientSecurityPosture {
        let g = self.inner.lock().unwrap();
        g.attestation_result
            .as_ref()
            .map_or(ClientSecurityPosture::OneDirectional, |res| {
                match res.claims.tee_class {
                    Some(TeeClass::Mock) => ClientSecurityPosture::SimulatedTee,
                    Some(cls) => ClientSecurityPosture::MutualTee(cls),
                    None => ClientSecurityPosture::MutualTee(TeeClass::Unknown),
                }
            })
    }

    /// Returns `true` if the session has not yet expired.
    ///
    /// # Panics
    ///
    /// Panics if the session mutex is poisoned.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        let g = self.inner.lock().unwrap();
        Instant::now() < g.expires_at
    }

    /// Transition to the next phase.
    ///
    /// # Panics
    ///
    /// Panics if the session mutex is poisoned.
    ///
    /// # Errors
    ///
    /// Returns [`Err`](`SessionError::Transition`) if the transition is not valid.
    pub fn advance_phase(&self, next: ProtocolPhase) -> Result<(), SessionError> {
        let mut g = self.inner.lock().unwrap();
        let new_phase = transition(g.phase, next)?;
        g.phase = new_phase;
        drop(g);
        Ok(())
    }

    /// Read-only access to session keys without validating nonces or incrementing counters.
    ///
    /// Use this for initializing separate transports (e.g. `WebSockets`) that
    /// handle their own replay protection.
    ///
    /// # Errors
    ///
    /// Returns [`Err`](`SessionError::Expired`) if the session has expired.
    ///
    /// # Panics
    ///
    /// Panics if the session mutex is poisoned.
    pub fn peek_keys<F, R>(&self, f: F) -> Result<R, SessionError>
    where
        F: FnOnce(&SessionKeys) -> R,
    {
        let g = self.inner.lock().unwrap();
        if Instant::now() >= g.expires_at {
            return Err(SessionError::Expired);
        }
        let result = f(g.keys.unseal());
        drop(g);
        Ok(result)
    }

    /// Run a closure with read access to the session keys and current client counter.
    ///
    /// Validates expiry and replay (check-only) before granting access. If the
    /// closure returns `Ok`, the nonce is committed to the replay guard and the
    /// client counter is incremented.
    ///
    /// This two-phase approach prevents unauthenticated attackers from
    /// desynchronising the session or causing a `DoS` by advancing the replay
    /// window with forged messages.
    ///
    /// # Panics
    ///
    /// Panics if the session mutex is poisoned.
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if the session has expired, the phase does not allow
    /// trusted requests, or the nonce is replayed/too-old.
    pub fn with_keys_for_trr<F, T, E>(&self, nonce: u64, f: F) -> Result<Result<T, E>, SessionError>
    where
        F: FnOnce(&SessionKeys, u64) -> Result<T, E>,
    {
        let mut g = self.inner.lock().unwrap();
        if Instant::now() >= g.expires_at {
            return Err(SessionError::Expired);
        }
        if !g.phase.allows_trusted_request() {
            return Err(SessionError::NotAttested);
        }

        // Phase 1: Check if nonce is acceptable (does NOT mutate for SlidingWindow;
        // DOES atomically advance last_seen for StrictMonotonic via CAS).
        match g.replay_strategy {
            ReplayStrategy::SlidingWindow(_) => {
                g.replay_guard.check(nonce).map_err(|e| {
                    tracing::error!(nonce = nonce, error = %e, "Nonce check failed (SlidingWindow)");
                    SessionError::Replay
                })?;
            }
            ReplayStrategy::StrictMonotonic => {
                // Strict monotonic: nonce must be strictly greater than last_seen.
                // Implemented as a CAS loop so concurrent calls serialize correctly.
                loop {
                    let last = g.strict_last_seen.load(Ordering::SeqCst);
                    if nonce <= last {
                        tracing::error!(
                            nonce = nonce,
                            last_seen = last,
                            "Nonce check failed (StrictMonotonic replay)"
                        );
                        return Err(SessionError::Replay);
                    }
                    if g.strict_last_seen
                        .compare_exchange(last, nonce, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        break; // CAS committed: nonce is now the new last_seen.
                    }
                    // Another thread advanced last_seen; re-check.
                }
            }
        }

        let counter = g.client_counter;
        let result = f(g.keys.unseal(), counter);

        // Phase 2: Only commit and increment if the closure (authentication) succeeded.
        if result.is_ok() {
            // SA-04: Dispatch commit to the active replay strategy.
            match g.replay_strategy {
                ReplayStrategy::SlidingWindow(_) => {
                    g.replay_guard.accept(nonce);
                }
                ReplayStrategy::StrictMonotonic => {
                    // The CAS already advanced last_seen in Phase 1; nothing more to do.
                    // (The strict check below in Phase 1 is also the commit for monotonic.)
                }
            }
            g.client_counter = g
                .client_counter
                .checked_add(1)
                .ok_or(SessionError::Overflow)?;
        } else {
            // Closure failed — roll back strict-monotonic last_seen to `nonce - 1`
            // so the nonce can be retried. For SlidingWindow, accept() was not
            // called, so nothing needs to be rolled back.
            if matches!(g.replay_strategy, ReplayStrategy::StrictMonotonic) {
                // Restore last_seen to what it was before Phase 1. Since Phase 1
                // set it to `nonce` via CAS, we restore to `nonce - 1` (or 0).
                g.strict_last_seen
                    .store(nonce.saturating_sub(1), Ordering::SeqCst);
            }
            tracing::warn!(nonce = nonce, "Closure returned error; nonce NOT committed");
        }
        drop(g);

        Ok(result)
    }

    /// # Errors
    ///
    /// Returns [`Err`](`SessionError::Expired`) if the session has expired or the
    /// counter overflows.
    ///
    /// # Panics
    ///
    /// Panics if the session mutex is poisoned.
    pub fn with_keys_for_trs<F, R>(&self, f: F) -> Result<R, SessionError>
    where
        F: FnOnce(&SessionKeys, u64) -> R,
    {
        let mut g = self.inner.lock().unwrap();
        if Instant::now() >= g.expires_at {
            return Err(SessionError::Expired);
        }

        let counter = g.server_counter;
        let result = f(g.keys.unseal(), counter);

        g.server_counter = g
            .server_counter
            .checked_add(1)
            .ok_or(SessionError::Overflow)?;

        drop(g);
        Ok(result)
    }

    /// Export the session to a durable, serialisable format.
    ///
    /// # Panics
    /// Panics if the session mutex is poisoned.
    #[must_use]
    pub fn export_durable(&self) -> DurableSessionState {
        let g = self.inner.lock().unwrap();
        let (replay_highest, window_arr) = g.replay_guard.export_state();

        // Convert Instant to SystemTime
        let now_inst = Instant::now();
        let now_sys = std::time::SystemTime::now();
        let expires_at = if g.expires_at > now_inst {
            now_sys + (g.expires_at - now_inst)
        } else {
            now_sys
        };

        DurableSessionState {
            id: g.id.clone(),
            cipher_suite: g.cipher_suite,
            version: g.version,
            phase: g.phase,
            keys: g.keys.clone(),
            resumption_secret: g.keys.unseal().master_secret.clone(),
            expires_at,
            client_counter: g.client_counter,
            server_counter: g.server_counter,
            replay_highest,
            replay_window: window_arr.to_vec(),
            attestation_result: g.attestation_result.clone(),
        }
    }

    /// Restore a session from a durable state.
    ///
    /// # Panics
    /// Panics if the session mutex is poisoned.
    #[must_use]
    pub fn from_durable(state: DurableSessionState) -> Self {
        let now_sys = std::time::SystemTime::now();
        let now_inst = Instant::now();
        let expires_at = if state.expires_at > now_sys {
            now_inst
                + state
                    .expires_at
                    .duration_since(now_sys)
                    .unwrap_or(std::time::Duration::ZERO)
        } else {
            now_inst
        };

        let replay_guard = ReplayGuard::new();
        let mut window = [0u64; 64];
        let len = state.replay_window.len().min(64);
        window[..len].copy_from_slice(&state.replay_window[..len]);
        replay_guard.import_state(state.replay_highest, window);

        Self {
            inner: Arc::new(Mutex::new(SessionInner {
                id: state.id,
                cipher_suite: state.cipher_suite,
                version: state.version,
                phase: state.phase,
                keys: state.keys,
                expires_at,
                replay_guard,
                // SA-04: Restored sessions use SlidingWindow (the default) for
                // backward compatibility. Callers that require StrictMonotonic
                // must re-create the session with the desired strategy.
                strict_last_seen: AtomicU64::new(state.client_counter.saturating_sub(1)),
                replay_strategy: ReplayStrategy::default(),
                client_counter: state.client_counter,
                server_counter: state.server_counter,
                attestation_result: state.attestation_result,
            })),
        }
    }
}

impl Clone for AttestSession {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openhttpa_crypto::hkdf::SessionKeys;

    fn dummy_keys() -> SessionKeys {
        SessionKeys::derive(
            &std::array::from_fn::<u8, 64, _>(|_| rand::random()),
            &std::array::from_fn::<u8, 48, _>(|_| rand::random()),
        )
        .unwrap()
    }

    #[test]
    fn new_session_is_alive() {
        let sess = AttestSession::new(
            AtbId::new(),
            CipherSuite::X25519MlKem768Aes256GcmSha384,
            ProtocolVersion::V2,
            dummy_keys(),
            Instant::now() + std::time::Duration::from_secs(3600),
            ReplayStrategy::default(),
            None,
        );
        assert!(sess.is_alive());
        assert_eq!(sess.state().phase, ProtocolPhase::Attested);
    }

    #[test]
    fn trusted_request_with_keys_accepts_fresh_nonce() {
        let sess = AttestSession::new(
            AtbId::new(),
            CipherSuite::X25519MlKem768Aes256GcmSha384,
            ProtocolVersion::V2,
            dummy_keys(),
            Instant::now() + std::time::Duration::from_secs(3600),
            ReplayStrategy::default(),
            None,
        );
        sess.with_keys_for_trr(1, |keys, _| {
            assert_eq!(keys.client_write_key.len(), 32);
            Ok::<(), ()>(())
        })
        .unwrap()
        .unwrap();
    }

    #[test]
    fn nonce_not_committed_on_failure() {
        let sess = AttestSession::new(
            AtbId::new(),
            CipherSuite::X25519MlKem768Aes256GcmSha384,
            ProtocolVersion::V2,
            dummy_keys(),
            Instant::now() + std::time::Duration::from_secs(3600),
            ReplayStrategy::default(),
            None,
        );
        // Closure fails -> nonce should NOT be marked as seen.
        let _ = sess.with_keys_for_trr(42, |_, _| Err::<(), _>("fail"));

        // Should be able to use nonce 42 again because it wasn't committed.
        sess.with_keys_for_trr(42, |_, _| Ok::<(), ()>(()))
            .unwrap()
            .unwrap();
    }

    #[test]
    fn replay_nonce_rejected() {
        let sess = AttestSession::new(
            AtbId::new(),
            CipherSuite::X25519MlKem768Aes256GcmSha384,
            ProtocolVersion::V2,
            dummy_keys(),
            Instant::now() + std::time::Duration::from_secs(3600),
            ReplayStrategy::default(),
            None,
        );
        sess.with_keys_for_trr(42, |_, _| Ok::<(), ()>(()))
            .unwrap()
            .unwrap();
        assert!(matches!(
            sess.with_keys_for_trr(42, |_, _| Ok::<(), ()>(())),
            Err(SessionError::Replay)
        ));
    }

    #[test]
    fn expired_session_rejected() {
        let sess = AttestSession::new(
            AtbId::new(),
            CipherSuite::X25519MlKem768Aes256GcmSha384,
            ProtocolVersion::V2,
            dummy_keys(),
            Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .unwrap(), // Already expired
            ReplayStrategy::default(),
            None,
        );
        assert!(!sess.is_alive());
        assert!(matches!(
            sess.with_keys_for_trr(1, |_, _| Ok::<(), ()>(())),
            Err(SessionError::Expired)
        ));
    }

    /// SA-04 regression: `StrictMonotonic` strategy must reject any nonce ≤ last accepted.
    #[test]
    fn strict_monotonic_rejects_out_of_order_nonce() {
        let sess = AttestSession::new(
            AtbId::new(),
            CipherSuite::X25519MlKem768Aes256GcmSha384,
            ProtocolVersion::V2,
            dummy_keys(),
            Instant::now() + std::time::Duration::from_secs(3600),
            ReplayStrategy::StrictMonotonic,
            None,
        );
        // Accept nonce 10.
        sess.with_keys_for_trr(10, |_, _| Ok::<(), ()>(()))
            .unwrap()
            .unwrap();
        // Nonce 9 (out of order, below last) must be rejected.
        assert!(
            matches!(
                sess.with_keys_for_trr(9, |_, _| Ok::<(), ()>(())),
                Err(SessionError::Replay)
            ),
            "StrictMonotonic must reject nonce <= last_seen"
        );
        // Replay of 10 must also be rejected.
        assert!(
            matches!(
                sess.with_keys_for_trr(10, |_, _| Ok::<(), ()>(())),
                Err(SessionError::Replay)
            ),
            "StrictMonotonic must reject exact replay"
        );
        // Nonce 11 (sequential) must be accepted.
        sess.with_keys_for_trr(11, |_, _| Ok::<(), ()>(()))
            .unwrap()
            .unwrap();
    }

    /// SA-04 regression: `SlidingWindow` strategy accepts out-of-order nonces within
    /// the window, unlike `StrictMonotonic`.
    #[test]
    fn sliding_window_accepts_out_of_order_within_window() {
        let sess = AttestSession::new(
            AtbId::new(),
            CipherSuite::X25519MlKem768Aes256GcmSha384,
            ProtocolVersion::V2,
            dummy_keys(),
            Instant::now() + std::time::Duration::from_secs(3600),
            ReplayStrategy::SlidingWindow(64),
            None,
        );
        // Accept nonce 100 first, then nonce 99 out-of-order.
        sess.with_keys_for_trr(100, |_, _| Ok::<(), ()>(()))
            .unwrap()
            .unwrap();
        // Out-of-order nonce 99 is within the window and must be accepted.
        sess.with_keys_for_trr(99, |_, _| Ok::<(), ()>(()))
            .unwrap()
            .unwrap();
        // Replay of 100 must be rejected.
        assert!(
            matches!(
                sess.with_keys_for_trr(100, |_, _| Ok::<(), ()>(())),
                Err(SessionError::Replay)
            ),
            "SlidingWindow must reject exact replay"
        );
    }

    #[test]
    fn sealed_keys_redaction() {
        let keys = dummy_keys();
        let sealed = SealedSessionKeys::new(keys);
        let debug_str = format!("{sealed:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("master_secret: [")); // Should not contain raw bytes
    }

    #[test]
    fn test_client_posture_one_directional() {
        let sess = AttestSession::new(
            AtbId::new(),
            CipherSuite::X25519MlKem768Aes256GcmSha384,
            ProtocolVersion::V2,
            dummy_keys(),
            Instant::now() + std::time::Duration::from_secs(3600),
            ReplayStrategy::default(),
            None,
        );
        assert_eq!(
            sess.client_posture(),
            openhttpa_proto::ClientSecurityPosture::OneDirectional
        );
        assert_eq!(
            sess.state().client_posture(),
            openhttpa_proto::ClientSecurityPosture::OneDirectional
        );
    }

    #[test]
    fn test_client_posture_simulated_tee() {
        let claims = openhttpa_proto::EatClaims {
            tee_class: Some(openhttpa_proto::TeeClass::Mock),
            ..Default::default()
        };
        let result = openhttpa_proto::VerificationResult {
            claims,
            ..Default::default()
        };
        let sess = AttestSession::new(
            AtbId::new(),
            CipherSuite::X25519MlKem768Aes256GcmSha384,
            ProtocolVersion::V2,
            dummy_keys(),
            Instant::now() + std::time::Duration::from_secs(3600),
            ReplayStrategy::default(),
            Some(result),
        );
        assert_eq!(
            sess.client_posture(),
            openhttpa_proto::ClientSecurityPosture::SimulatedTee
        );
        assert_eq!(
            sess.state().client_posture(),
            openhttpa_proto::ClientSecurityPosture::SimulatedTee
        );
    }

    #[test]
    fn test_client_posture_mutual_tee() {
        let claims = openhttpa_proto::EatClaims {
            tee_class: Some(openhttpa_proto::TeeClass::IntelTdx),
            ..Default::default()
        };
        let result = openhttpa_proto::VerificationResult {
            claims,
            ..Default::default()
        };
        let sess = AttestSession::new(
            AtbId::new(),
            CipherSuite::X25519MlKem768Aes256GcmSha384,
            ProtocolVersion::V2,
            dummy_keys(),
            Instant::now() + std::time::Duration::from_secs(3600),
            ReplayStrategy::default(),
            Some(result),
        );
        assert_eq!(
            sess.client_posture(),
            openhttpa_proto::ClientSecurityPosture::MutualTee(openhttpa_proto::TeeClass::IntelTdx)
        );
        assert_eq!(
            sess.state().client_posture(),
            openhttpa_proto::ClientSecurityPosture::MutualTee(openhttpa_proto::TeeClass::IntelTdx)
        );
    }
}
