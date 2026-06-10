// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! `OpenHTTPA` protocol phase state machine.

use std::collections::HashMap;
use thiserror::Error;
use tokio::sync::RwLock;

use serde::{Deserialize, Serialize};

pub struct Init;
pub struct AtHsInProgress;
pub struct Attested;

/// Each `OpenHTTPA` session progresses through these phases in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtocolPhase {
    /// Initial state; no handshake started.
    Init,
    /// Preflight OPTIONS exchange completed.
    Preflight,
    /// `AtHS` (Attest Handshake) in progress.
    AtHsInProgress,
    /// `AtHS` completed; session key material established; `AtB` allocated.
    Attested,
    /// `AtSP` in progress (secret provisioning).
    AtSpInProgress,
    /// Secrets provisioned; trusted requests can be made.
    SecretProvisioned,
    /// 0-RTT flight in progress (resumption).
    Rtt0,
    /// Session terminated (`AtB` destroyed or expired).
    Terminated,
}

impl ProtocolPhase {
    /// Returns `true` if trusted requests are permitted in this phase.
    #[must_use]
    pub const fn allows_trusted_request(self) -> bool {
        matches!(self, Self::Attested | Self::SecretProvisioned | Self::Rtt0)
    }
}

/// A state-transition error.
// MED-06: non_exhaustive prevents breaking changes when new variants are added.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum TransitionError {
    #[error("invalid phase transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: ProtocolPhase,
        to: ProtocolPhase,
    },
    #[error("operation not permitted in phase {phase:?}")]
    NotPermitted { phase: ProtocolPhase },
}

/// Validate and perform a phase transition.
///
/// # Errors
///
/// Returns [`Err`](`TransitionError::InvalidTransition`) if the transition from
/// `current` to `next` is not a valid protocol step.
pub const fn transition(
    current: ProtocolPhase,
    next: ProtocolPhase,
) -> Result<ProtocolPhase, TransitionError> {
    let valid = matches!(
        (current, next),
        (
            ProtocolPhase::Init,
            ProtocolPhase::Preflight | ProtocolPhase::AtHsInProgress | ProtocolPhase::Rtt0,
        ) | (ProtocolPhase::Preflight, ProtocolPhase::AtHsInProgress)
            | (
                ProtocolPhase::AtHsInProgress | ProtocolPhase::Rtt0,
                ProtocolPhase::Attested
            )
            | (
                ProtocolPhase::Attested,
                ProtocolPhase::AtSpInProgress | ProtocolPhase::Terminated,
            )
            | (
                ProtocolPhase::AtSpInProgress,
                ProtocolPhase::SecretProvisioned
            )
            | (
                ProtocolPhase::SecretProvisioned | ProtocolPhase::Rtt0,
                ProtocolPhase::Terminated
            )
    );
    if valid {
        Ok(next)
    } else {
        Err(TransitionError::InvalidTransition {
            from: current,
            to: next,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_handshake_path() {
        let mut phase = ProtocolPhase::Init;
        phase = transition(phase, ProtocolPhase::AtHsInProgress).unwrap();
        phase = transition(phase, ProtocolPhase::Attested).unwrap();
        assert!(phase.allows_trusted_request());
    }

    #[test]
    fn invalid_transition_rejected() {
        let res = transition(ProtocolPhase::Init, ProtocolPhase::Attested);
        assert!(res.is_err());
    }
}

/// A store for Pre-Shared Keys (PSKs) used for session resumption.
///
/// # Security properties (REL-01 fixes)
///
/// - **TTL enforcement**: every PSK is stored with an `expires_at` timestamp;
///   `take_psk` refuses to return expired tickets and schedules them for
///   cleanup.  Default lifetime is 24 hours; use [`PskStore::with_ttl`] to
///   customise.
/// - **Bounded capacity**: the store is capped at [`PskStore::MAX_CAPACITY`]
///   entries (10 000 by default) to prevent unbounded memory growth.
///   When the cap is reached, the oldest entries (by expiry) are evicted.
/// - **Single-use**: `take_psk` removes the ticket on first use to prevent
///   replay attacks.
#[derive(Debug)]
pub struct PskStore {
    /// Maps ticket IDs to (PSK, expiry) pairs.
    tickets: RwLock<HashMap<Vec<u8>, PskEntry>>,
    /// Maximum number of unexpired tickets.
    max_capacity: usize,
    /// How long a stored PSK is valid after insertion.
    psk_ttl: std::time::Duration,
}

#[derive(Debug)]
struct PskEntry {
    psk: zeroize::Zeroizing<Vec<u8>>,
    expires_at: std::time::Instant,
}

impl Default for PskStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PskStore {
    /// Default cap on in-memory PSK tickets.
    pub const MAX_CAPACITY: usize = 10_000;

    /// Default PSK lifetime (24 hours — SIGMA-I recommendation).
    pub const DEFAULT_TTL: std::time::Duration = std::time::Duration::from_secs(86_400);

    #[must_use]
    pub fn new() -> Self {
        Self {
            tickets: RwLock::new(HashMap::new()),
            max_capacity: Self::MAX_CAPACITY,
            psk_ttl: Self::DEFAULT_TTL,
        }
    }

    /// Create a store with a custom TTL and capacity.
    #[must_use]
    pub const fn with_ttl(mut self, ttl: std::time::Duration) -> Self {
        self.psk_ttl = ttl;
        self
    }

    /// Create a store with a custom capacity.
    #[must_use]
    pub const fn with_capacity(mut self, cap: usize) -> Self {
        self.max_capacity = cap;
        self
    }

    /// Store a PSK associated with a ticket ID.
    ///
    /// Returns `false` if the store is at capacity after eviction and the
    /// new entry cannot be stored.
    pub async fn store_psk(&self, ticket_id: Vec<u8>, psk: Vec<u8>) -> bool {
        let mut tickets = self.tickets.write().await;

        // 1. Purge expired tickets first to reclaim space.
        let now = std::time::Instant::now();
        tickets.retain(|_, v| v.expires_at > now);

        // 2. Enforce capacity: evict the ticket with the earliest expiry.
        while tickets.len() >= self.max_capacity {
            let oldest_key = tickets
                .iter()
                .min_by_key(|(_, v)| v.expires_at)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest_key {
                tickets.remove(&k);
            } else {
                break;
            }
        }

        // 3. Refuse to store if we're somehow still at capacity.
        if tickets.len() >= self.max_capacity {
            tracing::error!(
                "PskStore at maximum capacity ({}) — refusing to store new ticket",
                self.max_capacity
            );
            return false;
        }

        tickets.insert(
            ticket_id,
            PskEntry {
                psk: zeroize::Zeroizing::new(psk),
                expires_at: now + self.psk_ttl,
            },
        );
        true
    }

    /// Retrieve and remove a PSK associated with a ticket ID (single-use tickets).
    ///
    /// Returns `None` if the ticket does not exist or has expired.
    pub async fn take_psk(&self, ticket_id: &[u8]) -> Option<Vec<u8>> {
        let mut tickets = self.tickets.write().await;
        match tickets.remove(ticket_id) {
            Some(entry) if entry.expires_at > std::time::Instant::now() => Some(entry.psk.to_vec()),
            Some(_expired) => {
                // Ticket existed but has expired — treat as absent.
                tracing::debug!("PskStore: ticket expired and discarded on take_psk");
                None
            }
            None => None,
        }
    }

    /// Remove all expired tickets.  Call periodically from a background task.
    pub async fn purge_expired(&self) {
        let mut tickets = self.tickets.write().await;
        let now = std::time::Instant::now();
        let before = tickets.len();
        tickets.retain(|_, v| v.expires_at > now);
        let purged = before.saturating_sub(tickets.len());
        drop(tickets);
        if purged > 0 {
            tracing::debug!("PskStore: purged {} expired ticket(s)", purged);
        }
    }

    /// Return the number of stored (including possibly-expired) tickets.
    pub async fn len(&self) -> usize {
        self.tickets.read().await.len()
    }

    /// Return `true` if no tickets are stored.
    pub async fn is_empty(&self) -> bool {
        self.tickets.read().await.is_empty()
    }
}
