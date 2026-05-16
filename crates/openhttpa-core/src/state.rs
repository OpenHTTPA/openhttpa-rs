// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! `OpenHTTPA` protocol phase state machine.

use std::collections::HashMap;
use thiserror::Error;
use tokio::sync::RwLock;

use serde::{Deserialize, Serialize};

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
#[derive(Debug, Default)]
pub struct PskStore {
    /// Maps ticket IDs to session secrets.
    tickets: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

impl PskStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a PSK associated with a ticket ID.
    pub async fn store_psk(&self, ticket_id: Vec<u8>, psk: Vec<u8>) {
        let mut tickets = self.tickets.write().await;
        tickets.insert(ticket_id, psk);
    }

    /// Retrieve and remove a PSK associated with a ticket ID (single-use tickets).
    pub async fn take_psk(&self, ticket_id: &[u8]) -> Option<Vec<u8>> {
        let mut tickets = self.tickets.write().await;
        tickets.remove(ticket_id)
    }
}
