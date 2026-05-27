// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use openhttpa_crypto::hkdf::SessionKeys;
use openhttpa_proto::{AtbId, CipherSuite, ProtocolVersion, VerificationResult};
use std::time::Instant;

use crate::session::{AttestSession, ReplayStrategy};
use crate::state::{AtHsInProgress, Init};

pub struct SessionBuilder<State> {
    state: std::marker::PhantomData<State>,
}

impl Default for SessionBuilder<Init> {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionBuilder<Init> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: std::marker::PhantomData,
        }
    }

    #[must_use]
    pub const fn begin_handshake(self) -> SessionBuilder<AtHsInProgress> {
        SessionBuilder {
            state: std::marker::PhantomData,
        }
    }
}

impl SessionBuilder<AtHsInProgress> {
    #[must_use]
    pub fn complete_handshake(
        self,
        id: AtbId,
        cipher_suite: CipherSuite,
        version: ProtocolVersion,
        keys: SessionKeys,
        expires_at: Instant,
        strategy: ReplayStrategy,
        attestation_result: Option<VerificationResult>,
    ) -> AttestSession {
        AttestSession::new(
            id,
            cipher_suite,
            version,
            keys,
            expires_at,
            strategy,
            attestation_result,
        )
    }
}
