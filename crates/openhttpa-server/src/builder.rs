// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use crate::handlers::ChallengeKey;
use crate::handlers::{AtHsHandlerState, aths_handler};
use crate::{AtbRegistry, RateLimitLayer, TrRequestLayer};
use axum::{Router, routing::any};
use openhttpa_attestation::verifier::QuoteVerifier;
use openhttpa_core::handshake::AtHsExecutor;
use openhttpa_crypto::pqc::MlDsaKeyPair;
use openhttpa_tee::provider::TeeProvider;
use std::sync::Arc;
use std::time::Duration;

pub struct OpenHttpaServerBuilder {
    registry: AtbRegistry,
    executor: Option<Arc<AtHsExecutor>>,
    tee_provider: Option<Arc<dyn TeeProvider>>,
    verifier: Option<Arc<dyn QuoteVerifier>>,
    atb_ttl: Duration,
    challenge_key: ChallengeKey,
    identity_key: Option<MlDsaKeyPair>,
    rate_limit: Option<RateLimitLayer>,
}

impl Default for OpenHttpaServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenHttpaServerBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            registry: AtbRegistry::new(),
            executor: None,
            tee_provider: None,
            verifier: None,
            atb_ttl: Duration::from_secs(3600),
            challenge_key: ChallengeKey::new([0u8; 32]),
            identity_key: None,
            rate_limit: None,
        }
    }

    #[must_use]
    pub fn with_registry(mut self, registry: AtbRegistry) -> Self {
        self.registry = registry;
        self
    }

    #[must_use]
    pub fn with_executor(mut self, executor: Arc<AtHsExecutor>) -> Self {
        self.executor = Some(executor);
        self
    }

    #[must_use]
    pub fn with_tee_provider(mut self, provider: Arc<dyn TeeProvider>) -> Self {
        self.tee_provider = Some(provider);
        self
    }

    #[must_use]
    pub fn with_verifier(mut self, verifier: Arc<dyn QuoteVerifier>) -> Self {
        self.verifier = Some(verifier);
        self
    }

    #[must_use]
    pub const fn with_atb_ttl(mut self, ttl: Duration) -> Self {
        self.atb_ttl = ttl;
        self
    }

    #[must_use]
    pub fn with_challenge_key(mut self, key: [u8; 32]) -> Self {
        self.challenge_key = ChallengeKey::new(key);
        self
    }

    #[must_use]
    pub fn with_identity_key(mut self, key: MlDsaKeyPair) -> Self {
        self.identity_key = Some(key);
        self
    }

    #[must_use]
    pub fn with_rate_limit(mut self, layer: RateLimitLayer) -> Self {
        self.rate_limit = Some(layer);
        self
    }

    pub fn build(self) -> Router {
        let executor = self
            .executor
            .unwrap_or_else(|| Arc::new(AtHsExecutor::new(vec![], vec![])));

        let state = Arc::new(AtHsHandlerState {
            executor,
            registry: self.registry.clone(),
            tee_provider: self
                .tee_provider
                .unwrap_or_else(|| Arc::new(openhttpa_tee::mock::MockTeeProvider::default())),
            verifier: self.verifier,
            atb_ttl: self.atb_ttl,
            challenge_key: self.challenge_key,
            identity_key: self.identity_key.map(Arc::new),
        });

        let mut router = Router::new()
            .route("/attest", any(aths_handler))
            .with_state(state)
            .layer(TrRequestLayer::new(self.registry));

        if let Some(rl) = self.rate_limit {
            router = router.layer(rl);
        }

        router
    }
}
