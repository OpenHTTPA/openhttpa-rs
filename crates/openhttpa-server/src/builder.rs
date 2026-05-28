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
    fabric_config: Option<(
        String,
        Vec<String>,
        String,
        openhttpa_fabric::store::Topology,
    )>,
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
            fabric_config: None,
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

    #[must_use]
    pub fn with_fabric(
        mut self,
        name: String,
        capabilities: Vec<String>,
        endpoint: String,
        topology: openhttpa_fabric::store::Topology,
    ) -> Self {
        self.fabric_config = Some((name, capabilities, endpoint, topology));
        self
    }

    /// Automatically detects all available hardware TEEs and federates them for maximum security.
    /// Optionally wraps the federated provider in a ZK-compressed attestation (ZAA).
    #[must_use]
    pub fn with_auto_attestation(mut self, use_zk_compression: bool) -> Self {
        let config = openhttpa_tee::provider::TeeConfig::default();

        let provider: Arc<dyn TeeProvider> = match openhttpa_tee::provider::detect_all_providers(
            &config,
        ) {
            Ok(composite) => {
                let composite_arc = Arc::new(composite);
                #[cfg(feature = "zaa")]
                if use_zk_compression {
                    tracing::info!("Wrapping composite TEE provider with ZK compression (ZAA)");
                    Arc::new(openhttpa_tee::provider::ZkCompressedTeeProvider::new(
                        composite_arc,
                    ))
                } else {
                    composite_arc
                }

                #[cfg(not(feature = "zaa"))]
                {
                    if use_zk_compression {
                        tracing::warn!(
                            "ZK compression requested but 'zaa' feature is disabled. Proceeding with uncompressed composite provider."
                        );
                    }
                    composite_arc
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Auto-attestation failed to detect hardware TEEs: {}. Falling back to Mock.",
                    e
                );
                Arc::new(openhttpa_tee::mock::MockTeeProvider::default())
            }
        };

        self.tee_provider = Some(provider);
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

    /// Builds the server router and wires up the Attested Agentic Mesh Fabric.
    /// Returns a tuple of `(Router, Arc<openhttpa_mesh::AgentNode>)`.
    ///
    /// # Panics
    /// Panics if `fabric_config` or `tee_provider` is not set.
    pub fn build_fabric(self) -> (Router, Arc<openhttpa_mesh::AgentNode>) {
        let (name, caps, endpoint, _topology) = self
            .fabric_config
            .clone()
            .expect("fabric_config must be set via with_fabric");
        let tee_provider = self.tee_provider.clone().expect("tee_provider must be set");
        let verifier = self.verifier.clone().unwrap_or_else(|| {
            Arc::new(openhttpa_attestation::mock_verifier::MockVerifier::new(
                openhttpa_attestation::verifier::VerificationResult::default(),
            ))
        });

        let transport = Arc::new(openhttpa_transport::h2_adapter::H2Transport::new(
            endpoint.parse().unwrap(),
        ));
        let policy_engine = Arc::new(openhttpa_mesh::policy::RegoPolicyEngine::permissive());
        let agent_registry = Arc::new(openhttpa_mesh::registry::MockRegistry::new());

        let agent_node = openhttpa_mesh::AgentNode::new(
            name,
            caps,
            endpoint.clone(),
            agent_registry,
            tee_provider.clone(),
            verifier.clone(),
            transport,
            policy_engine,
        );
        let agent_node = Arc::new(agent_node);

        // We use A2AAgent for A2A communication, which ReplicationManager needs.
        let a2a_client = openhttpa_client::OpenHttpaClient::builder()
            .server_uri(endpoint.parse().unwrap())
            .build();
        let a2a_agent = Arc::new(openhttpa_a2a::A2AAgent::new_with_client(
            &agent_node.metadata().id.to_string(),
            a2a_client,
        ));

        let replication_manager = Arc::new(openhttpa_fabric::ReplicationManager::new(
            agent_node.fabric_store.clone(),
            a2a_agent as Arc<dyn openhttpa_fabric::ReplicationTransport>,
            verifier.clone(),
            tee_provider.clone(),
        ));

        let metrics = Arc::new(openhttpa_fabric::metrics::FabricMetrics::default());
        replication_manager.start_gossip_loop(vec![], metrics);

        // Also register fabric tools on the node's MCP server
        // In a real app we would await this, but we're in a sync build method.
        // We'll spawn it.
        let node_clone = agent_node.clone();
        tokio::spawn(async move {
            node_clone.register_fabric_tools().await;
        });

        let router = self.build();
        // Here we could mount the node's MCP server into the axum router if we had the routes.

        (router, agent_node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_default() {
        let builder = OpenHttpaServerBuilder::default();
        let _router = builder.build();
    }

    #[test]
    fn test_builder_with_options() {
        let builder = OpenHttpaServerBuilder::new()
            .with_atb_ttl(Duration::from_secs(1234))
            .with_challenge_key([1u8; 32])
            .with_registry(AtbRegistry::new());
        let _router = builder.build();
    }
}
