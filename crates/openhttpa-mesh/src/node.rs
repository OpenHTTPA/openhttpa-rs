// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use dashmap::DashMap;
use std::sync::Arc;
use tracing::{info, instrument};
use uuid::Uuid;

use openhttpa_attestation::verifier::QuoteVerifier;
use openhttpa_client::OpenHttpaClient;
use openhttpa_mcp::server::OpenHttpaMcpServer;
use openhttpa_tee::provider::TeeProvider;
use openhttpa_transport::connection::AttestTransport;

use crate::{
    policy::PolicyEngine, registry::AgentRegistry, AgentMetadata, AgentSession, MeshError,
};

/// An attested AI agent node in the mesh.
pub struct AgentNode {
    metadata: AgentMetadata,
    mcp_server: Arc<OpenHttpaMcpServer>,
    registry: Arc<dyn AgentRegistry>,
    sessions: DashMap<Uuid, Arc<AgentSession>>,
    tee_provider: Arc<dyn TeeProvider>,
    verifier: Arc<dyn QuoteVerifier>,
    transport: Arc<dyn AttestTransport>,
    policy_engine: Arc<dyn PolicyEngine>,
    heartbeat_handle: Option<tokio::task::JoinHandle<()>>,
}

impl AgentNode {
    /// Create a new `AgentNode`.
    #[must_use]
    pub fn new(
        name: String,
        capabilities: Vec<String>,
        endpoint: String,
        registry: Arc<dyn AgentRegistry>,
        tee_provider: Arc<dyn TeeProvider>,
        verifier: Arc<dyn QuoteVerifier>,
        transport: Arc<dyn AttestTransport>,
        policy_engine: Arc<dyn PolicyEngine>,
    ) -> Self {
        let id = Uuid::new_v4();
        let metadata = AgentMetadata {
            id,
            name,
            capabilities,
            endpoint,
            public_key: vec![], // In a real impl, this would be generated in TEE
            last_quote: None,
        };

        Self {
            metadata,
            mcp_server: Arc::new(OpenHttpaMcpServer::new()),
            registry,
            sessions: DashMap::new(),
            tee_provider,
            verifier,
            transport,
            policy_engine,
            heartbeat_handle: None,
        }
    }

    /// Get the agent's metadata.
    pub const fn metadata(&self) -> &AgentMetadata {
        &self.metadata
    }

    /// Get the internal MCP server to add tools.
    pub fn mcp_server(&self) -> Arc<OpenHttpaMcpServer> {
        self.mcp_server.clone()
    }

    /// Establish an attested session with another agent.
    #[instrument(skip(self), fields(agent_id = %peer_id))]
    /// Connect to a peer by ID.
    ///
    /// # Errors
    /// Returns [`MeshError`] if the peer is not found or handshake fails.
    pub async fn connect_to_peer(&self, peer_id: Uuid) -> Result<Arc<AgentSession>, MeshError> {
        if let Some(session) = self.sessions.get(&peer_id) {
            if session.session.is_alive() {
                return Ok(session.clone());
            }
        }

        let peer_metadata = self
            .registry
            .get_agent(peer_id)
            .await
            .map_err(MeshError::Registry)?
            .ok_or_else(|| MeshError::PeerNotFound(peer_id.to_string()))?;

        info!(
            "Establishing mutual `OpenHTTPA` handshake with peer: {}",
            peer_metadata.name
        );

        let client = OpenHttpaClient::builder()
            .server_uri(
                peer_metadata
                    .endpoint
                    .parse()
                    .map_err(|e| MeshError::Handshake(format!("Invalid endpoint: {e}")))?,
            )
            .tee_provider(self.tee_provider.clone())
            .verifier(self.verifier.clone())
            .transport(self.transport.clone())
            .build()
            .strict_attestation(true);

        let session = client
            .attest_handshake()
            .await
            .map_err(|e| MeshError::Handshake(e.to_string()))?;

        // M3: Policy Enforcement
        if let Some(ref res) = session.state().attestation_result {
            let policy_input = serde_json::json!({
                "src_id": self.metadata.id.to_string(),
                "dst_id": peer_id.to_string(),
                "claims": res.claims,
                "tcb_status": res.tcb_status,
                "pqc_bound": session.state().cipher_suite.is_post_quantum(),
                "timestamp": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            });

            let result = self
                .policy_engine
                .evaluate_ext("default", policy_input)
                .await?;
            if !result.allow {
                return Err(MeshError::Attestation(format!(
                    "Peer failed to satisfy mesh admission policy '{}'",
                    result.policy_id
                )));
            }
            info!(policy_id = %result.policy_id, "Peer satisfied mesh admission policy");
        }

        let agent_session = Arc::new(AgentSession {
            peer_metadata,
            session: Arc::new(session),
        });

        self.sessions.insert(peer_id, agent_session.clone());
        Ok(agent_session)
    }

    /// Call a tool on a peer agent confidentially.
    /// Call a tool on a peer agent.
    ///
    /// # Errors
    /// Returns [`MeshError`] if connection fails or tool execution errors.
    ///
    /// # Panics
    /// Panics if the peer endpoint is invalid.
    /// Call a tool on a peer agent confidentially with provenance tracking.
    pub async fn call_peer_tool(
        &self,
        peer_id: Uuid,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, MeshError> {
        self.call_peer_tool_with_provenance(
            peer_id,
            method,
            params,
            openhttpa_proto::ProvenanceChain::default(),
        )
        .await
    }

    /// Call a tool on a peer agent with an existing provenance chain.
    ///
    /// # Errors
    /// Returns [`MeshError`] if connection fails, tool execution errors, or
    /// provenance serialization fails.
    ///
    /// # Panics
    /// Panics if the provenance JSON contains invalid header characters or if
    /// the peer endpoint is invalid.
    #[instrument(skip(self, params, provenance), fields(peer_id = %peer_id, method = %method))]
    pub async fn call_peer_tool_with_provenance(
        &self,
        peer_id: Uuid,
        method: &str,
        params: serde_json::Value,
        mut provenance: openhttpa_proto::ProvenanceChain,
    ) -> Result<serde_json::Value, MeshError> {
        let session = self.connect_to_peer(peer_id).await?;

        // Append current node to the provenance chain (P-01).
        provenance.append(self.metadata.clone());

        // Construct MCP request
        let mcp_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": Uuid::new_v4().to_string(),
            "method": method,
            "params": params
        });

        let req_bytes = serde_json::to_vec(&mcp_req)
            .map_err(|e| MeshError::Mcp(format!("Serialization error: {e}")))?;

        // Prepare extra headers for provenance.
        let mut extra_headers = http::HeaderMap::new();
        let prov_bytes = serde_json::to_vec(&provenance)
            .map_err(|e| MeshError::Handshake(format!("Provenance serialization failed: {e}")))?;

        // `OpenHTTPA` requires all Attest-* headers to be SFV-encoded (Byte Sequence).
        // This prevents header injection and ensures ASCII-safe transport.
        let prov_header = openhttpa_headers::encode_attest_provenance(&prov_bytes);
        extra_headers.insert(&*openhttpa_headers::HDR_ATTEST_PROVENANCE, prov_header);

        let client = OpenHttpaClient::builder()
            .server_uri(session.peer_metadata.endpoint.parse().unwrap())
            .tee_provider(self.tee_provider.clone())
            .verifier(self.verifier.clone())
            .transport(self.transport.clone())
            .build()
            .strict_attestation(true);

        let response_bytes = client
            .trusted_request_ext(
                &session.session,
                "POST",
                "/api/mcp",
                &req_bytes,
                Some(extra_headers),
            )
            .await
            .map_err(|e| MeshError::Handshake(e.to_string()))?;

        let res_json: serde_json::Value = serde_json::from_slice(&response_bytes)
            .map_err(|e| MeshError::Mcp(format!("Deserialization error: {e}")))?;

        Ok(res_json)
    }

    /// Start the background heartbeat task.
    pub fn start_heartbeat(&mut self, interval: std::time::Duration) {
        if self.heartbeat_handle.is_some() {
            return;
        }

        let registry = self.registry.clone();
        let id = self.metadata.id;

        let handle = tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            loop {
                timer.tick().await;
                if let Err(e) = registry.heartbeat(id).await {
                    tracing::error!(id = %id, error = %e, "Heartbeat failed");
                }
            }
        });

        self.heartbeat_handle = Some(handle);
    }
}

impl Drop for AgentNode {
    fn drop(&mut self) {
        if let Some(handle) = self.heartbeat_handle.take() {
            handle.abort();
        }
    }
}
