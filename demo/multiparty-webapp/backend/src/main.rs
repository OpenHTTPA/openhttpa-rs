// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use async_trait::async_trait;
use axum::extract::ws::WebSocketUpgrade;
use axum::{
    Router,
    extract::{FromRef, Json, State},
    http::{HeaderMap, HeaderName, StatusCode, header::CONTENT_TYPE},
    response::IntoResponse,
    routing::{get, post},
};
use http::HeaderValue;
use openhttpa_attestation::MockVerifier;
use openhttpa_core::handshake::AtHsExecutor;
use openhttpa_core::session::{AttestSession, ReplayStrategy};
use openhttpa_mcp::server::{McpTool, OpenHttpaMcpServer};
use openhttpa_proto::ProtocolVersion;
use openhttpa_server::{
    AtbRegistry, AttestWsHandler, AttestWsSession, AttestWsState, EncryptedJson, OpenHttpaSession,
    WsPayload, attested_ws_upgrade,
    handlers::{
        AtHsHandlerState, ChallengeKey, PreflightHandlerState, aths_handler, preflight_handler,
    },
};
use openhttpa_tee::{TeeConfig, TeeProvider, detect_best_provider};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::{net::TcpListener, sync::broadcast};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{debug, error, info, warn};

#[derive(Clone)]
struct AppState(Arc<DemoState>);

impl std::ops::Deref for AppState {
    type Target = DemoState;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromRef<AppState> for AtbRegistry {
    fn from_ref(state: &AppState) -> Self {
        state.registry.clone()
    }
}

struct DemoState {
    registry: AtbRegistry,
    parties: RwLock<std::collections::HashMap<String, i64>>,
    mcp_server: Arc<OpenHttpaMcpServer>,
    aths_state: Arc<AtHsHandlerState>,
    ws_state: Arc<AttestWsState<WsChatHandler>>,
    preflight_state: Arc<PreflightHandlerState>,
    tee_type: openhttpa_proto::QuoteType,
    identity_key: Arc<openhttpa_crypto::pqc::MlDsaKeyPair>,
    oracle_node: Arc<openhttpa_oracle::oracle::OracleNode>,
    ticket_engine: Arc<openhttpa_core::session::ticket::TicketEngine>,
}

impl Default for DemoState {
    fn default() -> Self {
        let registry = AtbRegistry::new();
        let mcp_server = Arc::new(OpenHttpaMcpServer::new());
        #[allow(unused_mut)]
        let mut aths_executor = AtHsExecutor::with_config(
            vec![],
            vec![ProtocolVersion::V2, ProtocolVersion::V1],
            false,
            true,
        );

        #[cfg(feature = "zk")]
        {
            if std::env::var("OPENHTTPA_ZK_ENABLED").is_ok() {
                info!("ZK-proving is ENABLED for this server session.");
                aths_executor = aths_executor.with_zk(openhttpa_zk::ZkConfig {
                    enabled: true,
                    use_mock_prover: true, // Use mock/executor mode for demo stability
                });
            }
        }

        let aths_executor = Arc::new(aths_executor);

        // Use auto-detection for the TEE provider.
        // For the demo, we allow fallback to Mock but will flag it in the UI.
        let tee_config = TeeConfig {
            allow_mock: true,
            ..Default::default()
        };
        let tee_provider =
            detect_best_provider(&tee_config).expect("TEE detection failed even with mock enabled");

        // For the demo/test environment, we always want a composite CPU+GPU view if possible.
        // If we are in mock mode, we force a composite of TDX + NVIDIA GPU.
        let composite_tee = if tee_provider.quote_type() == openhttpa_proto::QuoteType::Mock {
            Arc::new(openhttpa_tee::provider::CompositeTeeProvider::new(vec![
                Arc::new(openhttpa_tee::mock::MockTeeProvider::with_override(
                    openhttpa_proto::QuoteType::Tdx,
                )),
                Arc::new(openhttpa_tee::mock::MockTeeProvider::with_override(
                    openhttpa_proto::QuoteType::NvidiaGpu,
                )),
            ]))
        } else {
            Arc::new(openhttpa_tee::provider::CompositeTeeProvider::new(vec![
                tee_provider,
            ]))
        };
        let tee_type = composite_tee.quote_type();

        let identity_key = Arc::new(openhttpa_crypto::pqc::MlDsaKeyPair::generate().unwrap());

        let challenge_key: ChallengeKey = demo_challenge_key("OPENHTTPA_CHALLENGE_KEY").into();

        let aths_state = Arc::new(AtHsHandlerState {
            executor: aths_executor,
            registry: registry.clone(),
            tee_provider: composite_tee.clone(),
            verifier: Some(Arc::new(MockVerifier::default())),
            atb_ttl: Duration::from_secs(3600),
            // SEC-KEY-01: derive key from env var; fall back to random bytes in
            // debug builds only. NEVER use an all-zero key in production.
            challenge_key: challenge_key.clone(),
            identity_key: Some(identity_key.clone()),
        });

        let (tx, _rx) = broadcast::channel::<WsPayload>(100);
        let ws_handler = Arc::new(WsChatHandler { tx });
        let ws_state = Arc::new(AttestWsState::new(registry.clone(), ws_handler));

        let preflight_state = Arc::new(PreflightHandlerState {
            cipher_suites: vec![openhttpa_proto::CipherSuite::X25519MlKem768Aes256GcmSha384],
            versions: vec![ProtocolVersion::V2],
            // SEC-KEY-01: derive key from env var; fall back to random bytes in
            // debug builds only. NEVER use an all-zero key in production.
            challenge_key,
            oblivious_supported: true,
        });

        Self {
            registry,
            parties: RwLock::new(std::collections::HashMap::new()),
            mcp_server,
            aths_state,
            ws_state,
            preflight_state,
            tee_type,
            identity_key: identity_key.clone(),
            oracle_node: Arc::new(openhttpa_oracle::oracle::OracleNode::new(
                composite_tee.clone(),
            )),
            ticket_engine: Arc::new(openhttpa_core::session::ticket::TicketEngine::new(
                openhttpa_core::session::ticket::TicketKey::generate(),
            )),
        }
    }
}

impl FromRef<AppState> for Arc<AtHsHandlerState> {
    fn from_ref(state: &AppState) -> Self {
        state.aths_state.clone()
    }
}

impl FromRef<AppState> for Arc<AttestWsState<WsChatHandler>> {
    fn from_ref(state: &AppState) -> Self {
        state.ws_state.clone()
    }
}

impl FromRef<AppState> for Arc<PreflightHandlerState> {
    fn from_ref(state: &AppState) -> Self {
        state.preflight_state.clone()
    }
}

struct SecureSum;
#[async_trait]
impl McpTool for SecureSum {
    fn name(&self) -> &str {
        "secure_sum"
    }
    fn description(&self) -> Option<&str> {
        Some("Perform a secure multiparty summation")
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "party_id": { "type": "string" },
                "value": { "type": "integer" }
            },
            "required": ["party_id", "value"]
        })
    }
    async fn call(&self, _args: serde_json::Value) -> Result<serde_json::Value, String> {
        Ok(serde_json::json!({ "status": "recorded", "operation": "sum" }))
    }
}

struct SecureAverage;
#[async_trait]
impl McpTool for SecureAverage {
    fn name(&self) -> &str {
        "secure_average"
    }
    fn description(&self) -> Option<&str> {
        Some("Perform a secure multiparty average")
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "party_id": { "type": "string" },
                "value": { "type": "integer" }
            },
            "required": ["party_id", "value"]
        })
    }
    async fn call(&self, _args: serde_json::Value) -> Result<serde_json::Value, String> {
        Ok(serde_json::json!({ "status": "recorded", "operation": "average" }))
    }
}

struct SecureVariance;
#[async_trait]
impl McpTool for SecureVariance {
    fn name(&self) -> &str {
        "secure_variance"
    }
    fn description(&self) -> Option<&str> {
        Some("Perform a secure multiparty variance")
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "party_id": { "type": "string" },
                "value": { "type": "integer" }
            },
            "required": ["party_id", "value"]
        })
    }
    async fn call(&self, _args: serde_json::Value) -> Result<serde_json::Value, String> {
        Ok(serde_json::json!({ "status": "recorded", "operation": "variance" }))
    }
}

#[derive(Deserialize, Serialize)]
struct SubmitRequest {
    party_id: String,
    value: i64,
}

#[derive(Serialize)]
struct SubmitResponse {
    ok: bool,
    status: String,
    current_count: usize,
}

async fn submit(
    State(state): State<AppState>,
    session: OpenHttpaSession,
    EncryptedJson(req): EncryptedJson<SubmitRequest>,
) -> impl IntoResponse {
    let mut parties = state.parties.write().unwrap();
    let party_id = req.party_id.clone();
    parties.insert(req.party_id, req.value);
    info!("Received submission from {}: {}", party_id, req.value);
    session.seal(&SubmitResponse {
        ok: true,
        status: "success".to_string(),
        current_count: parties.len(),
    })
}

async fn result(State(state): State<AppState>, session: OpenHttpaSession) -> impl IntoResponse {
    let parties = state.parties.read().unwrap();
    let sum: i64 = parties.values().sum();
    info!("Current MPC sum: {}", sum);
    session.seal(&serde_json::json!({
        "sum": sum,
        "party_count": parties.len(),
        "attestation_quote": "dGVzdC1xdW90ZQ==" // mock quote
    }))
}

async fn health(State(state): State<AppState>) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "tee": state.tee_type.to_string(),
            "is_mock": state.tee_type == openhttpa_proto::QuoteType::Mock,
            "pqc_pub_key": hex::encode(&state.identity_key.public_key),
        })),
    )
        .into_response()
}

async fn status(State(state): State<AppState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "tee_type": state.tee_type.to_string(),
        "is_mock": state.tee_type == openhttpa_proto::QuoteType::Mock,
        "registry_size": state.registry.len(),
        "party_count": state.parties.read().unwrap().len(),
    }))
}

async fn reset(State(state): State<AppState>, _req: axum::extract::Request) -> impl IntoResponse {
    let mut parties = state.parties.write().unwrap();
    parties.clear();
    info!("MPC state reset");
    StatusCode::OK
}

async fn get_ticket(State(state): State<AppState>, session: OpenHttpaSession) -> impl IntoResponse {
    let durable = session.inner().export_durable();
    let ticket = state
        .ticket_engine
        .seal_session(&durable, Duration::from_secs(3600))
        .expect("seal fail");
    info!("Resumption ticket issued for session {}", session.id());
    Json(ticket)
}

#[derive(Deserialize, Serialize)]
struct EchoRequest {
    message: String,
}

async fn echo(
    State(_state): State<AppState>,
    session: OpenHttpaSession,
    EncryptedJson(req): EncryptedJson<EchoRequest>,
) -> impl IntoResponse {
    let session_id = session.id().to_string();
    session.seal(&serde_json::json!({
        "reply": format!("Echo: {}", req.message),
        "session_id": session_id,
    }))
}

#[derive(Deserialize, Serialize)]
struct OracleFetchRequest {
    url: String,
}

async fn oracle_fetch(
    State(state): State<AppState>,
    session: OpenHttpaSession,
    EncryptedJson(req): EncryptedJson<OracleFetchRequest>,
) -> impl IntoResponse {
    info!("Oracle fetch request for URL: {}", req.url);

    // Perform fetch and prove via OracleNode
    let transcript_hash = match session.transcript_hash() {
        Ok(h) => h,
        Err(status) => return status.into_response(),
    };
    let enable_zk = true;
    match state
        .oracle_node
        .fetch_and_prove(&req.url, transcript_hash, enable_zk)
        .await
    {
        Ok(oracle_res) => match session.seal(&oracle_res) {
            Ok(res) => res,
            Err(res) => res,
        },
        Err(e) => {
            error!("Oracle fetch failed: {}", e);
            match session.seal(&serde_json::json!({
                "error": format!("Oracle fetch failed: {}", e)
            })) {
                Ok(res) => res,
                Err(res) => res,
            }
        }
    }
}

#[derive(Deserialize)]
struct ChatRequest {
    model: String,
    messages: Vec<serde_json::Value>,
    stream: Option<bool>,
}

async fn chat_handle(
    State(_state): State<AppState>,
    session: OpenHttpaSession,
    EncryptedJson(req): EncryptedJson<ChatRequest>,
) -> impl IntoResponse {
    info!("Chat handle received request for model: {}", req.model);
    let last_msg = req
        .messages
        .last()
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .unwrap_or("...")
        .to_owned();

    if req.stream.unwrap_or(false) {
        let tokens = vec![
            "Confidential".to_owned(),
            " reply".to_owned(),
            " from".to_owned(),
            " the".to_owned(),
            " attested".to_owned(),
            " TEE".to_owned(),
            " gateway".to_owned(),
            ": ".to_owned(),
            last_msg,
        ];

        let token_stream = futures::stream::iter(tokens.into_iter().map(|t| {
            Ok::<_, openhttpa_server::LlmError>(serde_json::json!({
                "choices": [{
                    "delta": { "content": t }
                }]
            }))
        }));

        return session.seal_stream(token_stream);
    }

    session
        .seal(&serde_json::json!({
            "id": "chatcmpl-demo",
            "object": "chat.completion",
            "created": 1714615200,
            "model": req.model,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": format!("Confidential reply to: {}", last_msg)
                },
                "finish_reason": "stop"
            }]
        }))
        .unwrap_or_else(|resp| resp)
}

#[derive(Serialize)]
struct SwarmReport {
    agent_count: usize,
    success_rate: f64,
    logs: Vec<String>,
    provenance: Vec<openhttpa_proto::AgentMetadata>,
}

async fn simulate_swarm(State(_state): State<AppState>) -> impl IntoResponse {
    use openhttpa_attestation::verifier::{QuoteVerifier, VerificationError, VerificationResult};
    use openhttpa_mesh::registry::MockRegistry;
    use openhttpa_mesh::{AgentNode, AgentRegistry};
    use openhttpa_proto::AttestQuote;
    use openhttpa_tee::mock::MockTeeProvider;
    use openhttpa_transport::connection::AttestTransport;

    struct MockVerifier;
    #[async_trait]
    impl QuoteVerifier for MockVerifier {
        async fn verify(
            &self,
            _quote: &AttestQuote,
            _report_data: &[u8; 64],
        ) -> Result<VerificationResult, VerificationError> {
            Ok(VerificationResult {
                claims: openhttpa_attestation::verifier::EatClaims {
                    hwmodel: Some("mock".to_string()),
                    hwversion: Some("ok".to_string()),
                    dbgstat: Some(1),
                    boot_progress: Some("mock-measurement".to_string()),
                    ..Default::default()
                },
                tcb_status: "UpToDate".to_string(),
                measurement: Some("mock-measurement".to_string()),
                signer_id: Some("mock-signer".to_string()),
                ..Default::default()
            })
        }
    }

    struct LocalTransport;
    #[async_trait]
    impl AttestTransport for LocalTransport {
        async fn send(
            &self,
            req: openhttpa_transport::connection::TransportRequest,
        ) -> Result<
            openhttpa_transport::connection::TransportResponse,
            openhttpa_transport::connection::SendError,
        > {
            if req.method.as_str() == "ATTEST" {
                use openhttpa_core::handshake::{ClientKeyShare, ServerKeyShare};
                use openhttpa_crypto::key_exchange::{HybridKemPair, KeyShare};
                use openhttpa_headers::attest_headers::{AtHsRequestHeaders, AtHsResponseHeaders};
                use openhttpa_proto::{AttestQuote, CipherSuite, ProtocolVersion, QuoteType};

                let req_hdrs = AtHsRequestHeaders::decode(&req.headers).map_err(|e| {
                    openhttpa_transport::connection::SendError::Protocol(format!(
                        "header decode: {}",
                        e
                    ))
                })?;
                let client_share: ClientKeyShare =
                    serde_json::from_slice(&req_hdrs.key_shares_json).map_err(|e| {
                        openhttpa_transport::connection::SendError::Protocol(format!(
                            "json decode: {}",
                            e
                        ))
                    })?;

                let server_pair = HybridKemPair::generate().map_err(|e| {
                    openhttpa_transport::connection::SendError::Protocol(e.to_string())
                })?;
                let server_pub = server_pair.public_key_share();
                let client_ks = KeyShare {
                    ecdhe_public: client_share.ecdhe_public,
                    mlkem_public: client_share.mlkem_public,
                };
                let (_, ct) = server_pair.server_combine(&client_ks).map_err(|e| {
                    openhttpa_transport::connection::SendError::Protocol(e.to_string())
                })?;

                let resp_hdrs = AtHsResponseHeaders {
                    cipher_suite: CipherSuite::X25519MlKem768Aes256GcmSha384,
                    random: vec![0u8; 32],
                    key_share_json: serde_json::to_vec(&ServerKeyShare {
                        ecdhe_public: server_pub.ecdhe_public,
                        mlkem_ciphertext: ct,
                        mlkem_public: server_pub.mlkem_public,
                    })
                    .unwrap(),
                    base_id: openhttpa_proto::AtbId::new(),
                    version: ProtocolVersion::V2,
                    expires_secs: 3600,
                    quotes: vec![AttestQuote {
                        quote_type: QuoteType::Mock,
                        raw: bytes::Bytes::from_static(b"mock-quote"),
                        qudd: bytes::Bytes::from_static(&[0u8; 64]),
                        collateral_uris: vec![],
                    }],
                    secrets: vec![],
                    cargo: None,
                    ticket_resumption: None,
                    server_signatures: vec![],
                    zk_proof: None,
                };
                return Ok(openhttpa_transport::connection::TransportResponse {
                    status: http::StatusCode::OK,
                    headers: resp_hdrs.encode(),
                    body: axum::body::Body::empty(),
                    trailers: None,
                });
            }

            Ok(openhttpa_transport::connection::TransportResponse {
                status: http::StatusCode::OK,
                headers: http::HeaderMap::new(),
                body: axum::body::Body::from("{\"status\": \"ok\"}"),
                trailers: None,
            })
        }
    }

    info!("Starting swarm simulation for Web UI");
    let mut logs = vec![];
    logs.push("Initializing swarm with 10 agents...".to_string());

    let registry = Arc::new(MockRegistry::new());
    let tee = Arc::new(MockTeeProvider::default());
    let verifier = Arc::new(MockVerifier);
    let transport = Arc::new(LocalTransport);

    let mut agents = vec![];
    for i in 0..10 {
        let name = format!("Agent-{}", i);
        let node = AgentNode::new(
            name.clone(),
            vec!["prime-check".to_string()],
            format!("http://agent-{}:8080", i),
            registry.clone(),
            tee.clone(),
            verifier.clone(),
            transport.clone(),
            Arc::new(openhttpa_mesh::RegoPolicyEngine::permissive()),
        );
        registry.register(node.metadata().clone()).await.unwrap();
        agents.push(node);
        logs.push(format!("Registered {} in the mesh (TEE verified)", name));
    }

    logs.push("Performing mutual attestation between Agent-0 and Agent-5...".to_string());
    let a0 = &agents[0];
    let a5_id = agents[5].metadata().id;
    match a0.connect_to_peer(a5_id).await {
        Ok(session) => {
            logs.push(format!(
                "✓ Handshake successful: Transcript bound to {}",
                hex::encode(&session.session.state().id.to_string().as_bytes()[0..8])
            ));
            logs.push("✓ Mutual attestation verified: Both agents running in TEE".to_string());
        }
        Err(e) => {
            logs.push(format!("✗ Handshake failed: {}", e));
        }
    }

    logs.push("Executing multi-hop tool delegation...".to_string());
    logs.push("Coordinator -> Worker-3 -> Aggregator".to_string());
    logs.push("✓ Confidential tunnel established (AES-256-GCM)".to_string());
    logs.push("✓ Result aggregated: Pi \u{2248} 3.14159 (attested)".to_string());

    // Generate a sample provenance chain for the visualizer
    let mut provenance = vec![
        agents[0].metadata().clone(),
        agents[3].metadata().clone(),
        agents[7].metadata().clone(),
    ];

    // Inject mock quotes so the UI shows "Verified"
    for agent in &mut provenance {
        agent.last_quote = Some(openhttpa_proto::AttestQuote {
            quote_type: openhttpa_proto::QuoteType::Mock,
            raw: bytes::Bytes::from_static(b"MOCK_TEE_QUOTE_PROVENANCE_SIMULATION"),
            qudd: bytes::Bytes::from_static(b"MOCK_QUDD_PROVENANCE_SIMULATION"),
            collateral_uris: vec![],
        });
    }

    Json(SwarmReport {
        agent_count: 10,
        success_rate: 1.0,
        logs,
        provenance,
    })
}

#[derive(Deserialize)]
struct HandshakeRequest {
    client_random: String,
    client_challenge: Option<String>,
    ecdhe_public: String,
    mlkem_public: String,
    cipher_suites: Option<Vec<String>>,
    versions: Option<Vec<String>>,
}

#[derive(Serialize)]
struct HandshakeResponse {
    base_id: String,
    server_ecdhe_public: String,
    mlkem_ciphertext: String,
    server_mlkem_ek: String,
    server_random: String,
    transcript_hash: String,
    quotes: Vec<String>,
    quote_type: String,
    expires_in: u64,
    cipher_suite: String,
    version: String,
}

async fn aths_json(
    State(state): State<AppState>,
    Json(req): Json<HandshakeRequest>,
) -> Result<impl IntoResponse, Response> {
    use openhttpa_core::handshake::{AtHsRequest, ClientKeyShare};
    use openhttpa_proto::{CipherSuite, ProtocolVersion};

    info!(
        "Received AtHS JSON request for client_random: {}",
        req.client_random
    );

    let client_random = hex::decode(&req.client_random).map_err(|e| {
        info!("invalid client_random hex: {}", e);
        (StatusCode::BAD_REQUEST, "invalid client_random").into_response()
    })?;
    let client_random: [u8; 32] = client_random.try_into().map_err(|_| {
        info!("client_random must be 32 bytes");
        (StatusCode::BAD_REQUEST, "client_random must be 32 bytes").into_response()
    })?;

    let client_challenge = if let Some(ref c) = req.client_challenge {
        hex::decode(c).map_err(|_| {
            (StatusCode::BAD_REQUEST, "invalid client_challenge hex").into_response()
        })?
    } else {
        vec![0u8; 48]
    };
    let client_challenge: [u8; 48] = client_challenge.try_into().map_err(|_| {
        (StatusCode::BAD_REQUEST, "client_challenge must be 48 bytes").into_response()
    })?;

    let ecdhe_public = hex::decode(&req.ecdhe_public).map_err(|e| {
        info!("invalid ecdhe_public hex: {}", e);
        (StatusCode::BAD_REQUEST, "invalid ecdhe_public").into_response()
    })?;
    if ecdhe_public.len() != 32 {
        info!("ecdhe_public must be 32 bytes, got {}", ecdhe_public.len());
        return Err((StatusCode::BAD_REQUEST, "ecdhe_public must be 32 bytes").into_response());
    }

    let mlkem_public = hex::decode(&req.mlkem_public).map_err(|e| {
        info!("invalid mlkem_public hex: {}", e);
        (StatusCode::BAD_REQUEST, "invalid mlkem_public").into_response()
    })?;
    if mlkem_public.len() != 1184 {
        info!(
            "mlkem_public must be 1184 bytes, got {}",
            mlkem_public.len()
        );
        return Err((StatusCode::BAD_REQUEST, "mlkem_public must be 1184 bytes").into_response());
    }

    let client_share = ClientKeyShare {
        ecdhe_public,
        mlkem_public,
    };

    let suites: Vec<CipherSuite> = req
        .cipher_suites
        .unwrap_or_default()
        .iter()
        .map(|s| {
            s.parse()
                .unwrap_or(CipherSuite::X25519MlKem768Aes256GcmSha384)
        })
        .collect();
    let suites = if suites.is_empty() {
        vec![CipherSuite::X25519MlKem768Aes256GcmSha384]
    } else {
        suites
    };

    let versions: Vec<ProtocolVersion> = req
        .versions
        .unwrap_or_default()
        .iter()
        .map(|v| v.parse().unwrap_or(ProtocolVersion::V2))
        .collect();
    let versions = if versions.is_empty() {
        vec![ProtocolVersion::V2]
    } else {
        versions
    };

    let aths = &state.0.aths_state;
    let (suite, version, server_share, result) = aths
        .executor
        .execute_server(
            &AtHsRequest {
                client_suites: &suites,
                client_versions: &versions,
                client_random: &client_random,
                client_challenge: &client_challenge,
                client_share: &client_share,
                client_quotes: &[],
                atb_ttl_secs: aths.atb_ttl.as_secs(),
                provenance: None,
            },
            Some(&*aths.tee_provider),
            aths.verifier.as_deref(),
            aths.identity_key.as_deref(),
        )
        .await
        .map_err(|e| {
            info!("execute_server failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        })?;

    let session = AttestSession::new(
        result.atb_id.clone(),
        suite,
        version,
        result.session_keys,
        std::time::Instant::now() + std::time::Duration::from_secs(3600),
        ReplayStrategy::default(),
        result.client_attestation_result,
    );

    if let Err(e) = state.registry.insert(session) {
        return Err((StatusCode::SERVICE_UNAVAILABLE, e).into_response());
    }

    info!("Handshake thash: {}", hex::encode(result.transcript_hash));
    let resp = HandshakeResponse {
        base_id: result.atb_id.to_string(),
        server_ecdhe_public: hex::encode(server_share.ecdhe_public),
        mlkem_ciphertext: hex::encode(server_share.mlkem_ciphertext),
        server_mlkem_ek: hex::encode(server_share.mlkem_public),
        server_random: hex::encode(result.server_random),
        transcript_hash: hex::encode(result.transcript_hash),
        quotes: if result.server_quotes.is_empty() {
            vec!["dGVzdC1xdW90ZQ==".to_owned()] // Default test-quote
        } else {
            result
                .server_quotes
                .iter()
                .map(|q| {
                    use base64ct::{Base64, Encoding};
                    Base64::encode_string(&q.raw)
                })
                .collect()
        },
        quote_type: state.tee_type.to_string(),
        expires_in: 3600,
        cipher_suite: suite.to_string(),
        version: version.to_string(),
    };
    Ok(Json(resp))
}

type Response = axum::response::Response;

async fn mcp_handle(
    State(state): State<AppState>,
    session: OpenHttpaSession,
    EncryptedJson(rpc_req): EncryptedJson<serde_json::Value>,
) -> impl IntoResponse {
    let req_bytes = serde_json::to_vec(&rpc_req).unwrap();
    let res = state.mcp_server.handle_request(&req_bytes).await;

    // Convert Vec<u8> result to JSON value if possible
    let final_res = match res {
        Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
            .unwrap_or_else(|_| serde_json::json!({ "error": "Invalid JSON from MCP server" })),
        Err(e) => serde_json::json!({ "error": e }),
    };

    session.seal(&final_res)
}

async fn a2a_handle(
    State(_state): State<AppState>,
    session: OpenHttpaSession,
    EncryptedJson(msg): EncryptedJson<serde_json::Value>,
) -> impl IntoResponse {
    info!("Received A2A message: {:?}", msg);
    session.seal(
        &serde_json::json!({ "status": "delivered", "response": "Message received by agent" }),
    )
}

struct WsChatHandler {
    tx: broadcast::Sender<WsPayload>,
}

#[async_trait]
impl AttestWsHandler for WsChatHandler {
    async fn handle(&self, mut ws: AttestWsSession) {
        let mut rx = self.tx.subscribe();
        info!("Attested WebSocket session started");

        loop {
            tokio::select! {
                msg = ws.recv() => {
                    match msg {
                        Some(Ok(payload)) => {
                            match &payload {
                                WsPayload::Text(text) => info!("Broadcast Text: {}", text),
                                WsPayload::Binary(data) => info!("Broadcast Binary: {} bytes", data.len()),
                                WsPayload::Close => {
                                    info!("WebSocket closed");
                                    break;
                                }
                            }
                            let _ = self.tx.send(payload);
                        }
                        Some(Err(e)) => {
                            error!("WebSocket error: {}", e);
                            break;
                        }
                        None => break,
                    }
                }
                Ok(payload) = rx.recv() => {
                    match payload {
                        WsPayload::Text(text) => {
                            if ws.send_text(&text).await.is_err() { break; }
                        }
                        WsPayload::Binary(data) => {
                            if ws.send_binary(&data).await.is_err() { break; }
                        }
                        WsPayload::Close => {
                            let _ = ws.close().await;
                            break;
                        }
                    }
                }
            }
        }
    }
}

async fn ws_upgrade_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AttestWsState<WsChatHandler>>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut final_headers = headers.clone();
    let mut selected_proto = None;
    let mut selected_atb_id: Option<String> = None;

    if let Some(proto_hdr) = headers.get("Sec-WebSocket-Protocol") {
        let proto_str = proto_hdr.to_str().unwrap_or("");
        debug!("Sec-WebSocket-Protocol: {}", proto_str);
        for p in proto_str.split(',').map(|s| s.trim()) {
            if p.starts_with("atb-id-") {
                selected_proto = Some(p.to_string());
                debug!("Found AtB proto: {}", p);
                break;
            }
        }
    }

    // Detailed header logging for debugging
    debug!("WS Upgrade Headers: {:?}", headers);
    if let Some(origin) = headers.get(axum::http::header::ORIGIN) {
        info!("WS Upgrade Origin: {:?}", origin);
    }

    // Also check query param (more reliable)
    if let Some(atb_id_raw) = params.get("atb-id") {
        let atb_id = atb_id_raw.trim();
        info!("Found AtB in query: {}", atb_id);
        selected_atb_id = Some(atb_id.to_string());
    } else if let Some(ref p) = selected_proto {
        selected_atb_id = Some(p[7..].to_string());
    }

    if let Some(ref atb_id) = selected_atb_id {
        if let Ok(hv) = HeaderValue::from_str(atb_id) {
            final_headers.insert("Attest-Base-ID", hv);
            info!("WebSocket upgrade for AtB: {}", atb_id);

            // Check if session actually exists in registry before forwarding
            if let Ok(atb_uuid) = atb_id.parse::<openhttpa_proto::AtbId>() {
                if let Some(session) = state.registry.get(&atb_uuid) {
                    info!("Found session in registry for WS upgrade: {}", atb_id);
                    if !session.is_alive() {
                        warn!("Session {} exists but is NOT alive (expired)", atb_id);
                    }
                } else {
                    warn!(
                        "WebSocket upgrade failed: Session {} not found in registry (total sessions: {})",
                        atb_id,
                        state.registry.len()
                    );
                }
            } else {
                warn!(
                    "WebSocket upgrade failed: Invalid UUID format for AtB ID: {}",
                    atb_id
                );
            }
        } else {
            warn!(
                "Invalid Attest-Base-ID in upgrade (header value conversion failed): {}",
                atb_id
            );
        }
    } else {
        warn!(
            "WebSocket upgrade attempted without AtB ID (missing both query 'atb-id' and Sec-WebSocket-Protocol header)"
        );
    }

    let ws = match selected_proto {
        Some(p) => ws.protocols([p]),
        None => ws,
    };

    info!("Forwarding to attested_ws_upgrade");
    attested_ws_upgrade(ws, State(state), final_headers).await
}

async fn fallback_handler(req: axum::extract::Request) -> impl IntoResponse {
    warn!("404 Fallback: {} {}", req.method(), req.uri());
    StatusCode::NOT_FOUND
}

async fn root_handler(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    info!("Root handler received {} {}", req.method(), req.uri());
    match *req.method() {
        axum::http::Method::OPTIONS => {
            info!("Handling preflight (OPTIONS)");
            preflight_handler(State(state.preflight_state.clone())).await
        }
        axum::http::Method::GET => health(State(state.clone())).await,
        ref m if m.as_str() == "ATTEST" => {
            info!("Handling ATTEST");
            aths_handler(State(state.aths_state.clone()), req).await
        }
        _ => {
            warn!("Unhandled method on root: {}", req.method());
            StatusCode::METHOD_NOT_ALLOWED.into_response()
        }
    }
}

/// SEC-KEY-01: Return a 32-byte HMAC challenge key sourced from an environment
/// variable (hex-encoded), falling back to OS random bytes in debug builds.
///
/// In release builds the env var is REQUIRED — a missing or malformed value
/// will panic at startup rather than silently use an insecure all-zero key.
fn demo_challenge_key(env_var: &str) -> [u8; 32] {
    if let Ok(hex_val) = std::env::var(env_var) {
        let bytes = hex::decode(&hex_val)
            .unwrap_or_else(|_| panic!("{env_var} must be a hex-encoded 32-byte value"));
        assert!(
            bytes.len() == 32,
            "{env_var} must decode to exactly 32 bytes (got {})",
            bytes.len()
        );
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        return key;
    }
    // DEMO ONLY: fall back to random key when env var is absent.
    // In release builds this prints a loud warning; do NOT rely on this in production.
    #[cfg(not(debug_assertions))]
    tracing::warn!(
        "{env_var} not set — using random challenge key. Set this env var in production.",
        env_var = env_var
    );
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).expect("OS CSPRNG unavailable");
    key
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let demo_state = AppState(Arc::new(DemoState::default()));

    // Safety check: Warn if MockTeeProvider is used in a production-like environment.
    let is_prod = std::env::var("APP_ENV")
        .map(|v| v.to_lowercase() == "production")
        .unwrap_or(false);
    if is_prod {
        warn!(
            "CRITICAL: Using MockTeeProvider in PRODUCTION mode. Attestation is NOT hardware-enforced!"
        );
    } else {
        info!("Running with MockTeeProvider (Development mode)");
    }

    // Register tools asynchronously
    demo_state.mcp_server.add_tool(Box::new(SecureSum)).await;
    demo_state
        .mcp_server
        .add_tool(Box::new(SecureAverage))
        .await;
    demo_state
        .mcp_server
        .add_tool(Box::new(SecureVariance))
        .await;

    let api_routes = Router::new()
        .route("/reset", post(reset))
        .route("/a2a", post(a2a_handle))
        .route("/attest", post(aths_json))
        .route("/submit", post(submit))
        .route("/result", get(result))
        .route("/mcp", post(mcp_handle))
        .route("/echo", post(echo))
        .route("/oracle/fetch", post(oracle_fetch))
        .route("/chat", post(chat_handle))
        .route("/ws", get(ws_upgrade_handler))
        .route("/status", get(status))
        .route("/swarm/simulate", post(simulate_swarm))
        .route("/ticket", post(get_ticket))
        .layer(
            CorsLayer::new()
                // CORS-01 DEMO ONLY: wildcard origin is acceptable for local
                // development and demos. In production, restrict this to your
                // actual frontend origin, e.g.:
                //   .allow_origin("https://your-domain.example".parse::<HeaderValue>().unwrap())
                .allow_origin(tower_http::cors::Any)
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
                .allow_headers([
                    CONTENT_TYPE,
                    HeaderName::from_static("attest-base-id"),
                    HeaderName::from_static("attest-binder"),
                    HeaderName::from_static("attest-ticket"),
                    HeaderName::from_static("attest-key-shares"),
                    HeaderName::from_static("attest-quote"),
                ]),
        );

    let app = Router::new()
        .route("/", axum::routing::any(root_handler))
        .route("/attest", axum::routing::any(root_handler))
        .route("/v1/chat/completions", axum::routing::post(chat_handle))
        .route("/health", get(health))
        .nest("/api", api_routes)
        .with_state(demo_state.clone())
        .layer(openhttpa_server::middleware::Rtt0ResumptionLayer::new(
            demo_state.registry.clone(),
            (*demo_state.ticket_engine).clone(),
            std::sync::Arc::new(openhttpa_server::middleware::LocalReplayGuard::new(
                100000, 0.01,
            )),
        ))
        .fallback(fallback_handler)
        .layer(TraceLayer::new_for_http());

    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .expect("PORT must be a number");
    let addr = format!("0.0.0.0:{port}");
    info!("`OpenHTTPA` demo backend listening on {addr} (SDK-hardened)");
    let listener = TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::{Method, Request, StatusCode};
    use openhttpa_core::handshake::SessionKeys;
    use tower::ServiceExt;

    async fn make_app() -> Router {
        // SEC-09: Allow hardware impersonation for these tests.
        // SAFETY: single-threaded test context.
        unsafe { std::env::set_var("OPENHTTPA_ALLOW_MOCK_HARDWARE", "1") };
        let state = AppState(Arc::new(DemoState::default()));
        Router::new()
            .route("/health", get(health))
            .route("/api/submit", post(submit))
            .route("/api/result", get(result))
            .with_state(state)
    }

    #[tokio::test]
    async fn health_check() {
        let app = make_app().await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn submit_and_result() {
        // SAFETY: single-threaded test context.
        unsafe { std::env::set_var("OPENHTTPA_ALLOW_MOCK_HARDWARE", "1") };
        let state = AppState(Arc::new(DemoState::default()));
        let app = Router::new()
            .route("/api/submit", post(submit))
            .route("/api/result", get(result))
            .with_state(state.clone());

        let base_id = openhttpa_proto::AtbId::new();
        let keys = SessionKeys {
            master_secret: vec![0u8; 48],
            client_write_key: vec![1u8; 32],
            server_write_key: vec![2u8; 32],
            client_write_iv: vec![3u8; 12],
            server_write_iv: vec![4u8; 12],
            client_mac_key: vec![5u8; 48],
            server_mac_key: vec![6u8; 48],
            transcript_hash: [0u8; 48],
        };
        let session = AttestSession::new(
            base_id.clone(),
            openhttpa_proto::CipherSuite::X25519MlKem768Aes256GcmSha384,
            openhttpa_proto::ProtocolVersion::V2,
            keys,
            std::time::Instant::now() + std::time::Duration::from_secs(3600),
            ReplayStrategy::default(),
            None,
        );
        state
            .registry
            .insert(session)
            .expect("test session insert failed");

        let base_id_str = base_id.to_string();
        let plaintext = serde_json::json!({ "party_id": "alice", "value": 42 }).to_string();

        use openhttpa_crypto::aead::{AeadAlgorithm, BoundAeadKey};
        let client_key_bytes = vec![1u8; 32];
        let client_iv_bytes: [u8; 12] = [3u8; 12];
        let sealer =
            BoundAeadKey::new(AeadAlgorithm::Aes256Gcm, &client_key_bytes, client_iv_bytes)
                .unwrap();

        let mut aad = b"openhttpa:".to_vec();
        aad.extend_from_slice(base_id_str.as_bytes());
        let mut data = plaintext.as_bytes().to_vec();
        sealer.seal(&aad, &mut data).unwrap();

        let body = serde_json::json!({ "ciphertext": hex::encode(data) }).to_string();

        // Calculate correct MAC for Attest-Ticket
        use hmac::{Hmac, Mac};
        use sha2::Sha384;
        let mut hmac = Hmac::<Sha384>::new_from_slice(&[5u8; 48]).unwrap();
        // Use production canonicalization logic
        let mut header_map = http::HeaderMap::new();
        header_map.insert("Attest-Base-ID", base_id_str.parse().unwrap());
        header_map.insert("content-type", "application/json".parse().unwrap());

        // Bind method and path for semantic integrity (H-01).
        let ahl =
            openhttpa_headers::canonicalize_ahl("POST", "/api/submit", None, &header_map).unwrap();
        hmac.update(&1u64.to_be_bytes());
        hmac.update(&ahl);
        let mac = hmac.finalize().into_bytes();

        // Use standard binary encoding (M-02).
        let ticket_bin = openhttpa_headers::encode_attest_ticket(1, &mac, None);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/submit")
                    .header("content-type", "application/json")
                    .header("Attest-Base-ID", &base_id_str)
                    .header("Attest-Ticket", ticket_bin)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_counter_desync_behavior() {
        // SAFETY: single-threaded test context.
        unsafe { std::env::set_var("OPENHTTPA_ALLOW_MOCK_HARDWARE", "1") };
        let state = AppState(Arc::new(DemoState::default()));
        let app = Router::new()
            .route("/api/submit", post(submit))
            .route("/api/result", get(result))
            .with_state(state.clone());

        let base_id = openhttpa_proto::AtbId::new();
        let keys = SessionKeys {
            master_secret: vec![0u8; 48],
            client_write_key: vec![1u8; 32],
            server_write_key: vec![2u8; 32],
            client_write_iv: vec![3u8; 12],
            server_write_iv: vec![4u8; 12],
            client_mac_key: vec![5u8; 48],
            server_mac_key: vec![6u8; 48],
            transcript_hash: [0u8; 48],
        };
        let session = AttestSession::new(
            base_id.clone(),
            openhttpa_proto::CipherSuite::X25519MlKem768Aes256GcmSha384,
            openhttpa_proto::ProtocolVersion::V2,
            keys,
            std::time::Instant::now() + std::time::Duration::from_secs(3600),
            ReplayStrategy::default(),
            None,
        );
        state
            .registry
            .insert(session)
            .expect("test session insert failed");

        let base_id_str = base_id.to_string();
        let client_mac_key = vec![5u8; 48];
        let plaintext = serde_json::json!({ "party_id": "alice", "value": 42 }).to_string();

        use openhttpa_crypto::aead::{AeadAlgorithm, BoundAeadKey};
        let client_key_bytes = vec![1u8; 32];
        let client_iv_bytes: [u8; 12] = [3u8; 12];
        let sealer =
            BoundAeadKey::new(AeadAlgorithm::Aes256Gcm, &client_key_bytes, client_iv_bytes)
                .unwrap();

        let mut aad = b"openhttpa:".to_vec();
        aad.extend_from_slice(base_id_str.as_bytes());
        let mut data = plaintext.as_bytes().to_vec();
        sealer.seal(&aad, &mut data).unwrap(); // Nonce 1

        let body = serde_json::json!({ "ciphertext": hex::encode(data) }).to_string();

        use hmac::{Hmac, Mac};
        use sha2::Sha384;
        let mut hmac = Hmac::<Sha384>::new_from_slice(&client_mac_key).unwrap();
        let mut header_map = http::HeaderMap::new();
        header_map.insert("Attest-Base-ID", base_id_str.parse().unwrap());
        header_map.insert("content-type", "application/json".parse().unwrap());

        // Bind method and path for semantic integrity (H-01).
        let ahl =
            openhttpa_headers::canonicalize_ahl("POST", "/api/submit", None, &header_map).unwrap();
        hmac.update(&1u64.to_be_bytes());
        hmac.update(&ahl);
        let mac = hmac.finalize().into_bytes();

        // Use standard binary encoding (M-02).
        let ticket_bin = openhttpa_headers::encode_attest_ticket(1, &mac, None);

        // 1. Submit (uses nonce 1)
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/submit")
                    .header("Attest-Base-ID", &base_id_str)
                    .header("Attest-Ticket", ticket_bin)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // 2. Result (uses nonce 1 implicitly for response? No, server counter starts at 1)
        // The server should have incremented its server_counter to 2 now.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/result")
                    .header("Attest-Base-ID", &base_id_str)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let res_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let ciphertext_hex = res_json["ciphertext"].as_str().unwrap();
        let mut ciphertext = hex::decode(ciphertext_hex).unwrap();

        // If we try to decrypt with nonce 1, it should FAIL because server used nonce 2
        let server_key_bytes = vec![2u8; 32];
        let server_iv_bytes: [u8; 12] = [4u8; 12];
        let unsealer =
            BoundAeadKey::new(AeadAlgorithm::Aes256Gcm, &server_key_bytes, server_iv_bytes)
                .unwrap();
        // Counter 1
        let mut nonce1 = [0u8; 12];
        nonce1.copy_from_slice(&server_iv_bytes);
        nonce1[11] ^= 1;

        let res = unsealer.open(
            &openhttpa_crypto::aead::AeadNonce::from_slice(&nonce1).unwrap(),
            &aad,
            &mut ciphertext,
        );
        assert!(
            res.is_err(),
            "Decryption with nonce 1 should fail because server incremented counter to 2 after /api/submit response"
        );

        // Counter 2 should work
        let mut ciphertext = hex::decode(ciphertext_hex).unwrap();
        let mut nonce2 = [0u8; 12];
        nonce2.copy_from_slice(&server_iv_bytes);
        nonce2[11] ^= 2;
        let res = unsealer.open(
            &openhttpa_crypto::aead::AeadNonce::from_slice(&nonce2).unwrap(),
            &aad,
            &mut ciphertext,
        );
        assert!(res.is_ok(), "Decryption with nonce 2 should succeed");
    }

    #[tokio::test]
    async fn test_mcp_tool_execution() {
        // SAFETY: single-threaded test context.
        unsafe { std::env::set_var("OPENHTTPA_ALLOW_MOCK_HARDWARE", "1") };
        let state = AppState(Arc::new(DemoState::default()));
        state.mcp_server.add_tool(Box::new(SecureSum)).await;

        let app = Router::new()
            .route("/api/mcp", post(mcp_handle))
            .with_state(state.clone());

        let base_id = openhttpa_proto::AtbId::new();
        let keys = SessionKeys {
            master_secret: vec![0u8; 48],
            client_write_key: vec![1u8; 32],
            server_write_key: vec![2u8; 32],
            client_write_iv: vec![3u8; 12],
            server_write_iv: vec![4u8; 12],
            client_mac_key: vec![5u8; 48],
            server_mac_key: vec![6u8; 48],
            transcript_hash: [0u8; 48],
        };
        state
            .registry
            .insert(AttestSession::new(
                base_id.clone(),
                openhttpa_proto::CipherSuite::X25519MlKem768Aes256GcmSha384,
                openhttpa_proto::ProtocolVersion::V2,
                keys,
                std::time::Instant::now() + std::time::Duration::from_secs(3600),
                ReplayStrategy::default(),
                None,
            ))
            .expect("test session insert failed");

        let rpc_req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "secure_sum",
                "arguments": { "party_id": "alice", "value": 100 }
            },
            "id": 1
        });

        // Seal the RPC request
        use openhttpa_crypto::aead::{AeadAlgorithm, BoundAeadKey};
        let sealer = BoundAeadKey::new(AeadAlgorithm::Aes256Gcm, &[1u8; 32], [3u8; 12]).unwrap();
        let mut aad = b"openhttpa:".to_vec();
        aad.extend_from_slice(base_id.to_string().as_bytes());
        let mut data = serde_json::to_vec(&rpc_req).unwrap();
        sealer.seal(&aad, &mut data).unwrap();

        // We need a real MAC for the test to pass the extractor verification
        use hmac::{Hmac, Mac};
        use sha2::Sha384;
        let mut hmac = Hmac::<Sha384>::new_from_slice(&[5u8; 48]).unwrap();
        let mut header_map = http::HeaderMap::new();
        header_map.insert("Attest-Base-ID", base_id.to_string().parse().unwrap());
        header_map.insert("content-type", "application/json".parse().unwrap());

        // Bind method and path for semantic integrity (H-01).
        let ahl =
            openhttpa_headers::canonicalize_ahl("POST", "/api/mcp", None, &header_map).unwrap();
        hmac.update(&1u64.to_be_bytes());
        hmac.update(&ahl);
        let mac = hmac.finalize().into_bytes();

        // Use standard binary encoding (M-02).
        let ticket = openhttpa_headers::encode_attest_ticket(1, &mac, None);

        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/mcp")
                    .header("Attest-Base-ID", base_id.to_string())
                    .header("Attest-Ticket", ticket)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "ciphertext": hex::encode(data) }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_oracle_fetch_endpoint() {
        // SAFETY: single-threaded test context.
        unsafe { std::env::set_var("OPENHTTPA_ALLOW_MOCK_HARDWARE", "1") };
        let state = AppState(Arc::new(DemoState::default()));
        let app = Router::new()
            .route("/api/oracle/fetch", post(oracle_fetch))
            .with_state(state.clone());

        let base_id = openhttpa_proto::AtbId::new();
        let keys = SessionKeys {
            master_secret: vec![0u8; 48],
            client_write_key: vec![1u8; 32],
            server_write_key: vec![2u8; 32],
            client_write_iv: vec![3u8; 12],
            server_write_iv: vec![4u8; 12],
            client_mac_key: vec![5u8; 48],
            server_mac_key: vec![6u8; 48],
            transcript_hash: [0u8; 48],
        };
        state
            .registry
            .insert(AttestSession::new(
                base_id.clone(),
                openhttpa_proto::CipherSuite::X25519MlKem768Aes256GcmSha384,
                openhttpa_proto::ProtocolVersion::V2,
                keys,
                std::time::Instant::now() + std::time::Duration::from_secs(3600),
                ReplayStrategy::default(),
                None,
            ))
            .expect("test session insert failed");

        let oracle_req = serde_json::json!({
            "url": "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd"
        });

        // Seal the request
        use openhttpa_crypto::aead::{AeadAlgorithm, BoundAeadKey};
        let sealer = BoundAeadKey::new(AeadAlgorithm::Aes256Gcm, &[1u8; 32], [3u8; 12]).unwrap();
        let mut aad = b"openhttpa:".to_vec();
        aad.extend_from_slice(base_id.to_string().as_bytes());
        let mut data = serde_json::to_vec(&oracle_req).unwrap();
        sealer.seal(&aad, &mut data).unwrap();

        // Bind and MAC
        use hmac::{Hmac, Mac};
        use sha2::Sha384;
        let mut hmac = Hmac::<Sha384>::new_from_slice(&[5u8; 48]).unwrap();
        let mut header_map = http::HeaderMap::new();
        header_map.insert("Attest-Base-ID", base_id.to_string().parse().unwrap());
        header_map.insert("content-type", "application/json".parse().unwrap());

        let ahl =
            openhttpa_headers::canonicalize_ahl("POST", "/api/oracle/fetch", None, &header_map)
                .unwrap();
        hmac.update(&1u64.to_be_bytes());
        hmac.update(&ahl);
        let mac = hmac.finalize().into_bytes();
        let ticket = openhttpa_headers::encode_attest_ticket(1, &mac, None);

        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/oracle/fetch")
                    .header("Attest-Base-ID", base_id.to_string())
                    .header("Attest-Ticket", ticket)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "ciphertext": hex::encode(data) }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let res: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(res.get("ciphertext").is_some());
    }
}
