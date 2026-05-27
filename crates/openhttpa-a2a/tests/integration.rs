// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use async_trait::async_trait;
use openhttpa_a2a::{A2AAgent, A2AMessage};
use openhttpa_core::handshake::AtHsExecutor;
use openhttpa_headers::attest_headers::{AtHsRequestHeaders, AtHsResponseHeaders};
use openhttpa_mcp::client::OpenHttpaMcpClient;
use openhttpa_mcp::server::{McpTool, OpenHttpaMcpServer};
use openhttpa_transport::connection::{
    AttestTransport, SendError, TransportRequest, TransportResponse,
};
use serde_json::json;
use std::sync::Arc;

struct MockTool;
impl McpTool for MockTool {
    fn name(&self) -> &str {
        "mock_tool"
    }
    fn description(&self) -> Option<&str> {
        Some("A mock tool for testing")
    }
    fn input_schema(&self) -> serde_json::Value {
        json!({})
    }
    fn call<'a>(
        &'a self,
        _args: serde_json::Value,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<serde_json::Value, String>> + Send + 'a>,
    > {
        Box::pin(async move { Ok(json!({ "status": "success" })) })
    }
}

struct MockTransport {
    executor: Arc<AtHsExecutor>,
    sessions: Arc<dashmap::DashMap<String, Arc<openhttpa_crypto::hkdf::SessionKeys>>>,
}

#[async_trait]
impl AttestTransport for MockTransport {
    async fn send(&self, request: TransportRequest) -> Result<TransportResponse, SendError> {
        if request.method.as_str() == "ATTEST" {
            let req_hdrs = AtHsRequestHeaders::decode(&request.headers)
                .map_err(|e| SendError::Protocol(e.to_string()))?;
            let client_share: openhttpa_core::handshake::ClientKeyShare =
                serde_json::from_slice(&req_hdrs.key_shares_json).unwrap();
            let client_random: [u8; 32] = req_hdrs.random.as_slice().try_into().unwrap();

            use openhttpa_core::handshake::AtHsRequest;
            let mut client_challenge_fixed = [0u8; 48];
            if let Some(ref c) = req_hdrs.challenge {
                let len = c.len().min(48);
                client_challenge_fixed[..len].copy_from_slice(&c[..len]);
            }

            let (suite, version, server_share, result) = self
                .executor
                .execute_server(
                    &AtHsRequest {
                        client_suites: &req_hdrs.cipher_suites,
                        client_versions: &req_hdrs.versions,
                        client_random: &client_random,
                        client_challenge: &client_challenge_fixed,
                        client_share: &client_share,
                        client_quotes: &req_hdrs.client_quotes,
                        atb_ttl_secs: 3600,
                        provenance: None,
                    },
                    Some(&openhttpa_tee::mock::MockTeeProvider::default()),
                    Some(&openhttpa_attestation::MockVerifier::default()),
                    None,
                )
                .await
                .map_err(|e: openhttpa_core::handshake::HandshakeError| {
                    SendError::Protocol(e.to_string())
                })?;

            let key_share_json = serde_json::to_vec(&server_share).unwrap();

            let keys = result.session_keys.clone();
            self.sessions
                .insert(result.atb_id.to_string(), Arc::new(keys));

            let resp_hdrs = AtHsResponseHeaders {
                cipher_suite: suite,
                random: result.server_random.to_vec(),
                key_share_json,
                base_id: result.atb_id.clone(),
                version,
                expires_secs: 3600,
                quotes: result.server_quotes.clone(),
                secrets: vec![],
                cargo: None,
                ticket_resumption: None,
                server_signatures: result.server_signatures.clone(),
                zk_proof: None,
            };

            return Ok(TransportResponse {
                status: http::StatusCode::OK,
                headers: resp_hdrs.encode(),
                body: axum::body::Body::empty(),
                trailers: None,
            });
        }

        // Handle trusted call with encryption (any path)
        if request.headers.contains_key("Attest-Ticket") {
            let base_id_str = request
                .headers
                .get("Attest-Base-ID")
                .unwrap()
                .to_str()
                .unwrap();
            let keys = self
                .sessions
                .get(base_id_str)
                .ok_or_else(|| SendError::Protocol("Session not found".to_owned()))?;

            let res_body = json!({
                "jsonrpc": "2.0",
                "id": "1",
                "result": { "status": "success" }
            });
            let plaintext = serde_json::to_vec(&res_body).unwrap();

            // Encrypt response
            let counter = 1u64; // In mock, we use fixed counter for simplicity
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes.copy_from_slice(&keys.server_write_iv);
            let count_bytes = counter.to_be_bytes();
            for (i, b) in count_bytes.iter().enumerate() {
                nonce_bytes[4 + i] ^= b;
            }
            let aead_nonce = openhttpa_crypto::aead::AeadNonce::from_slice(&nonce_bytes).unwrap();

            let mut data = plaintext;
            let mut aad = b"openhttpa:".to_vec();
            aad.extend_from_slice(base_id_str.as_bytes());

            let key = openhttpa_crypto::aead::AeadKey::new(
                openhttpa_crypto::aead::AeadAlgorithm::Aes256Gcm,
                &keys.server_write_key,
            )
            .unwrap();
            key.seal_in_place(&aead_nonce, &aad, &mut data).unwrap();

            return Ok(TransportResponse {
                status: http::StatusCode::OK,
                headers: http::HeaderMap::new(),
                body: axum::body::Body::from(
                    serde_json::to_vec(&json!({
                        "ciphertext": hex::encode(data)
                    }))
                    .unwrap(),
                ),
                trailers: None,
            });
        }

        Ok(TransportResponse {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: axum::body::Body::empty(),
            trailers: None,
        })
    }
}

#[tokio::test]
async fn test_mcp_e2e_flow() {
    let server = OpenHttpaMcpServer::new();
    server.add_tool(Box::new(MockTool)).await;

    let executor = Arc::new(AtHsExecutor::with_config(
        vec![openhttpa_proto::CipherSuite::X25519MlKem768Aes256GcmSha384],
        vec![openhttpa_proto::ProtocolVersion::V2],
        false,
        true,
    ));
    let transport = Arc::new(MockTransport {
        executor,
        sessions: Arc::new(dashmap::DashMap::new()),
    });

    let client = openhttpa_client::OpenHttpaClient::builder()
        .server_uri("http://127.0.0.1:8080".parse().unwrap())
        .transport(transport)
        .tee_provider(Arc::new(openhttpa_tee::mock::MockTeeProvider::default()))
        .build();

    // Create MCP client from existing client
    // We need to add OpenHttpaMcpClient::from_client
    let mcp_client = OpenHttpaMcpClient::new_from_client(client);
    let res = mcp_client.call_tool("mock_tool", json!({})).await;

    // The client implementation currently returns a mock success in our stub.
    assert!(res.is_ok(), "MCP flow failed: {:?}", res.err());
}

#[tokio::test]
async fn test_a2a_mutual_attestation_flow() {
    let executor = Arc::new(AtHsExecutor::with_config(
        vec![openhttpa_proto::CipherSuite::X25519MlKem768Aes256GcmSha384],
        vec![openhttpa_proto::ProtocolVersion::V2],
        false,
        true,
    ));
    let transport = Arc::new(MockTransport {
        executor,
        sessions: Arc::new(dashmap::DashMap::new()),
    });

    let client_alice = openhttpa_client::OpenHttpaClient::builder()
        .server_uri("http://bob:8080".parse().unwrap())
        .transport(transport)
        .tee_provider(Arc::new(openhttpa_tee::mock::MockTeeProvider::default()))
        .build();

    let agent_alice = A2AAgent::new_with_client("alice", client_alice);
    let _agent_bob = A2AAgent::new("bob").unwrap();

    // Test Alice connecting to Bob
    let res = agent_alice.connect_to_agent("http://bob:8080").await;
    assert!(res.is_ok(), "Alice connect failed: {:?}", res.err());

    // Test Alice sending a message to Bob
    let msg = A2AMessage {
        sender_id: "alice".to_string(),
        receiver_id: "bob".to_string(),
        message_type: "greeting".to_string(),
        payload: json!({ "text": "Hi Bob!" }),
        timestamp: 0,
    };
    let res = agent_alice.send_message("http://bob:8080", msg).await;
    assert!(res.is_ok(), "Alice send failed: {:?}", res.err());
}

#[tokio::test]
async fn test_agent_router_session_persistence() {
    let executor = Arc::new(AtHsExecutor::with_config(
        vec![openhttpa_proto::CipherSuite::X25519MlKem768Aes256GcmSha384],
        vec![openhttpa_proto::ProtocolVersion::V2],
        false,
        true,
    ));
    let transport = Arc::new(MockTransport {
        executor,
        sessions: Arc::new(dashmap::DashMap::new()),
    });

    let client_alice = openhttpa_client::OpenHttpaClient::builder()
        .server_uri("http://bob:8080".parse().unwrap())
        .transport(transport)
        .tee_provider(Arc::new(openhttpa_tee::mock::MockTeeProvider::default()))
        .build();

    let agent_alice = A2AAgent::new_with_client("alice", client_alice);
    let router = openhttpa_a2a::router::AgentRouter::new(agent_alice);

    // First connection establishes session
    let s1 = router.get_or_connect("http://bob:8080").await.unwrap();

    // Second call should reuse the session
    let s2 = router.get_or_connect("http://bob:8080").await.unwrap();

    assert_eq!(s1.state().id, s2.state().id);
}

#[tokio::test]
async fn test_agent_router_broadcast() {
    let executor = Arc::new(AtHsExecutor::with_config(
        vec![openhttpa_proto::CipherSuite::X25519MlKem768Aes256GcmSha384],
        vec![openhttpa_proto::ProtocolVersion::V2],
        false,
        true,
    ));
    let transport = Arc::new(MockTransport {
        executor,
        sessions: Arc::new(dashmap::DashMap::new()),
    });

    let client_alice = openhttpa_client::OpenHttpaClient::builder()
        .server_uri("http://bob:8080".parse().unwrap())
        .transport(transport)
        .tee_provider(Arc::new(openhttpa_tee::mock::MockTeeProvider::default()))
        .build();

    let agent_alice = A2AAgent::new_with_client("alice", client_alice);
    let router = openhttpa_a2a::router::AgentRouter::new(agent_alice);

    // Connect to two agents (they both use the same mock transport for this test)
    router.get_or_connect("http://bob:8080").await.unwrap();
    router.get_or_connect("http://charlie:8080").await.unwrap();

    let msg = A2AMessage {
        sender_id: "alice".to_string(),
        receiver_id: "swarm".to_string(),
        message_type: "broadcast".to_string(),
        payload: json!({ "text": "Hello world!" }),
        timestamp: 0,
    };

    let results = router.broadcast(msg).await;
    assert_eq!(results.len(), 2);
    for res in results {
        assert!(res.is_ok());
    }
}
