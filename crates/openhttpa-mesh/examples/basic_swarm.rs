// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! # Attested Agent Mesh: Basic Swarm Example
//!
//! This example demonstrates the core lifecycle of a secure Agent-to-Agent (A2A) interaction:
//! 1. **Registration**: Two agents (A and B) register themselves in a shared `AgentRegistry`.
//! 2. **Discovery**: Agent A searches for a peer with the "secure_sum" capability.
//! 3. **Handshake**: Agent A establishes a mutual `OpenHTTPA` session with Agent B.
//! 4. **Mutual Attestation**: Both agents verify each other's TEE hardware quotes.
//! 5. **Confidential Execution**: Agent A invokes an MCP tool on Agent B over the encrypted tunnel.

use async_trait::async_trait;
use dashmap::DashMap;
use openhttpa_attestation::EatClaims;
use openhttpa_attestation::verifier::{QuoteVerifier, VerificationError, VerificationResult};
use openhttpa_core::sha2::Digest;
use openhttpa_mcp::server::McpTool;
use openhttpa_mesh::{AgentNode, AgentRegistry, RegoPolicyEngine, registry::ShardedRegistry};
use openhttpa_proto::AttestQuote;
use openhttpa_tee::mock::MockTeeProvider;
use serde_json::json;
use std::sync::Arc;
use tracing::info;

/// A simple mock verifier for the example.
struct ExampleVerifier;
impl QuoteVerifier for ExampleVerifier {
    fn verify<'a>(
        &'a self,
        _quote: &'a AttestQuote,
        _report_data: &'a [u8; 64],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<VerificationResult, VerificationError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            Ok(VerificationResult {
                secondary: vec![],
                eat_token: None,
                claims: EatClaims {
                    hwmodel: Some("mock-measurement".to_string()),
                    dbgstat: Some(0),
                    ..Default::default()
                },
                tcb_status: "UpToDate".to_string(),
                measurement: Some("mock-measurement".to_string()),
                signer_id: Some("mock-signer".to_string()),
            })
        })
    }
}

/// A mock transport that simulates network communication.
struct ExampleTransport {
    // Shared state to store session keys for simulation
    sessions: DashMap<String, openhttpa_crypto::hkdf::SessionKeys>,
}
#[async_trait]
impl openhttpa_transport::connection::AttestTransport for ExampleTransport {
    async fn send(
        &self,
        req: openhttpa_transport::connection::TransportRequest,
    ) -> Result<
        openhttpa_transport::connection::TransportResponse,
        openhttpa_transport::connection::SendError,
    > {
        if req.method.as_str() == "ATTEST" {
            let client_hdrs =
                openhttpa_headers::attest_headers::AtHsRequestHeaders::decode(&req.headers)
                    .unwrap();
            let client_share: openhttpa_core::handshake::ClientKeyShare =
                serde_json::from_slice(&client_hdrs.key_shares_json).unwrap();

            let server_pair = openhttpa_crypto::key_exchange::HybridKemPair::generate().unwrap();
            let server_pub = server_pair.public_key_share();
            let client_ks = openhttpa_crypto::key_exchange::KeyShare {
                ecdhe_public: client_share.ecdhe_public.clone(),
                mlkem_public: client_share.mlkem_public.clone(),
            };
            let (ss, ct) = server_pair.server_combine(&client_ks).unwrap();

            let server_random: [u8; 32] = [0x55u8; 32]; // Fixed for reproducibility in example
            let mut client_random = [0u8; 32];
            client_random.copy_from_slice(&client_hdrs.random);

            let resp_hdrs = openhttpa_headers::attest_headers::AtHsResponseHeaders {
                cipher_suite: openhttpa_proto::CipherSuite::X25519MlKem768Aes256GcmSha384,
                random: server_random.to_vec(),
                key_share_json: serde_json::to_vec(&openhttpa_core::handshake::ServerKeyShare {
                    ecdhe_public: server_pub.ecdhe_public.clone(),
                    mlkem_ciphertext: ct.clone(),
                    mlkem_public: server_pub.mlkem_public.clone(),
                })
                .unwrap(),
                base_id: openhttpa_proto::AtbId::new(),
                version: openhttpa_proto::ProtocolVersion::V2,
                expires_secs: 3600,
                quotes: vec![openhttpa_proto::AttestQuote {
                    collateral_uris: vec![],
                    quote_type: openhttpa_proto::QuoteType::Mock,
                    raw: bytes::Bytes::from_static(b"mock-quote"),
                    qudd: bytes::Bytes::from_static(&[0u8; 64]),
                }],
                secrets: vec![],
                cargo: None,
                ticket_resumption: None,
                server_signatures: vec![],
                zk_proof: None,
            };

            let mut hasher = openhttpa_core::sha2::Sha384::new();

            // 1. Client Random
            hasher.update((client_random.len() as u64).to_be_bytes());
            hasher.update(client_random);

            // 2. Client Challenge (48 bytes)
            let mut challenge_bytes = [0u8; 48];
            if let Some(ref c) = client_hdrs.challenge {
                let len = c.len().min(48);
                challenge_bytes[..len].copy_from_slice(&c[..len]);
            }
            hasher.update((challenge_bytes.len() as u64).to_be_bytes());
            hasher.update(challenge_bytes);

            // 3. Client Key Share (ECDHE)
            hasher.update((client_share.ecdhe_public.len() as u64).to_be_bytes());
            hasher.update(&client_share.ecdhe_public);

            // 4. Client Key Share (ML-KEM)
            hasher.update((client_share.mlkem_public.len() as u64).to_be_bytes());
            hasher.update(&client_share.mlkem_public);

            // 5. Server Random
            hasher.update((server_random.len() as u64).to_be_bytes());
            hasher.update(server_random);

            // 6. Server Key Share (ECDHE)
            hasher.update((server_pub.ecdhe_public.len() as u64).to_be_bytes());
            hasher.update(&server_pub.ecdhe_public);

            // 7. Server Key Share (ML-KEM CT)
            hasher.update((ct.len() as u64).to_be_bytes());
            hasher.update(&ct);

            // 8. Server Key Share (ML-KEM Public)
            hasher.update((server_pub.mlkem_public.len() as u64).to_be_bytes());
            hasher.update(&server_pub.mlkem_public);

            // 9. Negotiated Cipher Suite (2 bytes)
            hasher.update(resp_hdrs.cipher_suite.numeric_id().to_be_bytes());

            // 10. Negotiated Protocol Version (1 byte)
            hasher.update([resp_hdrs.version.numeric_id()]);

            let transcript_hash: [u8; 48] = hasher.finalize().into();

            let keys = openhttpa_crypto::hkdf::SessionKeys::derive(ss.as_bytes(), &transcript_hash)
                .unwrap();
            self.sessions.insert(resp_hdrs.base_id.to_string(), keys);
            return Ok(openhttpa_transport::connection::TransportResponse {
                status: http::StatusCode::OK,
                headers: resp_hdrs.encode(),
                body: axum::body::Body::empty(),
                trailers: None,
            });
        }

        // Mock MCP response with encryption
        let base_id_str = req.headers.get("Attest-Base-ID").unwrap().to_str().unwrap();
        let keys = self.sessions.get(base_id_str).unwrap();

        let _ticket = openhttpa_headers::decode_attest_ticket(&req.headers).unwrap();

        let plaintext = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "result": { "sum": 42 },
            "id": "1"
        }))
        .unwrap();

        // Encrypt with server_write_key
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&keys.server_write_iv);
        // Note: in a real server, we'd increment our own counter.
        // For the example, we'll just use a fixed counter for simplicity.
        let counter = 1u64;
        let count_bytes = counter.to_be_bytes();
        for (i, b) in count_bytes.iter().enumerate() {
            nonce_bytes[4 + i] ^= b;
        }
        let aead_nonce = openhttpa_crypto::aead::AeadNonce::from_slice(&nonce_bytes).unwrap();

        let key = openhttpa_crypto::aead::AeadKey::new(
            openhttpa_crypto::aead::AeadAlgorithm::Aes256Gcm,
            &keys.server_write_key,
        )
        .unwrap();
        let mut data = plaintext;
        let mut aad = b"openhttpa:".to_vec();
        aad.extend_from_slice(base_id_str.as_bytes());
        info!(nonce = ?hex::encode(aead_nonce.0), counter = counter, aad = ?String::from_utf8_lossy(&aad), "Encrypting response");

        key.seal_in_place(&aead_nonce, &aad, &mut data).unwrap();
        info!(ciphertext = ?hex::encode(&data), "Encrypted response");

        Ok(openhttpa_transport::connection::TransportResponse {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: axum::body::Body::from(
                serde_json::to_vec(&json!({
                    "ciphertext": hex::encode(data)
                }))
                .unwrap(),
            ),
            trailers: None,
        })
    }
}

struct SecureSum;
impl McpTool for SecureSum {
    fn name(&self) -> &str {
        "secure_sum"
    }
    fn description(&self) -> Option<&str> {
        Some("Adds numbers securely")
    }
    fn input_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "a": { "type": "number" },
                "b": { "type": "number" }
            }
        })
    }
    fn call<'a>(
        &'a self,
        args: serde_json::Value,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<serde_json::Value, String>> + Send + 'a>,
    > {
        Box::pin(async move {
            let a = args["a"].as_f64().ok_or("missing a")?;
            let b = args["b"].as_f64().ok_or("missing b")?;
            Ok(json!({ "sum": a + b }))
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let registry = ShardedRegistry::new(4, std::time::Duration::from_secs(60));
    let tee = Arc::new(MockTeeProvider::default());
    let verifier = Arc::new(ExampleVerifier);
    let transport = Arc::new(ExampleTransport {
        sessions: DashMap::new(),
    });

    // 1. Create and register Agent A (the Requester)
    let mut agent_a = AgentNode::new(
        "Agent A".to_string(),
        vec![],
        "http://agent-a:8080".to_string(),
        registry.clone(),
        tee.clone(),
        verifier.clone(),
        transport.clone(),
        Arc::new(RegoPolicyEngine::default()),
    );
    agent_a.start_heartbeat(std::time::Duration::from_secs(10));
    registry.register(agent_a.metadata().clone()).await?;

    // 2. Create and register Agent B (the Worker)
    let mut agent_b = AgentNode::new(
        "Agent B".to_string(),
        vec!["secure_sum".to_string()],
        "http://agent-b:8080".to_string(),
        registry.clone(),
        tee.clone(),
        verifier.clone(),
        transport.clone(),
        Arc::new(RegoPolicyEngine::default()),
    );
    agent_b.mcp_server().add_tool(Box::new(SecureSum)).await;
    agent_b.start_heartbeat(std::time::Duration::from_secs(10));
    registry.register(agent_b.metadata().clone()).await?;

    println!("Mesh initialized with 2 agents.");

    // 3. Agent A discovers Agent B by capability
    println!("Agent A searching for 'secure_sum' capability...");
    let peers = registry.search("secure_sum").await?;
    let worker = peers.first().ok_or("No worker found")?;
    println!("Found worker: {} ({})", worker.name, worker.id);

    // 4. Agent A calls the tool on Agent B confidentially
    println!("Agent A calling 'secure_sum' on Agent B...");
    let result = agent_a
        .call_peer_tool(
            worker.id,
            "tools/call",
            json!({
                "name": "secure_sum",
                "arguments": { "a": 10, "b": 32 }
            }),
        )
        .await?;

    println!("Received result from Agent B: {}", result);

    Ok(())
}
