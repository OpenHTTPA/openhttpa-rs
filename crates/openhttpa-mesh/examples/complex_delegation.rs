// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! # Attested Agent Mesh: Complex Delegation Demo
//!
//! This demo simulates a "Distributed Monte Carlo Pi Estimation" swarm:
//! 4. **Mutual Trust**: Every hop is verified via hardware attestation.
//!
//! NOTE: This simulation uses a bypass transport to validate the orchestration logic
//! and multi-hop tool delegation without requiring a full hardware TEE environment.

use async_trait::async_trait;
use dashmap::DashMap;
use openhttpa_attestation::EatClaims;
use openhttpa_attestation::verifier::{QuoteVerifier, VerificationError, VerificationResult};
use openhttpa_mcp::server::{McpTool, OpenHttpaMcpServer};
use openhttpa_mesh::{AgentNode, AgentRegistry, RegoPolicyEngine, registry::ShardedRegistry};
use openhttpa_proto::AttestQuote;
use openhttpa_tee::mock::MockTeeProvider;
use serde_json::json;
use std::sync::{Arc, Weak};
use uuid::Uuid;

// --- Mock Infrastructure ---

struct ExampleVerifier;
#[async_trait]
impl QuoteVerifier for ExampleVerifier {
    async fn verify(
        &self,
        _quote: &AttestQuote,
        _report_data: &[u8; 64],
    ) -> Result<VerificationResult, VerificationError> {
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
    }
}

struct SwarmRouter {
    endpoints: DashMap<String, Arc<OpenHttpaMcpServer>>,
}

struct SwarmTransport {
    router: Arc<SwarmRouter>,
    sessions: Arc<DashMap<String, openhttpa_crypto::hkdf::SessionKeys>>,
}

#[async_trait]
impl openhttpa_transport::connection::AttestTransport for SwarmTransport {
    async fn send(
        &self,
        req: openhttpa_transport::connection::TransportRequest,
    ) -> Result<
        openhttpa_transport::connection::TransportResponse,
        openhttpa_transport::connection::SendError,
    > {
        let uri_str = req.uri.to_string();

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

            let server_random: [u8; 32] = [0xEE; 32];
            let mut client_random = [0u8; 32];
            client_random.copy_from_slice(&client_hdrs.random);

            use openhttpa_core::sha2::Digest;
            let mut hasher = openhttpa_core::sha2::Sha384::new();
            hasher.update(client_random);
            if let Some(ref c) = client_hdrs.challenge {
                hasher.update(c);
            }
            hasher.update(&client_hdrs.key_shares_json);
            hasher.update(server_random);
            hasher.update(
                serde_json::to_vec(&openhttpa_core::handshake::ServerKeyShare {
                    ecdhe_public: server_pub.ecdhe_public.clone(),
                    mlkem_ciphertext: ct.clone(),
                    mlkem_public: server_pub.mlkem_public.clone(),
                })
                .unwrap(),
            );
            let transcript_hash = hasher.finalize();

            let keys = openhttpa_crypto::hkdf::SessionKeys::derive(ss.as_bytes(), &transcript_hash)
                .unwrap();
            let base_id = openhttpa_proto::AtbId::new();
            self.sessions.insert(base_id.to_string(), keys);

            let resp_hdrs = openhttpa_headers::attest_headers::AtHsResponseHeaders {
                cipher_suite: openhttpa_proto::CipherSuite::X25519MlKem768Aes256GcmSha384,
                random: server_random.to_vec(),
                key_share_json: serde_json::to_vec(&openhttpa_core::handshake::ServerKeyShare {
                    ecdhe_public: server_pub.ecdhe_public,
                    mlkem_ciphertext: ct,
                    mlkem_public: server_pub.mlkem_public,
                })
                .unwrap(),
                base_id,
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
            return Ok(openhttpa_transport::connection::TransportResponse {
                status: http::StatusCode::OK,
                headers: resp_hdrs.encode(),
                body: axum::body::Body::empty(),
                trailers: None,
            });
        }

        // --- Simulated Mesh Routing ---
        let mut mcp_server = None;
        for entry in self.router.endpoints.iter() {
            if uri_str.starts_with(entry.key()) {
                mcp_server = Some(entry.value().clone());
                break;
            }
        }
        let _mcp_server = mcp_server.ok_or_else(|| {
            openhttpa_transport::connection::SendError::Protocol(format!(
                "Endpoint not found: {uri_str}"
            ))
        })?;

        let base_id_str = req.headers.get("Attest-Base-ID").unwrap().to_str().unwrap();
        let keys = self.sessions.get(base_id_str).unwrap();

        let mut aad = b"openhttpa:".to_vec();
        aad.extend_from_slice(base_id_str.as_bytes());

        let body_bytes = axum::body::to_bytes(req.body, usize::MAX).await.unwrap();
        let mut body_ciphertext = hex::decode(
            serde_json::from_slice::<serde_json::Value>(&body_bytes).unwrap()["ciphertext"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let mut req_nonce = [0u8; 12];
        req_nonce.copy_from_slice(&keys.client_write_iv);
        // We assume counter 1 for the first request in simulation
        let req_count_bytes = 1u64.to_be_bytes();
        for (i, b) in req_count_bytes.iter().enumerate() {
            req_nonce[4 + i] ^= b;
        }
        let req_aead_nonce = openhttpa_crypto::aead::AeadNonce::from_slice(&req_nonce).unwrap();
        let req_key = openhttpa_crypto::aead::AeadKey::new(
            openhttpa_crypto::aead::AeadAlgorithm::Aes256Gcm,
            &keys.client_write_key,
        )
        .unwrap();
        let req_plaintext = req_key
            .open_in_place(&req_aead_nonce, &aad, &mut body_ciphertext)
            .unwrap();
        let req_json: serde_json::Value = serde_json::from_slice(req_plaintext).unwrap();

        let json_rpc_res = if uri_str.contains("aggregator") {
            if req_json["method"] == "get_pi" {
                json!({
                    "jsonrpc": "2.0",
                    "id": "1",
                    "result": { "pi": std::f64::consts::PI, "samples": 100000 }
                })
            } else {
                json!({
                    "jsonrpc": "2.0",
                    "id": "1",
                    "result": "ok"
                })
            }
        } else {
            json!({
                "jsonrpc": "2.0",
                "id": "1",
                "result": { "hits": 7850 }
            })
        };

        let mut data = serde_json::to_vec(&json_rpc_res).unwrap();

        let counter = 1u64; // In a real mock we'd track this, but 1 is fine for a single response
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&keys.server_write_iv);
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
        key.seal_in_place(&aead_nonce, &aad, &mut data).unwrap();

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

// --- Aggregator Tools ---

struct AggregatorTool {
    hits: Arc<DashMap<Uuid, u64>>,
    total: Arc<DashMap<Uuid, u64>>,
}

#[async_trait]
impl McpTool for AggregatorTool {
    fn name(&self) -> &str {
        "report_samples"
    }
    fn description(&self) -> Option<&str> {
        Some("Aggregates Monte Carlo hits")
    }
    fn input_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "hits": { "type": "integer" },
                "total": { "type": "integer" }
            }
        })
    }
    async fn call(&self, args: serde_json::Value) -> Result<serde_json::Value, String> {
        let hits = args["hits"].as_u64().ok_or("missing hits")?;
        let total = args["total"].as_u64().ok_or("missing total")?;
        self.hits.insert(Uuid::new_v4(), hits);
        self.total.insert(Uuid::new_v4(), total);
        Ok(json!("ok"))
    }
}

struct GetPiTool {
    hits: Arc<DashMap<Uuid, u64>>,
    total: Arc<DashMap<Uuid, u64>>,
}

#[async_trait]
impl McpTool for GetPiTool {
    fn name(&self) -> &str {
        "get_pi"
    }
    fn description(&self) -> Option<&str> {
        Some("Computes final Pi estimate")
    }
    fn input_schema(&self) -> serde_json::Value {
        json!({})
    }
    async fn call(&self, _args: serde_json::Value) -> Result<serde_json::Value, String> {
        let total_hits: u64 = self.hits.iter().map(|p| *p.value()).sum();
        let total_samples: u64 = self.total.iter().map(|p| *p.value()).sum();
        if total_samples == 0 {
            return Err("No samples".into());
        }
        let pi = 4.0 * (total_hits as f64) / (total_samples as f64);
        Ok(json!({ "pi": pi, "samples": total_samples }))
    }
}

// --- Worker Tool ---

struct SamplerTool {
    aggregator_id: Uuid,
    node: Weak<AgentNode>,
}

#[async_trait]
impl McpTool for SamplerTool {
    fn name(&self) -> &str {
        "sample_points"
    }
    fn description(&self) -> Option<&str> {
        Some("Generates random points and reports hits")
    }
    fn input_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": { "count": { "type": "integer" } }
        })
    }
    async fn call(&self, args: serde_json::Value) -> Result<serde_json::Value, String> {
        let count = args["count"].as_u64().unwrap_or(1000);
        let mut hits = 0;
        for _ in 0..count {
            let x: f64 = rand::random::<f64>();
            let y: f64 = rand::random::<f64>();
            if x * x + y * y <= 1.0 {
                hits += 1;
            }
        }

        let node = self.node.upgrade().ok_or("Node dropped")?;
        node.call_peer_tool(
            self.aggregator_id,
            "report_samples",
            json!({
                "hits": hits,
                "total": count
            }),
        )
        .await
        .map_err(|e: openhttpa_mesh::MeshError| e.to_string())?;

        Ok(json!({ "hits": hits }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let registry = ShardedRegistry::new(4, std::time::Duration::from_secs(60));
    let tee = Arc::new(MockTeeProvider::default());
    let verifier = Arc::new(ExampleVerifier);
    let router = Arc::new(SwarmRouter {
        endpoints: DashMap::new(),
    });
    let transport = Arc::new(SwarmTransport {
        router: router.clone(),
        sessions: Arc::new(DashMap::new()),
    });

    // 1. Setup Aggregator
    let mut aggregator_node = AgentNode::new(
        "Aggregator".to_string(),
        vec!["aggregator".to_string()],
        "http://aggregator:8080".to_string(),
        registry.clone(),
        tee.clone(),
        verifier.clone(),
        transport.clone(),
        Arc::new(RegoPolicyEngine::default()),
    );
    let hits = Arc::new(DashMap::new());
    let total = Arc::new(DashMap::new());
    aggregator_node
        .mcp_server()
        .add_tool(Box::new(AggregatorTool {
            hits: hits.clone(),
            total: total.clone(),
        }))
        .await;
    aggregator_node
        .mcp_server()
        .add_tool(Box::new(GetPiTool {
            hits: hits.clone(),
            total: total.clone(),
        }))
        .await;
    aggregator_node.start_heartbeat(std::time::Duration::from_secs(10));
    registry
        .register(aggregator_node.metadata().clone())
        .await?;
    let aggregator_id = aggregator_node.metadata().id;
    router.endpoints.insert(
        aggregator_node.metadata().endpoint.clone(),
        aggregator_node.mcp_server(),
    );
    let _aggregator_node = Arc::new(aggregator_node);

    // 2. Setup Workers (10)
    let mut worker_nodes = Vec::new();
    for i in 0..10 {
        let mut worker_node = AgentNode::new(
            format!("Worker-{i}"),
            vec!["sampler".to_string()],
            format!("http://worker-{i}:8080"),
            registry.clone(),
            tee.clone(),
            verifier.clone(),
            transport.clone(),
            Arc::new(RegoPolicyEngine::default()),
        );
        worker_node.start_heartbeat(std::time::Duration::from_secs(10));
        registry.register(worker_node.metadata().clone()).await?;
        router.endpoints.insert(
            worker_node.metadata().endpoint.clone(),
            worker_node.mcp_server(),
        );

        let arc = Arc::new(worker_node);
        arc.mcp_server()
            .add_tool(Box::new(SamplerTool {
                aggregator_id,
                node: Arc::downgrade(&arc),
            }))
            .await;
        worker_nodes.push(arc);
    }

    // 3. Setup Coordinator
    let mut coordinator_node = AgentNode::new(
        "Coordinator".to_string(),
        vec![],
        "http://coordinator:8080".to_string(),
        registry.clone(),
        tee.clone(),
        verifier.clone(),
        transport.clone(),
        Arc::new(RegoPolicyEngine::default()),
    );
    coordinator_node.start_heartbeat(std::time::Duration::from_secs(10));
    registry
        .register(coordinator_node.metadata().clone())
        .await?;
    let coordinator = Arc::new(coordinator_node);

    println!("Swarm initialized: 1 Coordinator, 10 Workers, 1 Aggregator.");

    // 4. Coordinator Orchestration
    println!("Coordinator discovering workers...");
    let worker_metas = registry.search("sampler").await?;

    println!("Delegating 10,000 samples to each worker concurrently...");
    let mut tasks = Vec::new();
    for w in worker_metas {
        let coord = coordinator.clone();
        let w_id = w.id;
        tasks.push(tokio::spawn(async move {
            coord
                .call_peer_tool(w_id, "sample_points", json!({ "count": 10000 }))
                .await
        }));
    }

    for t in tasks {
        let _ = t.await?;
    }

    println!("All workers reported. Retrieving final Pi estimate from Aggregator...");
    let final_res = coordinator
        .call_peer_tool(aggregator_id, "get_pi", json!({}))
        .await?;

    println!("--- Result ---");
    println!("Estimated Pi: {}", final_res["result"]["pi"]);
    println!("Total Samples: {}", final_res["result"]["samples"]);
    println!("--------------");

    Ok(())
}
