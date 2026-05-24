// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! # Attested Agent Mesh: Massive Swarm Simulation
//!
//! This example simulates a large-scale decentralized mesh of 100 autonomous agents.
//! It demonstrates the efficiency and scalability of the `OpenHTTPA` handshake protocol:
//! 1. **Massive Registration**: 100 agents are initialized and registered concurrently.
//! 2. **Capability Search**: An agent discovers all peers with a specific capability (Prime Test).
//! 3. **Parallel Handshakes**: The agent performs concurrent `OpenHTTPA` handshakes with all discovered peers.
//! 4. **Cryptographic Isolation**: Each session uses unique, transcript-bound keys derived from TEE quotes.

use async_trait::async_trait;
use openhttpa_attestation::EatClaims;
use openhttpa_attestation::verifier::{QuoteVerifier, VerificationError, VerificationResult};
use openhttpa_mesh::{AgentNode, AgentRegistry, RegoPolicyEngine, registry::ShardedRegistry};
use openhttpa_proto::AttestQuote;
use openhttpa_tee::mock::MockTeeProvider;
use std::sync::Arc;

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

struct MockTransport;
#[async_trait]
impl openhttpa_transport::connection::AttestTransport for MockTransport {
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
                ecdhe_public: client_share.ecdhe_public,
                mlkem_public: client_share.mlkem_public,
            };
            let (_, ct) = server_pair.server_combine(&client_ks).unwrap();

            let resp_hdrs = openhttpa_headers::attest_headers::AtHsResponseHeaders {
                cipher_suite: openhttpa_proto::CipherSuite::X25519MlKem768Aes256GcmSha384,
                random: vec![0u8; 32],
                key_share_json: serde_json::to_vec(&openhttpa_core::handshake::ServerKeyShare {
                    ecdhe_public: server_pub.ecdhe_public,
                    mlkem_ciphertext: ct,
                    mlkem_public: server_pub.mlkem_public,
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
            body: axum::body::Body::from("{\"result\": \"ok\"}"),
            trailers: None,
        })
    }
}

#[allow(clippy::manual_is_multiple_of)]
fn is_prime(n: u32) -> bool {
    if n <= 1 {
        return false;
    }
    for i in 2..=((n as f64).sqrt() as u32) {
        if n % i == 0 {
            return false;
        }
    }
    true
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let registry = ShardedRegistry::new(4, std::time::Duration::from_secs(60));
    let tee = Arc::new(MockTeeProvider::default());
    let verifier = Arc::new(ExampleVerifier);

    let mut agents = Vec::new();
    for i in 0..100 {
        let mut agent = AgentNode::new(
            format!("Agent-{i}"),
            vec!["prime_test".to_string()],
            format!("http://agent-{i}.mesh:8080"),
            registry.clone(),
            tee.clone(),
            verifier.clone(),
            Arc::new(MockTransport),
            Arc::new(RegoPolicyEngine::default()),
        );
        agent.start_heartbeat(std::time::Duration::from_secs(10));
        let agent = Arc::new(agent);
        registry.register(agent.metadata().clone()).await?;
        agents.push(agent);
    }

    println!("Mesh populated with 100 agents.");

    // Select a subset to simulate a swarm
    let requester = agents[1].clone(); // Use Agent-1 as the requester
    let primes = agents
        .iter()
        .filter(|a| {
            let n: u32 = a
                .metadata()
                .name
                .split('-')
                .nth(1)
                .unwrap()
                .parse()
                .unwrap();
            is_prime(n)
        })
        .collect::<Vec<_>>();

    let total_primes = primes.len();
    println!(
        "Agent-1 initiating swarm handshake with {} prime agents...",
        total_primes
    );

    let mut tasks = Vec::new();
    for p in primes {
        let requester_ref = requester.clone();
        let p_id = p.metadata().id;
        tasks.push(tokio::spawn(async move {
            requester_ref.connect_to_peer(p_id).await
        }));
    }

    let mut success_count = 0;
    for task in tasks {
        if let Ok(Ok(_)) = task.await {
            success_count += 1;
        }
    }

    println!(
        "Successfully established {}/{} attested sessions.",
        success_count, total_primes
    );

    Ok(())
}
