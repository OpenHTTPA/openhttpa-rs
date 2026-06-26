// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! # openhttpa-mesh
//!
//! Attested Agent Mesh (AAM) implementation for secure AI agent communication.
//! This crate provides the building blocks for creating a network of AI agents
//! where each agent's identity and environment are hardware-verified.

#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_code)]

use openhttpa_core::session::AttestSession;
pub use openhttpa_proto::AttestQuote;
use std::sync::Arc;

pub mod node;
pub mod policy;
pub mod provenance;
pub mod registry;

pub use node::AgentNode;
pub use openhttpa_proto::{AgentMetadata, ProvenanceChain};
pub use policy::{PolicyEngine, RegoPolicyEngine};
pub use registry::AgentRegistry;

/// A session between two agents in the mesh.
pub struct AgentSession {
    pub peer_metadata: AgentMetadata,
    pub session: Arc<AttestSession>,
}

/// Error types for the mesh.
// MED-06: non_exhaustive prevents breaking changes when new variants are added.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    #[error("handshake failed: {0}")]
    Handshake(String),
    #[error("attestation verification failed: {0}")]
    Attestation(String),
    #[error("peer not found: {0}")]
    PeerNotFound(String),
    #[error("mcp error: {0}")]
    Mcp(String),
    #[error("registry error: {0}")]
    Registry(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::MockRegistry;
    use openhttpa_attestation::verifier::{QuoteVerifier, VerificationError, VerificationResult};
    use openhttpa_proto::AttestQuote;
    use openhttpa_tee::mock::MockTeeProvider;

    struct MockVerifier;
    impl QuoteVerifier for MockVerifier {
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
            })
        }
    }

    struct MockTransport;
    impl openhttpa_transport::connection::AttestTransport for MockTransport {
        fn send(
            &self,
            req: openhttpa_transport::connection::TransportRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            openhttpa_transport::connection::TransportResponse,
                            openhttpa_transport::connection::SendError,
                        >,
                    > + Send
                    + '_,
            >,
        > {
            Box::pin(async move {
                // Mock ATTEST response
                if req.method.as_str() == "ATTEST" {
                    let req_hdrs =
                        openhttpa_headers::attest_headers::AtHsRequestHeaders::decode(&req.headers)
                            .unwrap();
                    let client_share: openhttpa_core::handshake::ClientKeyShare =
                        serde_json::from_slice(&req_hdrs.key_shares_json).unwrap();

                    let server_pair =
                        openhttpa_crypto::key_exchange::HybridKemPair::generate().unwrap();
                    let server_pub = server_pair.public_key_share();
                    let client_ks = openhttpa_crypto::key_exchange::KeyShare {
                        ecdhe_public: client_share.ecdhe_public,

                        mlkem_public: client_share.mlkem_public,
                    };
                    let (_, ct) = server_pair.server_combine(&client_ks).unwrap();

                    let resp_hdrs = openhttpa_headers::attest_headers::AtHsResponseHeaders {
                        cipher_suite: openhttpa_proto::CipherSuite::X25519MlKem768Aes256GcmSha384,
                        random: vec![0u8; 32],
                        key_share_json: serde_json::to_vec(
                            &openhttpa_core::handshake::ServerKeyShare {
                                ecdhe_public: server_pub.ecdhe_public,
                                mlkem_ciphertext: ct,
                                signature_alg: Some(openhttpa_core::handshake::SIG_ALG_ML_DSA_65),

                                mlkem_public: server_pub.mlkem_public,
                            },
                        )
                        .unwrap(),
                        base_id: openhttpa_proto::AtbId::new(),
                        version: openhttpa_proto::ProtocolVersion::V2,
                        expires_secs: 3600,
                        quotes: vec![openhttpa_proto::AttestQuote {
                            collateral_uris: vec![],
                            quote_type: openhttpa_proto::QuoteType::Mock,
                            format: openhttpa_proto::QuoteFormat::default(),
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
                        body: openhttpa_transport::connection::empty_body(),
                        trailers: None,
                    });
                }
                Ok(openhttpa_transport::connection::TransportResponse {
                    status: http::StatusCode::OK,
                    headers: http::HeaderMap::new(),
                    body: openhttpa_transport::connection::full_body(
                        b"{\"result\": \"success\"}".to_vec(),
                    ),
                    trailers: None,
                })
            })
        }
    }

    #[tokio::test]
    async fn test_agent_node_discovery() {
        let registry = Arc::new(MockRegistry::new());
        let tee = Arc::new(MockTeeProvider::default());
        let verifier = Arc::new(MockVerifier);
        let transport = Arc::new(MockTransport);

        let policy = Arc::new(RegoPolicyEngine::permissive());

        let node_a = AgentNode::new(
            "Agent A".to_string(),
            vec!["calc".to_string()],
            "http://agent-a:8080".to_string(),
            registry.clone(),
            tee.clone(),
            verifier.clone(),
            transport.clone(),
            policy.clone(),
        );

        let node_b = AgentNode::new(
            "Agent B".to_string(),
            vec!["sum".to_string()],
            "http://agent-b:8080".to_string(),
            registry.clone(),
            tee.clone(),
            verifier.clone(),
            transport.clone(),
            policy.clone(),
        );

        registry.register(node_a.metadata().clone()).await.unwrap();
        registry.register(node_b.metadata().clone()).await.unwrap();

        let peers = registry.search("sum").await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name, "Agent B");
    }

    #[tokio::test]
    async fn test_agent_node_connection() {
        let registry = Arc::new(MockRegistry::new());
        let tee = Arc::new(MockTeeProvider::default());
        let verifier = Arc::new(MockVerifier);
        let transport = Arc::new(MockTransport);

        let permissive_rego = r"
            package openhttpa.mesh
            default allow = true
        ";
        let policy = Arc::new(
            RegoPolicyEngine::new("permissive".to_string(), permissive_rego.to_string()).unwrap(),
        );

        let node_a = AgentNode::new(
            "Agent A".to_string(),
            vec![],
            "http://agent-a:8080".to_string(),
            registry.clone(),
            tee.clone(),
            verifier.clone(),
            transport.clone(),
            policy.clone(),
        );

        let node_b = AgentNode::new(
            "Agent B".to_string(),
            vec![],
            "http://agent-b:8080".to_string(),
            registry.clone(),
            tee.clone(),
            verifier.clone(),
            transport.clone(),
            policy.clone(),
        );

        registry.register(node_b.metadata().clone()).await.unwrap();

        let session = node_a.connect_to_peer(node_b.metadata().id).await.unwrap();
        assert_eq!(session.peer_metadata.name, "Agent B");
        assert!(session.session.is_alive());
    }
}
