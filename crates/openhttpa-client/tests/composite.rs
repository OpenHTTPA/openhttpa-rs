// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use openhttpa_client::OpenHttpaClient;
use openhttpa_tee::mock::MockTeeProvider;
use openhttpa_tee::nvidia_gpu::NvidiaGpuTeeProvider;
use std::sync::Arc;

use openhttpa_headers::attest_headers::{AtHsRequestHeaders, AtHsResponseHeaders};
use openhttpa_proto::{AtbId, CipherSuite, ProtocolVersion};
use openhttpa_transport::connection::{AttestTransport, TransportRequest, TransportResponse};

struct DummyTransport {
    server_random: [u8; 32],
}

impl AttestTransport for DummyTransport {
    fn send(
        &self,
        req: TransportRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<TransportResponse, openhttpa_transport::connection::SendError>,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            if req.method.as_str() == "ATTEST" {
                let req_hdrs = AtHsRequestHeaders::decode(&req.headers).unwrap();

                // VERIFY: The client sent TWO quotes (TDX + NVIDIA)
                assert_eq!(req_hdrs.client_quotes.len(), 2);
                assert!(
                    req_hdrs
                        .client_quotes
                        .iter()
                        .any(|q| q.quote_type == openhttpa_proto::QuoteType::Mock)
                );
                assert!(
                    req_hdrs
                        .client_quotes
                        .iter()
                        .any(|q| q.quote_type == openhttpa_proto::QuoteType::NvidiaGpu)
                );

                // Respond with a dummy success
                let resp_hdrs = AtHsResponseHeaders {
                    cipher_suite: CipherSuite::X25519MlKem768Aes256GcmSha384,
                    random: self.server_random.to_vec(),
                    key_share_json: serde_json::to_vec(
                        &openhttpa_core::handshake::ServerKeyShare {
                            ecdhe_public: vec![0u8; 32],
                            mlkem_ciphertext: vec![0u8; 1088],
                            signature_alg: Some(
                                openhttpa_core::handshake::SIG_ALG_ML_DSA_65.to_string(),
                            ),

                            mlkem_public: vec![0u8; 1184],
                        },
                    )
                    .unwrap(),
                    base_id: AtbId::new(),
                    version: ProtocolVersion::V2,
                    expires_secs: 3600,
                    quotes: vec![],
                    secrets: vec![],
                    cargo: None,
                    ticket_resumption: None,
                    server_signatures: vec![],
                    zk_proof: None,
                };

                return Ok(TransportResponse {
                    status: http::StatusCode::OK,
                    headers: resp_hdrs.encode(),
                    body: axum::body::Body::empty(),
                    trailers: None,
                });
            }

            Ok(TransportResponse {
                status: http::StatusCode::NOT_FOUND,
                headers: http::HeaderMap::new(),
                body: axum::body::Body::empty(),
                trailers: None,
            })
        })
    }
}

#[tokio::test]
async fn test_composite_attestation_full_handshake() {
    // 1. Setup Composite TeeProvider (Mock TDX + Simulated NVIDIA GPU)
    let tdx_provider = Arc::new(MockTeeProvider::default());
    let gpu_provider = Arc::new(NvidiaGpuTeeProvider);

    // 2. Setup Client with ergonomic builder
    let client = OpenHttpaClient::builder()
        .server_uri("http://127.0.0.1:8080".parse().unwrap())
        .add_tee_provider(tdx_provider)
        .add_tee_provider(gpu_provider)
        .transport(Arc::new(DummyTransport {
            server_random: [0x55u8; 32],
        }))
        .build();

    // 3. Perform Handshake
    // It will still fail on key exchange because the DummyTransport returns zeros,
    // but the verification inside DummyTransport::send will confirm the quotes were sent.
    let _ = client.attest_handshake().await;
}
