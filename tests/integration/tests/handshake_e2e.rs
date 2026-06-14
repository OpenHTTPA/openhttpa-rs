// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Cross-crate end-to-end integration tests for the full Preflight → AtHS → AtSP → TrR flow.

use std::sync::Arc;
use tokio::net::TcpListener;

use openhttpa_attestation::MockVerifier;
use openhttpa_client::builder::OpenHttpaClientBuilder;
use openhttpa_server::OpenHttpaServerBuilder;
use openhttpa_server::extractors::OpenHttpaSession;
use openhttpa_tee::mock::MockTeeProvider;
use openhttpa_transport::reqwest_adapter::ReqwestTransport;

use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::post;

async fn echo_handler(
    session: OpenHttpaSession,
    openhttpa_server::extractors::EncryptedJson(payload): openhttpa_server::extractors::EncryptedJson<serde_json::Value>,
) -> Result<Response, StatusCode> {
    println!("echo_handler: received request");

    let session_inner = session.session;
    println!("echo_handler: encrypting response");
    let plaintext = serde_json::to_vec(&payload).unwrap();

    let base_id = session_inner.state().id;
    // Encrypt response
    let res = session_inner
        .with_keys_for_trs(|keys, counter| {
            println!("echo_handler: inside with_keys_for_trs");
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
            let mut data = plaintext;
            println!("echo_handler: sealing");
            key.seal_in_place(&aead_nonce, &session.aad, &mut data)
                .unwrap();
            println!("echo_handler: sealed");
            let resp_json = serde_json::json!({ "ciphertext": hex::encode(data) });
            let resp_bytes = serde_json::to_vec(&resp_json).unwrap();
            let mut resp = Response::builder()
                .status(200)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(resp_bytes))
                .unwrap();
            resp.headers_mut().insert(
                openhttpa_headers::HDR_ATTEST_BASE_ID.as_str(),
                axum::http::HeaderValue::from_str(&base_id.to_string()).unwrap(),
            );
            println!("echo_handler: returning response");
            Ok::<Response, ()>(resp)
        })
        .unwrap()
        .unwrap();

    println!("echo_handler: handler done");
    Ok(res)
}

#[tokio::test]
async fn test_full_handshake_flow_e2e() {
    let tee_provider = Arc::new(MockTeeProvider::default());
    let verifier = Arc::new(MockVerifier::default());

    // 1. Start Server
    let executor = Arc::new(openhttpa_core::handshake::AtHsExecutor::with_config(
        vec![],
        vec![
            openhttpa_proto::ProtocolVersion::V2,
            openhttpa_proto::ProtocolVersion::V1,
        ],
        false, // require_provenance
        true,  // allow_debug
    ));

    let builder = OpenHttpaServerBuilder::new()
        .with_executor(executor)
        .with_tee_provider(tee_provider.clone())
        .with_verifier(verifier.clone());
    let registry = builder.registry.clone();
    let base_router = builder.build();

    let app = base_router.route(
        "/echo",
        post(echo_handler).with_state(registry.clone()).route_layer(
            openhttpa_server::middleware::TrRequestLayer::new(registry.clone()),
        ),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let server_uri = format!("http://{}", addr).parse().unwrap();

    // 2. Build Client
    let transport = Arc::new(ReqwestTransport::new());
    let client = OpenHttpaClientBuilder::default()
        .server_uri(server_uri)
        .tee_provider(tee_provider.clone())
        .verifier(verifier.clone())
        .transport(transport)
        .require_preflight(true)
        .build();

    // 3. Perform Handshake
    let session = client.attest_handshake().await.expect("Handshake failed");

    // The handshake succeeded and returned an AttestSession.

    // 4. Perform Trusted Request
    println!("test: sending echo request");
    let payload_str = "\"hello openhttpa\"";
    let payload = payload_str.as_bytes();
    let echo_resp = client
        .trusted_request(&session, "POST", "/echo", payload)
        .await
        .unwrap();
    println!("test: got echo response");

    let expected_resp = serde_json::to_vec(&serde_json::json!("hello openhttpa")).unwrap();
    assert_eq!(echo_resp, expected_resp);
}

#[tokio::test]
async fn test_metadata_protection_e2e() {
    let tee_provider = Arc::new(MockTeeProvider::default());
    let verifier = Arc::new(MockVerifier::default());

    let executor = Arc::new(openhttpa_core::handshake::AtHsExecutor::with_config(
        vec![],
        vec![openhttpa_proto::ProtocolVersion::V2],
        false,
        true,
    ));

    let hpke_pair = openhttpa_crypto::pqc::MlKemPair::generate().unwrap();
    let hpke_pub = hpke_pair.public_encap_key().to_vec();

    let builder = OpenHttpaServerBuilder::new()
        .with_executor(executor)
        .with_tee_provider(tee_provider.clone())
        .with_verifier(verifier.clone())
        .with_hpke_key(hpke_pair);

    let _registry = builder.registry.clone();
    let base_router = builder.build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, base_router).await.unwrap();
    });

    let server_uri = format!("http://{}/attest", addr);

    // Craft a manual Encrypted Hello request
    let payload = openhttpa_proto::EncryptedHelloPayload {
        inner_headers: vec![],
        is_cover_traffic: true,
    };
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let hpke_ct = openhttpa_crypto::hpke::HpkeClient::seal(&hpke_pub, &payload_bytes).unwrap();

    let mut eh = hpke_ct.mlkem_ct;
    eh.extend_from_slice(&hpke_ct.payload_ct);
    eh.extend_from_slice(&hpke_ct.tag);

    use openhttpa_proto::{AtbCreation, CipherSuite, ProtocolVersion};
    let req_hdrs = openhttpa_headers::attest_headers::AtHsRequestHeaders {
        cipher_suites: vec![CipherSuite::X25519MlKem768Aes256GcmSha384],
        random: vec![0u8; 32],
        versions: vec![ProtocolVersion::V2],
        key_shares_json: b"{}".to_vec(),
        date: "2026-04-27T00:00:00Z".to_owned(),
        base_creation: AtbCreation::New,
        direct_attestation: true,
        allow_untrusted_requests: true,
        client_quotes: vec![],
        encrypted_hello: Some(eh),
        challenge: None,
        signatures: vec![],
        ticket: None,
        provenance: None,
    };

    let http_client = reqwest::Client::new();
    let resp = http_client
        .post(&server_uri)
        .headers(req_hdrs.encode())
        .send()
        .await
        .unwrap();

    // Cover traffic returns 200 OK
    assert_eq!(resp.status(), StatusCode::OK);
}

struct RejectingVerifier;

impl openhttpa_attestation::verifier::QuoteVerifier for RejectingVerifier {
    fn verify<'a>(
        &'a self,
        _quote: &'a openhttpa_proto::AttestQuote,
        _report_data: &'a [u8; 64],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        openhttpa_proto::VerificationResult,
                        openhttpa_proto::AttestError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move { Err(openhttpa_proto::AttestError::SignatureInvalid) })
    }
}

#[tokio::test]
async fn test_attestation_rejection_e2e() {
    let tee_provider = Arc::new(MockTeeProvider::default());
    let verifier = Arc::new(RejectingVerifier);

    let executor = Arc::new(openhttpa_core::handshake::AtHsExecutor::with_config(
        vec![],
        vec![openhttpa_proto::ProtocolVersion::V2],
        false,
        true,
    ));

    let builder = OpenHttpaServerBuilder::new()
        .with_executor(executor)
        .with_tee_provider(tee_provider.clone())
        .with_verifier(verifier.clone());

    let base_router = builder.build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, base_router).await.unwrap();
    });

    let server_uri = format!("http://{}", addr).parse().unwrap();

    let transport = Arc::new(ReqwestTransport::new());
    let client = OpenHttpaClientBuilder::default()
        .server_uri(server_uri)
        .tee_provider(tee_provider.clone())
        .verifier(Arc::new(MockVerifier::default())) // Client trusts server
        .transport(transport)
        .require_preflight(true)
        .build();

    let res = client.attest_handshake().await;
    // Server rejects because verifier rejects client quote
    assert!(res.is_err());
}

type RecordedRequest = (
    axum::http::Method,
    axum::http::Uri,
    axum::http::HeaderMap,
    bytes::Bytes,
);

#[derive(Clone)]
struct RecordingTransport {
    inner: Arc<ReqwestTransport>,
    last_req: Arc<tokio::sync::Mutex<Option<RecordedRequest>>>,
}

impl openhttpa_transport::AttestTransport for RecordingTransport {
    fn send(
        &self,
        request: openhttpa_transport::TransportRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        openhttpa_transport::TransportResponse,
                        openhttpa_transport::SendError,
                    >,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            let body_bytes = openhttpa_transport::connection::to_bytes(request.body, 1024 * 1024)
                .await
                .unwrap();
            *self.last_req.lock().await = Some((
                request.method.clone(),
                request.uri.clone(),
                request.headers.clone(),
                body_bytes.clone(),
            ));

            let new_req = openhttpa_transport::TransportRequest {
                method: request.method,
                uri: request.uri,
                headers: request.headers,
                body: openhttpa_transport::connection::full_body(body_bytes),
                trailers: request.trailers,
            };
            self.inner.send(new_req).await
        })
    }
}

#[tokio::test]
async fn test_replay_attack_prevention_e2e() {
    let tee_provider = Arc::new(MockTeeProvider::default());
    let verifier = Arc::new(MockVerifier::default());

    let executor = Arc::new(openhttpa_core::handshake::AtHsExecutor::with_config(
        vec![],
        vec![openhttpa_proto::ProtocolVersion::V2],
        false,
        true,
    ));

    let builder = OpenHttpaServerBuilder::new()
        .with_executor(executor)
        .with_tee_provider(tee_provider.clone())
        .with_verifier(verifier.clone());

    let registry = builder.registry.clone();
    let base_router = builder.build();

    let app = base_router.route(
        "/echo",
        post(echo_handler).with_state(registry.clone()).route_layer(
            openhttpa_server::middleware::TrRequestLayer::new(registry.clone()),
        ),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let server_uri: axum::http::Uri = format!("http://{}", addr).parse().unwrap();

    let inner_transport = Arc::new(ReqwestTransport::new());
    let recording_transport = Arc::new(RecordingTransport {
        inner: inner_transport.clone(),
        last_req: Arc::new(tokio::sync::Mutex::new(None)),
    });

    let client = OpenHttpaClientBuilder::default()
        .server_uri(server_uri.clone())
        .tee_provider(tee_provider.clone())
        .verifier(verifier.clone())
        .transport(recording_transport.clone())
        .require_preflight(true)
        .build();

    let session = client.attest_handshake().await.expect("Handshake failed");

    // Try request 1 (Should succeed)
    let payload_str = "\"hello openhttpa\"";
    let echo_resp = client
        .trusted_request(&session, "POST", "/echo", payload_str.as_bytes())
        .await
        .unwrap();

    let expected_resp = serde_json::to_vec(&serde_json::json!("hello openhttpa")).unwrap();
    assert_eq!(echo_resp, expected_resp);

    // Try request 2 (Replay exactly what was recorded)
    let last_req = recording_transport
        .last_req
        .lock()
        .await
        .clone()
        .expect("Request was not recorded");
    let (method, uri, headers, body) = last_req;

    let replay_req = openhttpa_transport::TransportRequest {
        method,
        uri,
        headers,
        body: openhttpa_transport::connection::full_body(body),
        trailers: None,
    };
    use openhttpa_transport::AttestTransport;
    let resp2 = inner_transport.send(replay_req).await;

    match resp2 {
        Ok(resp) => {
            assert!(
                resp.status.is_client_error(),
                "Replay attack succeeded when it should have failed (got status {})",
                resp.status
            );
        }
        Err(_) => {
            // Transport error is also a failure, which is fine for a rejected replay
        }
    }
}
