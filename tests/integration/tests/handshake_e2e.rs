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
