// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use openhttpa_oracle::OracleNode;
use openhttpa_tee::mock::MockTeeProvider;
use std::sync::Arc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_oracle_fetch_and_prove_mock() {
    // 1. Start a mock server
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/test-data"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{\"price\": 100}"))
        .mount(&mock_server)
        .await;

    // 2. Initialize Mock TEE Provider
    let provider = Arc::new(MockTeeProvider::default());

    // 3. Initialize Oracle Node
    let oracle = OracleNode::new(provider);

    // 4. Define target URL (pointing to mock server) and transcript hash
    let target_url = format!("{}/test-data", mock_server.uri());
    let transcript_hash = [8u8; 48]; // Dummy hash

    // 5. Fetch and generate mock proof
    let response = oracle
        .fetch_and_prove(&target_url, transcript_hash, true)
        .await
        .expect("Failed to fetch and prove");

    // 6. Assertions
    assert!(
        !response.data.is_empty(),
        "Data payload should not be empty"
    );
    assert_eq!(response.data, b"{\"price\": 100}");
    assert!(!response.quote.is_empty(), "TEE Quote should not be empty");
    assert_eq!(
        response.transcript_hash, transcript_hash,
        "Transcript hash must match"
    );

    // Check if ZK receipt was generated
    assert!(
        response.zk_receipt.is_some(),
        "ZK Receipt should be generated"
    );
}
