// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! End-to-End Enterprise Integration Test for OpenHTTPA.
//!
//! This test ensures that the SPIFFE identity provider and the Confidential
//! Telemetry layer can be wired together securely in a single application.

use hpke::{Serializable, kem::X25519HkdfSha256};
use openhttpa_spiffe::SpiffeTeeProvider;
use openhttpa_tee::{QuoteRequest, mock::MockTeeProvider};
use openhttpa_telemetry::ConfidentialTelemetryLayer;
use rand::SeedableRng;
use std::sync::Arc;
use tracing::{info, subscriber::with_default};
use tracing_subscriber::{Registry, layer::SubscriberExt};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_enterprise_e2e_flow() {
    // 1. Setup Confidential Telemetry
    let mut csprng = rand::rngs::StdRng::from_os_rng();
    let (_sk, pk) = <X25519HkdfSha256 as hpke::kem::Kem>::gen_keypair(&mut csprng);

    let telemetry_layer =
        ConfidentialTelemetryLayer::new(&pk.to_bytes()).expect("Telemetry initialization failed");
    let subscriber = Registry::default().with(telemetry_layer);

    with_default(subscriber, || {
        info!(action = "startup", "Initializing OpenHTTPA Enclave");

        // 2. Setup SPIFFE Provider
        let hardware_provider = Arc::new(MockTeeProvider::default());
        // Using a mock path for the test, fetch_svid will fail but generate_quote should succeed
        let spiffe_provider =
            SpiffeTeeProvider::new(hardware_provider, "unix:///tmp/mock-spire.sock");

        // 3. Simulate an Attestation Request (Envoy WASM would trigger this)
        let request = QuoteRequest {
            report_data: [0; 64],
        };

        let result = openhttpa_tee::TeeProvider::generate_quote(&spiffe_provider, &request);
        assert!(result.is_ok(), "Enterprise attestation flow failed");

        info!(
            action = "attestation_complete",
            "Successfully generated quote"
        );
    });
}
