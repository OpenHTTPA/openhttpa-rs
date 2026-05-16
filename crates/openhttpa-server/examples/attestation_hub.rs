// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! # Self-Hosted `OpenHTTPA` Attestation Hub
//!
//! This example demonstrates how to build a powerful, self-hosted attestation service
//! that uses `OpenHTTPA` for secure transport.

use axum::{
    extract::FromRef,
    routing::{any, post},
    Json, Router,
};
use openhttpa_attestation::{MockVerifier, QuoteVerifier, VerificationResult};
use openhttpa_proto::{AttestQuote, CipherSuite, ProtocolVersion};
use openhttpa_server::{
    handlers::{aths_handler, AtHsHandlerState},
    AtbRegistry, OpenHttpaSession, TrRequestLayer,
};
use openhttpa_tee::mock::MockTeeProvider;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

/// Custom state for our Hub, integrating Handshake and Registry.
#[derive(Clone, FromRef)]
struct HubState {
    hs_state: Arc<AtHsHandlerState>,
    registry: AtbRegistry,
}

/// Request to verify a peer's quote.
#[derive(Deserialize)]
struct VerifyRequest {
    quote: AttestQuote,
    report_data_hex: String,
}

#[derive(Serialize)]
struct VerifyResponse {
    result: VerificationResult,
    hub_assertion: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let registry = AtbRegistry::new();
    let executor = Arc::new(openhttpa_core::handshake::AtHsExecutor::with_config(
        vec![CipherSuite::X25519MlKem768Aes256GcmSha384],
        vec![ProtocolVersion::V2],
        true,
        true,
    ));

    let hs_state = Arc::new(AtHsHandlerState {
        executor,
        registry: registry.clone(),
        tee_provider: Arc::new(MockTeeProvider::default()),
        verifier: Some(Arc::new(MockVerifier::default())),
        atb_ttl: Duration::from_secs(3600),
        challenge_key: [0u8; 32].into(),
        identity_key: None,
    });

    let state = HubState {
        hs_state,
        registry: registry.clone(),
    };
    let verifier_logic = Arc::new(MockVerifier::default());

    let app = Router::new()
        // Phase 1: Attestation Handshake (AtHS)
        // This carries the Hub's quotes and verifies the Client's quotes.
        .route("/attest", any(aths_handler))
        // Phase 2: Trusted Request (TrR)
        // Protected by encryption and authentication.
        .route("/verify", post({
            let verifier = Arc::clone(&verifier_logic);
            move |_session: OpenHttpaSession, Json(req): Json<VerifyRequest>| {
                let verifier = Arc::clone(&verifier);
                async move {
                    let report_data = hex::decode(&req.report_data_hex).expect("invalid hex");
                    let mut rd_array = [0u8; 64];
                    rd_array.copy_from_slice(&report_data);

                    match verifier.verify(&req.quote, &rd_array).await {
                        Ok(res) => Json(VerifyResponse {
                            result: res,
                            hub_assertion: "hub-signed-assertion-hex".to_owned(),
                        }),
                        Err(e) => panic!("Verification failed: {}", e),
                    }
                }
            }
        }))
        .layer(TrRequestLayer::new(registry.clone()))
        .with_state(state);

    println!("`OpenHTTPA` Attestation Hub starting on http://0.0.0.0:3000");
    println!("  - Handshake (AtHS) carries CPU/GPU quotes");
    println!("  - Mutual Attestation required before session establishment");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
