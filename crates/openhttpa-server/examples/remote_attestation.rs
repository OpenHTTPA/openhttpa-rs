// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Example of using remote attestation verifiers (ITA and NVIDIA NRAS).
//!
//! This example shows how to configure a server to use Intel Trust Authority
//! for host attestation and NVIDIA NRAS for GPU attestation.

use std::env;
use std::sync::Arc;
// use openhttpa_server::handlers::AtHsHandlerState;
use openhttpa_attestation::{ItaVerifier, NvidiaRemoteVerifier};
use openhttpa_core::handshake::AtHsExecutor;
use openhttpa_proto::{CipherSuite, ProtocolVersion};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Configure Intel Trust Authority (ITA) Verifier from environment
    let ita_api_key = env::var("OPENHTTPA_ITA_API_KEY")
        .unwrap_or_else(|_| "dummy-ita-key-for-ci-verification".to_owned());
    let ita_endpoint = env::var("OPENHTTPA_ITA_ENDPOINT")
        .unwrap_or_else(|_| "https://portal.trustauthority.intel.com".to_owned());
    let ita_verifier = Arc::new(ItaVerifier::new(ita_api_key, ita_endpoint.clone()));

    // 2. Configure NVIDIA Remote Attestation Service (NRAS) Verifier from environment
    let nras_endpoint = env::var("OPENHTTPA_NRAS_ENDPOINT")
        .unwrap_or_else(|_| "https://nras.nvidia.com/v1".to_owned());
    let nras_verifier = Arc::new(NvidiaRemoteVerifier::new(nras_endpoint.clone()));

    // 3. Create the Handshake Executor
    let _executor = AtHsExecutor::with_config(
        vec![CipherSuite::X25519MlKem768Aes256GcmSha384],
        vec![ProtocolVersion::V2],
        false,
        true,
    );

    println!("`OpenHTTPA` Server configured for Azure/NVIDIA Deployment:");
    println!("  - Intel Host Verifier:  {}", ita_endpoint);
    println!("  - NVIDIA GPU Verifier: {}", nras_endpoint);
    println!("\nReady to accept multi-TEE handshakes.");

    // The handler would then be used in your Axum/Tonic server:
    // let _state = AtHsHandlerState {
    //     executor: Arc::new(_executor),
    //     registry: openhttpa_server::AtbRegistry::new(),
    //     tee_provider: Arc::new(openhttpa_tee::mock::MockTeeProvider::default()),
    //     verifier: Some(ita_verifier), // For simplicity, just ITA or a CompositeVerifier
    //     atb_ttl: std::time::Duration::from_secs(3600),
    //     challenge_key: [0u8; 32],
    // };

    let _ = (ita_verifier, nras_verifier);

    Ok(())
}
