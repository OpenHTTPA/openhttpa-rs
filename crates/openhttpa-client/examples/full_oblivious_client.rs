// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! Example demonstrating a fully configured O-HTTPA client.
//!
//! This shows the high-level builder API for configuring an oblivious gateway
//! with HPKE for privacy-preserving attestation.

use openhttpa_client::OpenHttpaClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Simulate server public key (X25519)
    let server_pk = [0xabu8; 32];
    let key_id = 1;
    let gateway_uri = "http://gateway.relay:8080".parse()?;
    let target_uri = "http://enclave.service:8080".parse()?;

    // 2. Build the client with O-HTTPA configured
    let _client = OpenHttpaClient::builder()
        .server_uri(target_uri)
        .oblivious_gateway(gateway_uri, server_pk.to_vec(), key_id)
        .require_preflight(true)
        .build();

    println!("O-HTTPA Client initialized successfully via Builder API.");
    println!("Transport is now wrapped in an ObliviousClient for all handshakes and requests.");

    Ok(())
}
