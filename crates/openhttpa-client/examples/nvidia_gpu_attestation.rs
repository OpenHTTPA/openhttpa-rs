// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Example demonstrating how to use NVIDIA Hopper GPU attestation with `OpenHTTPA`.
//!
//! This example shows a client in a Confidential VM (TDX or SEV-SNP) that also
//! has an NVIDIA H100 GPU. It performs a composite attestation handshake
//! where both the Host TEE and the GPU are verified by the server.

use openhttpa_client::OpenHttpaClient;
use openhttpa_tee::mock::MockTeeProvider;
use openhttpa_tee::nvidia_gpu::NvidiaGpuTeeProvider;
use std::sync::Arc;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("--- `OpenHTTPA` NVIDIA GPU Attestation Example ---");

    // 1. Initialise TEE providers.
    // In a real system, these would use actual hardware-backed providers.
    // Here we use MockTeeProvider (for TDX/SNP simulation) and NvidiaGpuTeeProvider (Hopper simulation).
    let host_tee = Arc::new(MockTeeProvider::default());
    let gpu_tee = Arc::new(NvidiaGpuTeeProvider);

    // 2. Build the client.
    // We add both providers to the builder. The client will automatically
    // create a CompositeTeeProvider to gather quotes from both.
    let _client = OpenHttpaClient::builder()
        .server_uri("http://127.0.0.1:8080".parse()?)
        .add_tee_provider(host_tee)
        .add_tee_provider(gpu_tee)
        // Set strict_attestation to true to ensure all TEEs are verified.
        .strict_attestation(true)
        .build();

    println!("Client initialised with Host TEE + NVIDIA GPU providers.");

    // 3. Perform the handshake.
    // Note: This requires a running server that supports multiple quotes.
    println!("Starting ATTEST handshake...");

    // For this example, we'll just print what would happen since there's no server running.
    println!("(Handshake logic would send Attest-Quotes: [tdx_quote, nvidia_gpu_quote])");

    // 4. (Optional) Configure a verifier if we want to verify the server's identity.
    // We can add the NvidiaGpuVerifier to ensure the server is also running on an NVIDIA GPU.
    // let verifier = NvidiaGpuVerifier::default();

    println!("Example complete.");
    Ok(())
}
