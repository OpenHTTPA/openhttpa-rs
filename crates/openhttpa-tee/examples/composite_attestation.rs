// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

use openhttpa_tee::{detect_best_provider, QuoteRequest, TeeConfig, TeeProvider};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Configure the environment to mock a TDX host with an NVIDIA H100 GPU
    std::env::set_var("OPENHTTPA_MOCK_TEE_TYPE", "tdx");

    let config = TeeConfig {
        allow_mock: true,
        preferred_type: None,
    };

    println!("Initializing Composite TEE Environment...");

    // Get TDX provider
    let tdx_provider = detect_best_provider(&config)?;

    // Switch mock type to GPU for the second provider
    std::env::set_var("OPENHTTPA_MOCK_TEE_TYPE", "nvidia_gpu");
    let gpu_provider = detect_best_provider(&config)?;

    // 3. Create a Composite Provider
    let composite =
        openhttpa_tee::provider::CompositeTeeProvider::new(vec![tdx_provider, gpu_provider]);

    // 4. Generate a composite quote
    let request = QuoteRequest {
        report_data: [0x55u8; 64], // Typically SHA-384 of the public key
    };

    println!("Generating Composite Attestation (TDX + H100)...");
    let quotes = composite.generate_quotes(&request)?;

    for (i, quote) in quotes.iter().enumerate() {
        println!("Quote #{} [{}]:", i + 1, quote.quote_type);
        println!("  Raw Length: {} bytes", quote.raw.len());
        println!("  Collateral URIs: {:?}", quote.collateral_uris);
    }

    println!("\nSuccess: Composite attestation generated autonomously.");
    Ok(())
}
