// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Example: Generating a SPIFFE-augmented hardware quote.

use openhttpa_spiffe::SpiffeTeeProvider;
use openhttpa_tee::{QuoteRequest, TeeProvider, mock::MockTeeProvider};
use std::sync::Arc;

fn main() {
    tracing_subscriber::fmt::init();

    // 1. Initialize the base hardware TEE provider (Mock used here for demonstration)
    let hardware_provider = Arc::new(MockTeeProvider::default());

    // 2. Wrap it in the SpiffeTeeProvider, pointing to the local SPIRE agent socket
    let spiffe_provider =
        SpiffeTeeProvider::new(hardware_provider, "unix:///tmp/spire-agent/public/api.sock");

    // 3. Request a quote (e.g., during an Attestation Handshake)
    let request = QuoteRequest {
        report_data: [0x42; 64], // Simulated transcript hash
    };

    println!("Requesting hardware quote + SPIFFE workload identity...");

    match spiffe_provider.generate_quote(&request) {
        Ok(quote) => {
            println!("Successfully generated quote:");
            println!("  Quote Type: {:?}", quote.quote_type);
            println!("  Quote Length: {} bytes", quote.raw.len());
            println!(
                "  Collateral (SVIDs): {} items",
                quote.collateral_uris.len()
            );
            for uri in &quote.collateral_uris {
                println!("    - {}", uri);
            }
        }
        Err(e) => {
            eprintln!("Failed to generate quote: {:?}", e);
        }
    }
}
