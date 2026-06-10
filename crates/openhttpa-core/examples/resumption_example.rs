// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Example demonstrating `OpenHTTPA` Session Resumption (Phase 3).
//!
//! This shows how a client can use an `Attest-Ticket` to resume a session
//! without a full hybrid KEM handshake.

use openhttpa_core::state::PskStore;
use openhttpa_proto::{AtbId, CipherSuite, SessionTicket};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Server side: Initialize PskStore
    let store = PskStore::new();

    // 2. Simulate a completed handshake
    let session_id = AtbId::new();
    let psk = [0u8; 32]; // Derived from handshake

    println!("Handshake 1: Complete. Session ID: {}", session_id);

    // Server issues a ticket
    let ticket = SessionTicket {
        ticket: vec![1, 2, 3, 4],
        lifetime: 3600,
        cipher_suite: CipherSuite::X25519MlKem768Aes256GcmSha384,
        rtt0_eligible: true,
    };

    // Server stores the PSK associated with the ticket data
    // In a real flow, the 'ticket' field contains encrypted state
    let stored = store.store_psk(ticket.ticket.clone(), psk.to_vec()).await;
    assert!(stored, "Failed to store PSK — store may be at capacity");
    println!("Server: Issued ticket for resumption");

    // 3. Client side: Reconnect using ticket
    println!("Client: Attempting resumption with ticket...");

    // In a real flow, the client would send the ticket in `Attest-Ticket`
    // Server looks up the PSK (single-use)
    if let Some(resumed_psk) = store.take_psk(&ticket.ticket).await {
        assert_eq!(resumed_psk, psk.to_vec());
        println!("Server: Ticket valid. Session resumed successfully!");
    } else {
        println!("Server: Ticket invalid or expired. Falling back to full handshake.");
    }

    Ok(())
}
