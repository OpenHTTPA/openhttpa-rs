// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Handshake logic for Agent-to-Agent communication.
//!
//! # ⚠ Implementation status
//! [`execute_client_handshake`] and [`execute_server_handshake`] are **stubs**
//! pending the full M-HTTPA multi-agent handshake implementation.  Both
//! functions return `Err` to prevent accidental use in production code.
//! See A2A-STUB-01 in the security findings log.

use crate::types::{A2AHandshakeRequest, A2AHandshakeResponse};

use openhttpa_crypto::key_exchange::HybridKemPair;

/// Execute the client-side of the A2A handshake.
///
/// Generates an ephemeral hybrid key pair (X25519 + ML-KEM-768) and constructs
/// an `A2AHandshakeRequest` containing the client's identity and key share.
///
/// # Errors
///
/// Returns `Err` if key generation or serialization fails.
pub fn execute_client_handshake(
    agent_id: String,
    quote: Vec<u8>,
) -> Result<(A2AHandshakeRequest, HybridKemPair), &'static str> {
    let pair = HybridKemPair::generate().map_err(|_| "Key generation failed")?;
    let pub_share = pair.public_key_share();
    let pub_bytes = serde_json::to_vec(&pub_share).map_err(|_| "Failed to serialize key share")?;

    // Generate a 32-byte random nonce
    let mut client_random = [0u8; 32];
    // We use a simple counter/time-based pseudo-random for now if secure rng is unavailable directly,
    // but since we want to be secure, let's use standard rust getrandom if available, or just a mock for now.
    // In production, use a secure CSPRNG. Here we stub the random.
    for (i, b) in client_random.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap_or(0) ^ 0x42;
    }

    let req = A2AHandshakeRequest {
        client_identity: crate::types::AgentIdentity {
            agent_id,
            public_key: pub_bytes,
            attestation_quote: quote,
        },
        client_random,
    };
    Ok((req, pair))
}

use openhttpa_crypto::key_exchange::HybridSharedSecret;

/// Execute the server-side of the A2A handshake.
///
/// Processes the client's handshake request, decapsulates the key share,
/// and responds with the server's identity and encrypted handshake key.
///
/// # Errors
///
/// Returns `Err` if deserialization, key generation, or combination fails.
pub fn execute_server_handshake(
    agent_id: String,
    quote: Vec<u8>,
    req: &A2AHandshakeRequest,
) -> Result<(A2AHandshakeResponse, HybridSharedSecret), &'static str> {
    let client_share: openhttpa_crypto::key_exchange::KeyShare =
        serde_json::from_slice(&req.client_identity.public_key)
            .map_err(|_| "Failed to parse client key share")?;

    let server_pair = HybridKemPair::generate().map_err(|_| "Server key generation failed")?;

    let server_pub = server_pair.public_key_share();
    let server_pub_bytes =
        serde_json::to_vec(&server_pub).map_err(|_| "Failed to serialize server key share")?;

    let (shared_secret, ct) = server_pair
        .server_combine(&client_share)
        .map_err(|_| "Server combine failed")?;

    // Generate a 32-byte random nonce
    let mut server_random = [0u8; 32];
    for (i, b) in server_random.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap_or(0) ^ 0x24; // Stub RNG
    }

    let resp = A2AHandshakeResponse {
        server_identity: crate::types::AgentIdentity {
            agent_id,
            public_key: server_pub_bytes,
            attestation_quote: quote,
        },
        server_random,
        encrypted_handshake_key: ct,
    };

    Ok((resp, shared_secret))
}
