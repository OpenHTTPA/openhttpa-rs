// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use serde::{Deserialize, Serialize};

/// An A2A message envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2AMessage {
    pub sender_id: String,
    pub receiver_id: String,
    pub message_type: String,
    pub payload: serde_json::Value,
    pub timestamp: u64,
}

/// Algorithm tag for an agent public key (INFO-04).
///
/// Carried alongside the raw key bytes so callers can dispatch on the algorithm
/// without having to inspect the byte encoding.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PublicKeyAlgorithm {
    /// P-256 / ECDSA (classical; not recommended for new sessions).
    #[deprecated(note = "P-256 keys have a 128-bit security level; prefer ML-DSA-65 or higher")]
    EcdsaP256,
    /// P-384 / ECDSA.
    EcdsaP384,
    /// ML-DSA-65 (CRYSTALS-Dilithium level 3) — NIST FIPS 204 post-quantum.
    MlDsa65,
    /// ML-DSA-87 (CRYSTALS-Dilithium level 5) — NIST FIPS 204 post-quantum.
    MlDsa87,
    /// X25519 + ML-KEM-768 hybrid key-encapsulation share.
    HybridMlKem768X25519,
    /// Algorithm is not known to this version of the library.
    #[serde(other)]
    #[default]
    Unknown,
}

/// A typed public key carrying both the raw bytes and an algorithm tag (INFO-04).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// Algorithm used to generate or derive this key.
    pub algorithm: PublicKeyAlgorithm,
    /// Raw encoded key bytes.  Encoding depends on `algorithm`
    /// (e.g. uncompressed SEC1 for ECDSA, DER SPKI for ML-DSA, JSON `KeyShare`
    /// for hybrid KEM).
    pub bytes: Vec<u8>,
}

/// Agent identity and attestation info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub agent_id: String,
    /// Typed public key — includes the algorithm tag so callers do not need to
    /// guess encoding from context (INFO-04).
    pub public_key: PublicKey,
    pub attestation_quote: Vec<u8>,
}

/// A2A Handshake Request (Mutual Attestation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2AHandshakeRequest {
    pub client_identity: AgentIdentity,
    /// 32-byte cryptographically random nonce chosen by the client.
    ///
    /// Must **not** be all-zero bytes — use [`A2AHandshakeRequest::has_valid_entropy`]
    /// to validate before processing (INFO-05).
    pub client_random: [u8; 32],
}

impl A2AHandshakeRequest {
    /// Returns `true` if `client_random` passes a basic entropy sanity check.
    ///
    /// An all-zero (or all-same-byte) nonce is a strong indicator of a stub or
    /// broken RNG and MUST be rejected by the server (INFO-05).
    #[must_use]
    pub fn has_valid_entropy(&self) -> bool {
        // Reject if all bytes are identical (covers the all-zeros case).
        let first = self.client_random[0];
        !self.client_random.iter().all(|&b| b == first)
    }
}

/// A2A Handshake Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2AHandshakeResponse {
    pub server_identity: AgentIdentity,
    pub server_random: [u8; 32],
    pub encrypted_handshake_key: Vec<u8>,
}
