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

/// Agent identity and attestation info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub agent_id: String,
    pub public_key: Vec<u8>,
    pub attestation_quote: Vec<u8>,
}

/// A2A Handshake Request (Mutual Attestation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2AHandshakeRequest {
    pub client_identity: AgentIdentity,
    pub client_random: [u8; 32],
}

/// A2A Handshake Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2AHandshakeResponse {
    pub server_identity: AgentIdentity,
    pub server_random: [u8; 32],
    pub encrypted_handshake_key: Vec<u8>,
}
