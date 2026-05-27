// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! # openhttpa-a2a
//!
//! Agent-to-Agent (A2A) protocol implementation over HTTPA.
//!
//! This crate provides the building blocks for secure, attested communication
//! between autonomous agents running in TEEs.

#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_code)]

pub mod agent;
pub mod handshake;
pub mod router;
pub mod types;

pub use agent::A2AAgent;
pub use router::AgentRouter;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{A2AHandshakeRequest, A2AHandshakeResponse, A2AMessage, AgentIdentity};

    #[test]
    fn test_agent_creation() {
        let agent = A2AAgent::new("test-agent").unwrap();
        assert_eq!(agent.agent_id, "test-agent");
    }

    #[test]
    fn test_handshake_stub() {
        // A2A-STUB-01: both functions now return Err until M-HTTPA is implemented.
        assert!(handshake::execute_client_handshake().is_err());
    }

    // ── new_with_client ──────────────────────────────────────────────────────

    #[test]
    fn test_new_with_client_sets_agent_id() {
        let client = openhttpa_client::OpenHttpaClient::builder()
            .server_uri("http://127.0.0.1:9999".parse().unwrap())
            .build();
        let agent = A2AAgent::new_with_client("my-agent", client);
        assert_eq!(agent.agent_id, "my-agent");
    }

    // ── A2AMessage serde ─────────────────────────────────────────────────────

    #[test]
    fn a2a_message_serde_round_trip() {
        let msg = A2AMessage {
            sender_id: "alice".to_owned(),
            receiver_id: "bob".to_owned(),
            message_type: "task".to_owned(),
            payload: serde_json::json!({ "data": 42 }),
            timestamp: 1_700_000_000,
        };
        let json = serde_json::to_vec(&msg).unwrap();
        let decoded: A2AMessage = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.sender_id, "alice");
        assert_eq!(decoded.receiver_id, "bob");
        assert_eq!(decoded.timestamp, 1_700_000_000);
        assert_eq!(decoded.payload["data"], 42);
    }

    #[test]
    fn a2a_message_clone() {
        let msg = A2AMessage {
            sender_id: "s".to_owned(),
            receiver_id: "r".to_owned(),
            message_type: "t".to_owned(),
            payload: serde_json::Value::Null,
            timestamp: 0,
        };
        let cloned = msg.clone();
        assert_eq!(cloned.sender_id, msg.sender_id);
    }

    // ── AgentIdentity serde ──────────────────────────────────────────────────

    #[test]
    fn agent_identity_serde_round_trip() {
        let id = AgentIdentity {
            agent_id: "agent-001".to_owned(),
            public_key: vec![0x01, 0x02, 0x03],
            attestation_quote: vec![0xde, 0xad],
        };
        let json = serde_json::to_vec(&id).unwrap();
        let decoded: AgentIdentity = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.agent_id, "agent-001");
        assert_eq!(decoded.public_key, vec![0x01, 0x02, 0x03]);
    }

    // ── A2AHandshakeRequest / Response serde ─────────────────────────────────

    #[test]
    fn a2a_handshake_request_serde_round_trip() {
        let req = A2AHandshakeRequest {
            client_identity: AgentIdentity {
                agent_id: "client".to_owned(),
                public_key: vec![],
                attestation_quote: vec![],
            },
            client_random: [0x11u8; 32],
        };
        let json = serde_json::to_vec(&req).unwrap();
        let decoded: A2AHandshakeRequest = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.client_random, [0x11u8; 32]);
    }

    #[test]
    fn a2a_handshake_response_serde_round_trip() {
        let resp = A2AHandshakeResponse {
            server_identity: AgentIdentity {
                agent_id: "server".to_owned(),
                public_key: vec![0xaa],
                attestation_quote: vec![0xbb],
            },
            server_random: [0x22u8; 32],
            encrypted_handshake_key: vec![0x33, 0x44],
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let decoded: A2AHandshakeResponse = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.server_random, [0x22u8; 32]);
        assert_eq!(decoded.encrypted_handshake_key, vec![0x33, 0x44]);
    }

    // ── AgentRouter construction ──────────────────────────────────────────────

    #[test]
    fn agent_router_new_initializes_empty_sessions() {
        let agent = A2AAgent::new("router-agent").unwrap();
        let router = router::AgentRouter::new(agent);
        // Router should start with no sessions
        // We can only verify it constructs without panic
        drop(router);
    }
}
