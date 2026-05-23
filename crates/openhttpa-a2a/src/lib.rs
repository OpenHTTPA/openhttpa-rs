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

    #[tokio::test]
    async fn test_agent_creation() {
        let agent = A2AAgent::new("test-agent").unwrap();
        assert_eq!(agent.agent_id, "test-agent");
    }

    #[test]
    fn test_handshake_stub() {
        // A2A-STUB-01: both functions now return Err until M-HTTPA is implemented.
        assert!(handshake::execute_client_handshake().is_err());
    }
}
