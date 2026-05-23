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

/// Execute the client-side of the A2A handshake.
///
/// # Errors
///
/// Always returns `Err` — this function is a placeholder.  The full M-HTTPA
/// client handshake (fresh ephemeral KEM + attestation quote) has not yet been
/// implemented.  Do not use in production.
pub const fn execute_client_handshake() -> Result<A2AHandshakeRequest, &'static str> {
    // A2A-STUB-01: Return Err to prevent silent use of zero-crypto values.
    // Replace with real ephemeral KEM + TEE quote when M-HTTPA is implemented.
    Err("A2A client handshake is not yet implemented; do not use in production")
}

/// Execute the server-side of the A2A handshake.
///
/// # Errors
///
/// Always returns `Err` — this function is a placeholder.  The full M-HTTPA
/// server handshake has not yet been implemented.  Do not use in production.
pub fn execute_server_handshake(
    _req: A2AHandshakeRequest,
) -> Result<A2AHandshakeResponse, &'static str> {
    // A2A-STUB-01: Return Err to prevent silent use of zero-crypto values.
    Err("A2A server handshake is not yet implemented; do not use in production")
}
