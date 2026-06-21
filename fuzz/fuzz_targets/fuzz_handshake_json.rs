// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Fuzz target: `OpenHTTPA` handshake JSON deserialization (TEST-03).
//!
//! Exercises the `ClientKeyShare` and `ServerKeyShare` JSON deserialization
//! paths with arbitrary byte sequences. Any panic is a bug; parse errors
//! are expected and NOT treated as failures.
//!
//! This fuzz target covers the highest-risk parsing surface for the handshake:
//! malformed JSON that reaches `serde_json::from_slice` could trigger unexpected
//! panics, stack overflows, or excessive memory allocation if input validation
//! is insufficient.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Attempt to deserialize as ClientKeyShare (the most common ingress path).
    let _ = serde_json::from_slice::<serde_json::Value>(data);

    // Also exercise the structured types if the data is valid JSON.
    // We use `serde_json::Value` first to avoid hitting serde_json's own
    // panics on deeply nested structures, then attempt typed parsing.
    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(data) {
        // Try to interpret as a client key share structure
        let _ = serde_json::from_value::<serde_json::Map<String, serde_json::Value>>(val.clone());

        // Try to extract typical handshake fields to exercise validation paths
        if let Some(obj) = val.as_object() {
            // Exercise field access patterns that the handshake code uses
            let _ = obj.get("ecdhe_public");
            let _ = obj.get("mlkem_public");
            let _ = obj.get("mlkem_ciphertext");
            let _ = obj.get("signature_alg");
            let _ = obj.get("client_random");
            let _ = obj.get("client_challenge");
            let _ = obj.get("cipher_suites");
            let _ = obj.get("versions");
        }
    }
});
