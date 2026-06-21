// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Fuzz target: AEAD decryption with malformed ciphertexts (TEST-03).
//!
//! Exercises the AEAD decryption path with arbitrary ciphertext and AAD
//! data. Any panic is a bug; decryption failures (tag mismatch, etc.)
//! are expected and NOT treated as failures.
//!
//! This covers the second-highest-risk parsing surface: malformed
//! ciphertexts that reach the AEAD `open_in_place` code path could
//! trigger panic-based DoS if bounds checking is insufficient.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Need at least 44 bytes: 32 (key) + 12 (nonce) = 44
    if data.len() < 44 {
        return;
    }

    let key_bytes: [u8; 32] = data[..32].try_into().unwrap();
    let nonce_bytes: [u8; 12] = data[32..44].try_into().unwrap();
    let remaining = &data[44..];

    // Split remaining into ciphertext and AAD (half each, minimum 1 byte ciphertext)
    if remaining.is_empty() {
        return;
    }
    let split = remaining.len() / 2;
    let ciphertext = &remaining[..split.max(1)];
    let aad = &remaining[split.max(1)..];

    // Try AES-256-GCM decryption — must not panic on any input
    use aws_lc_rs::aead;
    let unbound_key = match aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes) {
        Ok(k) => k,
        Err(_) => return,
    };
    let nonce = match aead::Nonce::try_assume_unique_for_key(&nonce_bytes) {
        Ok(n) => n,
        Err(_) => return,
    };
    let opening_key = aead::LessSafeKey::new(unbound_key);
    let mut ct = ciphertext.to_vec();
    // open_in_place must never panic, only return Err on bad data
    let _ = opening_key.open_in_place(nonce, aead::Aad::from(aad), &mut ct);
});
