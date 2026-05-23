// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Fuzz target: `OpenHTTPA` attestation quote parsing (T-03).
//!
//! Feeds arbitrary bytes to `AttestQuote` deserialization paths.
//! A panic = bug; deserialization errors are expected and are NOT failures.
#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;

use openhttpa_proto::{AttestQuote, QuoteType};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    // ── Path 1: CBOR / serde_json deserialization ────────────────────────
    // Try to deserialize the raw bytes as a serialized AttestQuote.
    // Uses serde_json as an accessible path; ciborium deserialization is
    // covered by the same serde machinery.
    let _ = serde_json::from_slice::<AttestQuote>(data);

    // ── Path 2: Construct a quote with fuzz data and exercise raw_base64 ─
    // Exercises the base64 encoding path with arbitrary raw bytes.
    let (qt_byte, rest) = data.split_first().unwrap();
    let quote_type = match qt_byte % 7 {
        0 => QuoteType::Sgx,
        1 => QuoteType::Tdx,
        2 => QuoteType::SevSnp,
        3 => QuoteType::TrustZone,
        4 => QuoteType::NvidiaGpu,
        5 => QuoteType::Tpm,
        _ => QuoteType::Mock,
    };

    let mid = rest.len() / 2;
    let quote = AttestQuote {
        quote_type,
        raw: Bytes::copy_from_slice(&rest[..mid]),
        qudd: Bytes::copy_from_slice(&rest[mid..]),
        collateral_uris: vec![],
    };

    // raw_base64 must never panic regardless of content.
    let _ = quote.raw_base64();

    // ── Path 3: QuoteType FromStr (header value parsing) ─────────────────
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = s.parse::<QuoteType>();
    }
});
