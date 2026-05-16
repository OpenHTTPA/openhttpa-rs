// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! Fuzz target: `OpenHTTPA` header parsing (T-03).
//!
//! Exercises all `*.decode(map)` entry points with arbitrary byte sequences
//! injected as header values. Panic = bug; invalid-header errors are expected
//! and are NOT treated as failures.
#![no_main]

use http::header::HeaderName;
use http::HeaderMap;
use libfuzzer_sys::fuzz_target;

use openhttpa_headers::attest_headers::{
    AtHsRequestHeaders, AtHsResponseHeaders, PreflightResponseHeaders, TrRequestHeaders,
};
use openhttpa_headers::trailers::{decode_attest_binder, decode_attest_ticket};

/// `OpenHTTPA` header names that carry non-trivial parsing logic.
const HEADERS: &[&str] = &[
    "attest-versions",
    "attest-cipher-suites",
    "attest-base-id",
    "attest-challenge",
    "attest-quote",
    "attest-svn",
    "attest-nonce",
    "attest-session-id",
    "attest-ticket",
    "attest-binder",
];

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Build a HeaderMap where each `OpenHTTPA` header is set to a window of `data`.
    // `HeaderValue::from_bytes` rejects values with control chars — that is fine;
    // we just skip headers whose value is invalid UTF-8/ASCII-safe bytes.
    let mut map = HeaderMap::new();
    let chunk = data.len() / HEADERS.len().max(1);
    for (i, name) in HEADERS.iter().enumerate() {
        let start = (i * chunk).min(data.len());
        let end = ((i + 1) * chunk).min(data.len());
        let slice = &data[start..end];

        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_bytes(slice),
        ) {
            map.insert(hn, hv);
        }
    }

    // Exercise all decode paths — any panic is a bug; Err is expected and OK.
    let _ = AtHsRequestHeaders::decode(&map);
    let _ = AtHsResponseHeaders::decode(&map);
    let _ = TrRequestHeaders::decode(&map);
    let _ = PreflightResponseHeaders::decode(&map);
    let _ = decode_attest_ticket(&map);
    let _ = decode_attest_binder(&map);
});
