// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! # openhttpa-headers
//!
//! Typed encode/decode support for all `Attest-*` HTTP header fields (AHFs)
//! defined by the `OpenHTTPA` protocol (arXiv:2205.01052, §3).
//!
//! Header values use RFC 9651 Structured Field Values via the `sfv` crate.
//!
//! # Header coverage
//! | Phase       | Header name                    | Direction  |
//! |-------------|--------------------------------|------------|
//! | Preflight   | Access-Control-Request-Method  | req        |
//! | Preflight   | Access-Control-Request-Headers | req        |
//! | Preflight   | Allow                          | resp       |
//! | Preflight   | Access-Control-Allow-Headers   | resp       |
//! | Preflight   | Access-Control-Max-Age         | resp       |
//! | AtHS        | Attest-Cipher-Suites           | req        |
//! | AtHS        | Attest-Supported-Groups        | req        |
//! | AtHS        | Attest-Key-Shares              | req        |
//! | AtHS        | Attest-Random                  | req/resp   |
//! | AtHS        | Attest-Policies                | req        |
//! | AtHS        | Attest-Base-Creation           | req        |
//! | AtHS        | Attest-Blocklist               | req        |
//! | AtHS        | Attest-Versions                | req        |
//! | AtHS        | Attest-Date                    | req        |
//! | AtHS        | Attest-Signatures              | req        |
//! | AtHS        | Attest-Transport               | req/resp   |
//! | AtHS        | Attest-Quotes                  | req/resp   |
//! | AtHS        | Attest-Cipher-Suite            | resp       |
//! | AtHS        | Attest-Key-Share               | resp       |
//! | AtHS        | Attest-Base-ID                 | resp       |
//! | AtHS        | Attest-Version                 | resp       |
//! | AtHS        | Attest-Expires                 | resp       |
//! | AtHS        | Attest-Secrets                 | resp       |
//! | AtHS        | Attest-Cargo                   | resp       |
//! | AtSP+TrR    | Attest-Base-ID                 | req        |
//! | AtSP+TrR    | Attest-Ticket (trailer)        | req        |
//! | AtSP+TrR    | Attest-Binder (trailer)        | resp       |
//! | TrR         | Attest-Base-Termination        | req        |

#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_code)]

pub mod attest_headers;
pub mod method;
pub mod trailers;

pub use attest_headers::*;
pub use method::attest_method;
pub use trailers::*;
