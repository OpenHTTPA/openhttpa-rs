// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! # openhttpa-transport
//!
//! Transport adapters for `OpenHTTPA`.
//!
//! * `h2_adapter` — HTTP/2 over TLS (hyper + h2).
//! * `h3_adapter` — HTTP/3 over QUIC (quinn + h3).
//!
//! Each adapter implements the [`AttestTransport`] trait, which allows the
//! higher-level `openhttpa-server` and `openhttpa-client` crates to remain
//! transport-agnostic.

#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_code)]

pub mod connection;

#[cfg(feature = "h2")]
pub mod h2_adapter;

#[cfg(feature = "h3")]
pub mod h3_adapter;

pub mod oblivious;
pub mod reqwest_adapter;

pub use connection::{AttestTransport, SendError, TransportRequest, TransportResponse};
pub use oblivious::ObliviousClient;
