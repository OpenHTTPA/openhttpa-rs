// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! # openhttpa-grpc
//!
//! gRPC integration for `OpenHTTPA` using tonic.
//!
//! Message types are generated from `proto/openhttpa.proto` via `prost-build`
//! (see `build.rs` — DES-01).  The `service` module provides the concrete
//! [`service::AttestHandshakeService`] implementation using `tonic-build`'s
//! manual service API.

#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

/// prost-generated message types from `proto/openhttpa.proto`.
/// This is the single source of truth for all wire types (DES-01).
pub mod proto {
    // Prost-generated code derives `PartialEq` without `Eq` because proto3
    // fields can include floats. Suppress the lint for generated files only.
    #![allow(clippy::derive_partial_eq_without_eq)]
    // The generated file name matches the proto `package openhttpa`.
    include!(concat!(env!("OUT_DIR"), "/openhttpa.rs"));
}

// Re-export the message types with the flat namespace that the rest of the
// crate (and downstream crates) use directly, preserving compatibility.
pub use proto::{
    AtHsRequest, AtHsResponse, AttestQuote as GrpcAttestQuote, TrustedRequest, TrustedResponse,
};

pub mod service;

pub use service::AttestHandshakeService;
