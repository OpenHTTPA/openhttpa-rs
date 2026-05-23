// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! # openhttpa-grpc
//!
//! gRPC integration for `OpenHTTPA` using tonic.
//!
//! Message types are defined here as `prost`-derived structs (matching
//! `proto/openhttpa.proto`).  The tonic service server/client stubs are
//! implemented manually via [`service`].

#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

use prost::Message;

// ─── Shared message: AttestQuote ────────────────────────────────────────────

#[derive(Clone, PartialEq, Eq, Message)]
pub struct GrpcAttestQuote {
    #[prost(string, tag = "1")]
    pub quote_type: ::prost::alloc::string::String,
    #[prost(bytes = "bytes", tag = "2")]
    pub raw: ::prost::bytes::Bytes,
    #[prost(bytes = "bytes", tag = "3")]
    pub qudd: ::prost::bytes::Bytes,
}

// ─── AtHS messages ──────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Eq, Message)]
pub struct AtHsRequest {
    #[prost(bytes = "bytes", tag = "1")]
    pub key_share: ::prost::bytes::Bytes,
    #[prost(bytes = "bytes", tag = "2")]
    pub random: ::prost::bytes::Bytes,
    #[prost(string, repeated, tag = "3")]
    pub cipher_suites: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, repeated, tag = "4")]
    pub versions: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, tag = "5")]
    pub date: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub base_creation: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "7")]
    pub client_quote: ::core::option::Option<GrpcAttestQuote>,
    #[prost(bytes = "bytes", tag = "8")]
    pub challenge: ::prost::bytes::Bytes,
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct AtHsResponse {
    #[prost(string, tag = "1")]
    pub cipher_suite: ::prost::alloc::string::String,
    #[prost(bytes = "bytes", tag = "2")]
    pub random: ::prost::bytes::Bytes,
    #[prost(bytes = "bytes", tag = "3")]
    pub key_share: ::prost::bytes::Bytes,
    #[prost(string, tag = "4")]
    pub base_id: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub version: ::prost::alloc::string::String,
    #[prost(uint64, tag = "6")]
    pub expires_secs: u64,
    #[prost(message, repeated, tag = "7")]
    pub quotes: ::prost::alloc::vec::Vec<GrpcAttestQuote>,
}

// ─── TrR messages ───────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Eq, Message)]
pub struct TrustedRequest {
    #[prost(string, tag = "1")]
    pub base_id: ::prost::alloc::string::String,
    #[prost(bytes = "bytes", tag = "2")]
    pub ciphertext: ::prost::bytes::Bytes,
    #[prost(bytes = "bytes", tag = "3")]
    pub nonce: ::prost::bytes::Bytes,
    #[prost(string, tag = "4")]
    pub termination: ::prost::alloc::string::String,
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct TrustedResponse {
    #[prost(bytes = "bytes", tag = "1")]
    pub ciphertext: ::prost::bytes::Bytes,
    #[prost(bytes = "bytes", tag = "2")]
    pub nonce: ::prost::bytes::Bytes,
}

pub mod service;

pub use service::AttestHandshakeService;
