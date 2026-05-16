// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! # openhttpa-client
//!
//! Async client SDK for `OpenHTTPA`.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use openhttpa_client::OpenHttpaClient;
//! use openhttpa_tee::mock::MockTeeProvider;
//! use openhttpa_attestation::MockVerifier;
//!
//! #[tokio::main]
//! async fn main() {
//!     let client = OpenHttpaClient::builder()
//!         .server_uri("https://service.example.com".parse().unwrap())
//!         .tee_provider(std::sync::Arc::new(MockTeeProvider::default()))
//!         .verifier(std::sync::Arc::new(MockVerifier::default()))
//!         .build();
//!
//!     let session = client.attest_handshake().await.unwrap();
//!     let response = client
//!         .trusted_request(&session, "GET", "/api/secret", b"")
//!         .await
//!         .unwrap();
//! }
//! ```

#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_code)]

pub mod builder;
pub mod client;

pub use builder::OpenHttpaClientBuilder;
pub use client::OpenHttpaClient;
