// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

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

#[cfg(test)]
mod tests {
    use super::OpenHttpaClient;
    use super::client::ClientError;

    #[test]
    fn client_error_handshake_display() {
        let e = ClientError::Handshake("handshake failed".to_owned());
        assert!(e.to_string().contains("handshake failed"));
    }

    #[test]
    fn client_error_transport_display() {
        let e = ClientError::Transport("connection refused".to_owned());
        assert!(e.to_string().contains("connection refused"));
    }

    #[test]
    fn client_error_attestation_display() {
        let e = ClientError::Attestation("quote verification failed".to_owned());
        assert!(e.to_string().contains("quote verification failed"));
    }

    #[test]
    fn client_error_not_attested_display() {
        let e = ClientError::NotAttested;
        assert_eq!(e.to_string(), "session not attested");
    }

    #[test]
    fn client_error_serialisation_display() {
        let e = ClientError::Serialisation("unexpected EOF".to_owned());
        assert!(e.to_string().contains("unexpected EOF"));
    }

    #[test]
    fn client_error_key_exchange_display() {
        let e = ClientError::KeyExchange("invalid key size".to_owned());
        assert!(e.to_string().contains("invalid key size"));
    }

    #[test]
    fn client_builder_default_construction() {
        // Verify builder chain constructs without panic.
        let _client = OpenHttpaClient::builder()
            .server_uri("http://127.0.0.1:8080".parse().unwrap())
            .build();
    }

    #[test]
    fn client_strict_attestation_setter() {
        let client = OpenHttpaClient::builder()
            .server_uri("http://127.0.0.1:8080".parse().unwrap())
            .build()
            .strict_attestation(true);
        // If the setter panics, the test fails.
        drop(client);
    }
}
