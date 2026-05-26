// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Builder for [`OpenHttpaClient`].

use std::sync::Arc;

use http::Uri;

use openhttpa_attestation::verifier::QuoteVerifier;
use openhttpa_tee::{TeeConfig, detect_best_provider, provider::TeeProvider};
use openhttpa_transport::connection::AttestTransport;

use crate::client::OpenHttpaClient;

/// Builder for [`OpenHttpaClient`].  All fields optional; sensible defaults apply.
#[derive(Default)]
pub struct OpenHttpaClientBuilder {
    server_uri: Option<Uri>,
    tee_providers: Vec<Arc<dyn TeeProvider>>,
    verifier: Option<Arc<dyn QuoteVerifier>>,
    transport: Option<Arc<dyn AttestTransport>>,
    tee_config: Option<TeeConfig>,
    strict_attestation: bool,
    require_preflight: bool,
    oblivious_config: Option<ObliviousConfig>,
    server_identity_pub: Option<Vec<u8>>,
    /// Maximum bytes to buffer for a non-streaming response body.
    /// Defaults to [`DEFAULT_MAX_RESPONSE_SIZE`].
    max_response_size: Option<usize>,
}

/// Default maximum response size for non-streaming trusted requests (16 MiB).
/// Override with [`OpenHttpaClientBuilder::max_response_size`].
pub const DEFAULT_MAX_RESPONSE_SIZE: usize = 16 * 1024 * 1024;

/// Configuration for Oblivious `OpenHTTPA` (O-HTTPA).
///
/// Enables HPKE-encapsulation of all requests through an oblivious gateway,
/// so the gateway cannot correlate requests to clients.
#[derive(Clone, Debug)]
pub struct ObliviousConfig {
    /// URI of the oblivious gateway/relay.
    pub gateway_uri: Uri,
    /// Raw X25519 public key of the target TEE server for HPKE encapsulation,
    /// encoded as 32 raw bytes (RFC 9180 §5.1 encapsulation key format).
    ///
    /// # Key format
    ///
    /// This MUST be the server's Diffie-Hellman public key in the X25519
    /// representation: 32 bytes in the format described by RFC 7748 §6.1
    /// (little-endian Montgomery-form u-coordinate). This is the format
    /// produced by `x25519_dalek::PublicKey::to_bytes()` and
    /// `openssl pkey -outform DER -pubout | tail -c 32`.
    ///
    /// Do NOT use SPKI DER or any other wrapped format here.
    pub server_public_key: Vec<u8>,
    /// Key ID for the HPKE public key (for server-side key rotation).
    pub key_id: u8,
}

impl OpenHttpaClientBuilder {
    #[must_use]
    pub fn server_uri(mut self, uri: Uri) -> Self {
        self.server_uri = Some(uri);
        self
    }

    #[must_use]
    pub fn tee_provider(mut self, p: Arc<dyn TeeProvider>) -> Self {
        self.tee_providers = vec![p];
        self
    }

    #[must_use]
    pub fn add_tee_provider(mut self, p: Arc<dyn TeeProvider>) -> Self {
        self.tee_providers.push(p);
        self
    }

    #[must_use]
    pub fn tee_config(mut self, config: TeeConfig) -> Self {
        self.tee_config = Some(config);
        self
    }

    #[must_use]
    pub fn verifier(mut self, v: Arc<dyn QuoteVerifier>) -> Self {
        self.verifier = Some(v);
        self
    }

    #[must_use]
    pub fn transport(mut self, t: Arc<dyn AttestTransport>) -> Self {
        self.transport = Some(t);
        self
    }

    #[must_use]
    pub const fn strict_attestation(mut self, s: bool) -> Self {
        self.strict_attestation = s;
        self
    }

    #[must_use]
    pub const fn require_preflight(mut self, r: bool) -> Self {
        self.require_preflight = r;
        self
    }

    /// Configure the client to use an Oblivious Gateway (O-HTTPA).
    ///
    /// When configured, all requests will be encapsulated using HPKE and sent to the
    /// specified gateway instead of directly to the target server.
    #[must_use]
    pub fn oblivious_gateway(
        mut self,
        gateway_uri: Uri,
        server_public_key: Vec<u8>,
        key_id: u8,
    ) -> Self {
        self.oblivious_config = Some(ObliviousConfig {
            gateway_uri,
            server_public_key,
            key_id,
        });
        self
    }

    /// Pin a server ML-DSA public key for post-quantum signature verification.
    #[must_use]
    pub fn server_identity_pub(mut self, pk: Vec<u8>) -> Self {
        self.server_identity_pub = Some(pk);
        self
    }

    /// Override the maximum response body size for non-streaming trusted requests.
    ///
    /// The default is [`DEFAULT_MAX_RESPONSE_SIZE`] (16 MiB).  Set a smaller
    /// value for latency-sensitive APIs or a larger value for bulk-data
    /// endpoints.  For arbitrarily large responses use
    /// [`OpenHttpaClient::trusted_request_streaming`] instead.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` is zero.
    #[must_use]
    pub fn max_response_size(mut self, bytes: usize) -> Self {
        assert!(bytes > 0, "max_response_size must be > 0");
        self.max_response_size = Some(bytes);
        self
    }

    /// Build the client.
    ///
    /// # Panics
    ///
    /// Panics if `server_uri` was not set.
    #[must_use]
    pub fn build(self) -> OpenHttpaClient {
        let uri = self.server_uri.expect("server_uri is required");

        let tee_provider: Arc<dyn TeeProvider> = if self.tee_providers.is_empty() {
            let config = self.tee_config.unwrap_or_default();
            detect_best_provider(&config)
                .expect("Failed to detect a valid TEE provider (check hardware or enable mock)")
        } else if self.tee_providers.len() == 1 {
            self.tee_providers[0].clone()
        } else {
            Arc::new(openhttpa_tee::provider::CompositeTeeProvider::new(
                self.tee_providers,
            ))
        };

        let verifier: Arc<dyn QuoteVerifier> = self
            .verifier
            .unwrap_or_else(|| Arc::new(openhttpa_attestation::MockVerifier::default()));

        let transport = self.transport.unwrap_or_else(|| {
            Arc::new(openhttpa_transport::reqwest_adapter::ReqwestTransport::new())
        });

        // Wrap in ObliviousClient if configured.
        let transport: Arc<dyn AttestTransport> = if let Some(conf) = self.oblivious_config {
            Arc::new(openhttpa_transport::oblivious::ObliviousClient::new(
                transport,
                conf.server_public_key,
                conf.key_id,
            ))
        } else {
            transport
        };

        OpenHttpaClient::new(
            uri,
            tee_provider,
            verifier,
            Some(transport),
            self.strict_attestation,
            self.require_preflight,
            self.server_identity_pub,
            self.max_response_size.unwrap_or(DEFAULT_MAX_RESPONSE_SIZE),
        )
    }
}
