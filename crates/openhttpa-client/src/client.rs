// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! [`OpenHttpaClient`] — the high-level async client.

use std::sync::Arc;

use http::Uri;
use thiserror::Error;
use tracing::instrument;

use hmac::{Hmac, KeyInit, Mac};
use openhttpa_attestation::verifier::QuoteVerifier;
use openhttpa_core::handshake::ClientKeyShare;
use openhttpa_core::session::AttestSession;
use openhttpa_crypto::aead::{AeadAlgorithm, AeadNonce, BoundAeadKey};
use openhttpa_crypto::key_exchange::HybridKemPair;
use openhttpa_headers::{HDR_ATTEST_BASE_ID, HDR_ATTEST_TICKET};
use openhttpa_proto::{CipherSuite, ProtocolVersion};
use openhttpa_tee::{QuoteRequest, provider::TeeProvider};
use openhttpa_transport::connection::{AttestTransport, TransportRequest};
use sha2::{Digest, Sha384};

type HmacSha384 = Hmac<Sha384>;

use crate::builder::OpenHttpaClientBuilder;

/// Returns the authority component of `uri` with the default port stripped,
/// matching what an HTTP client library sends in the `Host` header (RFC 7230 §5.4).
///
/// Both client (MAC computation) and server (MAC verification via `Host` header)
/// must agree on the authority string.  Default ports must be omitted so that
/// URIs with explicit default ports (`https://host:443`) yield the same string
/// as those without (`https://host`).
fn ahl_authority(uri: &http::Uri) -> &str {
    let auth = match uri.authority() {
        Some(a) => a.as_str(),
        None => return "",
    };
    let default_port = match uri.scheme_str() {
        Some("https") => "443",
        Some("http") => "80",
        _ => return auth,
    };
    if let Some((host, port)) = auth.rsplit_once(':')
        && port == default_port
    {
        return host;
    }
    auth
}

/// Errors from the `OpenHTTPA` client.
// MED-06: non_exhaustive prevents breaking changes when new variants are added.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("handshake error: {0}")]
    Handshake(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("attestation verification failed: {0}")]
    Attestation(String),
    #[error("session not attested")]
    NotAttested,
    #[error("serialisation error: {0}")]
    Serialisation(String),
    #[error("key exchange error: {0}")]
    KeyExchange(String),
}

/// The `OpenHTTPA` async client.
///
/// # Security defaults
///
/// - `strict_attestation` defaults to `false` (development mode). **Set to
///   `true` in production** to reject sessions with no server attestation quotes.
/// - `max_response_size` defaults to [`crate::builder::DEFAULT_MAX_RESPONSE_SIZE`] (16 MiB).
///   Increase only for known bulk-data endpoints.
#[allow(dead_code)]
#[derive(Clone)]
pub struct OpenHttpaClient {
    server_uri: Uri,
    tee_provider: Arc<dyn TeeProvider>,
    verifier: Arc<dyn QuoteVerifier>,
    transport: Option<Arc<dyn AttestTransport>>,
    strict_attestation: bool,
    require_preflight: bool,
    server_identity_pub: Option<Vec<u8>>,
    /// Maximum bytes to buffer for non-streaming response bodies.
    max_response_size: usize,
}

impl OpenHttpaClient {
    pub(crate) fn new(
        server_uri: Uri,
        tee_provider: Arc<dyn TeeProvider>,
        verifier: Arc<dyn QuoteVerifier>,
        transport: Option<Arc<dyn AttestTransport>>,
        strict_attestation: bool,
        require_preflight: bool,
        server_identity_pub: Option<Vec<u8>>,
        max_response_size: usize,
    ) -> Self {
        Self {
            server_uri,
            tee_provider,
            verifier,
            transport,
            strict_attestation,
            require_preflight,
            server_identity_pub,
            max_response_size,
        }
    }

    /// Set attestation strictness.
    #[must_use]
    pub const fn strict_attestation(mut self, s: bool) -> Self {
        self.strict_attestation = s;
        self
    }

    /// Entry point for creating a builder.
    #[must_use]
    pub fn builder() -> OpenHttpaClientBuilder {
        OpenHttpaClientBuilder::default()
    }

    /// Perform the `AtHS` handshake and return a live [`AttestSession`].
    ///
    /// The client:
    /// 1. Generates a hybrid KEM key pair.
    /// 2. (Optionally) generates a TEE quote over the public key share.
    /// 3. Sends the `ATTEST` request with all `Attest-*` headers.
    /// 4. Receives the server's key share + quotes.
    /// 5. (Optionally) verifies the server's quote.
    /// 6. Derives session key material via HKDF.
    ///
    /// # Errors
    ///
    /// Returns [`Err`](`ClientError`) if key generation, the handshake, or
    /// session key derivation fails.
    ///
    /// # Panics
    ///
    /// Panics if internal cryptographic state is corrupted.
    #[instrument(skip_all, name = "client.attest_handshake")]
    pub async fn attest_handshake(&self) -> Result<AttestSession, ClientError> {
        // 1. Optional: Preflight to get fresh server challenge.
        let challenge = if self.require_preflight {
            Some(self.perform_preflight().await?)
        } else {
            None
        };

        // 2. Generate client parameters.
        let client_kem =
            HybridKemPair::generate().map_err(|e| ClientError::Handshake(e.to_string()))?;
        let client_pub_share = client_kem.public_key_share();

        // O-03: Unified entropy generation via aws-lc-rs SystemRandom.
        let mut client_random = [0u8; 32];
        let rng = openhttpa_crypto::rand::SystemRandom::new();
        openhttpa_crypto::rand::SecureRandom::fill(&rng, &mut client_random)
            .map_err(|_| ClientError::Handshake("RNG failure".to_owned()))?;

        let client_share = ClientKeyShare {
            ecdhe_public: client_pub_share.ecdhe_public,
            mlkem_public: client_pub_share.mlkem_public,
            signature_alg: Some(openhttpa_core::handshake::SIG_ALG_ML_DSA_65),
        };
        let client_share_bytes = serde_json::to_vec(&client_share)
            .map_err(|e| ClientError::Serialisation(e.to_string()))?;

        // 3. Optional: generate client quotes (M-HTTPA).
        let client_quotes =
            self.generate_client_quote(&client_random, &client_share, challenge.as_deref())?;

        // 4. Send ATTEST request and get response.
        let response = self
            .send_attest_request(
                &client_random,
                &client_share_bytes,
                client_quotes,
                challenge.clone(),
            )
            .await?;

        if !response.status.is_success() {
            let err_body = openhttpa_transport::connection::to_bytes(response.body, 4096)
                .await
                .unwrap_or_default();
            return Err(ClientError::Handshake(format!(
                "server returned error {}: {}",
                response.status,
                String::from_utf8_lossy(&err_body)
            )));
        }

        // 4. Decode response and extract server parameters.
        let resp_hdrs =
            openhttpa_headers::attest_headers::AtHsResponseHeaders::decode(&response.headers)
                .map_err(|e| ClientError::Handshake(format!("invalid response headers: {e}")))?;

        let server_share: openhttpa_core::handshake::ServerKeyShare =
            serde_json::from_slice(&resp_hdrs.key_share_json)
                .map_err(|e| ClientError::Handshake(format!("invalid server key share: {e}")))?;

        let mut server_random = [0u8; 32];
        if resp_hdrs.random.len() >= 32 {
            server_random.copy_from_slice(&resp_hdrs.random[..32]);
        }

        // 5. Compute transcript hash (M-01).
        // Must match AtHsExecutor::execute_server: canonical length-prefixed fields.
        let mut hasher = sha2::Sha384::new();

        // 1. Client Random
        hasher.update((client_random.len() as u64).to_be_bytes());
        hasher.update(client_random);

        // 2. Client Challenge (Hardened: 48 bytes to match server)
        let mut challenge_bytes = [0u8; 48];
        if let Some(c) = challenge.as_deref() {
            let len = c.len().min(48);
            challenge_bytes[..len].copy_from_slice(&c[..len]);
        }
        hasher.update((challenge_bytes.len() as u64).to_be_bytes());
        hasher.update(challenge_bytes);

        // 3. Client Key Share (ECDHE)
        hasher.update((client_share.ecdhe_public.len() as u64).to_be_bytes());
        hasher.update(&client_share.ecdhe_public);

        // 4. Client Key Share (ML-KEM)
        hasher.update((client_share.mlkem_public.len() as u64).to_be_bytes());
        hasher.update(&client_share.mlkem_public);

        // 5. Server Random
        hasher.update((server_random.len() as u64).to_be_bytes());
        hasher.update(server_random);

        // 6. Server Key Share (ECDHE)
        hasher.update((server_share.ecdhe_public.len() as u64).to_be_bytes());
        hasher.update(&server_share.ecdhe_public);

        // 7. Server Key Share (ML-KEM CT)
        hasher.update((server_share.mlkem_ciphertext.len() as u64).to_be_bytes());
        hasher.update(&server_share.mlkem_ciphertext);

        // 8. Server Key Share (ML-KEM Public)
        hasher.update((server_share.mlkem_public.len() as u64).to_be_bytes());
        hasher.update(&server_share.mlkem_public);

        // 9. Negotiated Cipher Suite (2 bytes)
        hasher.update(resp_hdrs.cipher_suite.numeric_id().to_be_bytes());

        // 10. Negotiated Protocol Version (1 byte)
        hasher.update([resp_hdrs.version.numeric_id()]);

        let transcript_hash = hasher.finalize().to_vec();

        // 5.5 Verify ML-DSA PQC Signature if server_identity_pub is pinned.
        self.verify_pqc_server_sig(&resp_hdrs, &transcript_hash)?;

        // 6. Verify server quotes.
        let attestation_result = self
            .verify_server_quotes(&resp_hdrs, &transcript_hash)
            .await?;

        // 7. Combine KEM shares and derive session keys.
        let server_key_share = openhttpa_crypto::key_exchange::KeyShare {
            ecdhe_public: server_share.ecdhe_public,
            mlkem_public: vec![],
        };
        let hybrid_ss = client_kem
            .client_combine(&server_key_share, &server_share.mlkem_ciphertext)
            .map_err(|e| ClientError::KeyExchange(e.to_string()))?;

        let session_keys =
            openhttpa_core::handshake::SessionKeys::derive(hybrid_ss.as_bytes(), &transcript_hash)
                .map_err(|e| ClientError::Handshake(format!("key derivation failed: {e}")))?;

        Ok(AttestSession::new(
            resp_hdrs.base_id,
            CipherSuite::X25519MlKem768Aes256GcmSha384,
            ProtocolVersion::V2,
            session_keys,
            std::time::Instant::now() + std::time::Duration::from_secs(resp_hdrs.expires_secs),
            openhttpa_core::ReplayStrategy::default(),
            attestation_result,
        ))
    }

    /// Verify the server's ML-DSA signature over the handshake transcript if
    /// a pinned identity key is configured.
    ///
    /// # Errors
    /// Returns [`ClientError::Attestation`] if the key is pinned but no
    /// signature was supplied, or if the signature fails verification.
    fn verify_pqc_server_sig(
        &self,
        resp_hdrs: &openhttpa_headers::attest_headers::AtHsResponseHeaders,
        transcript_hash: &[u8],
    ) -> Result<(), ClientError> {
        let Some(ref pub_key_bytes) = self.server_identity_pub else {
            return Ok(());
        };
        if resp_hdrs.server_signatures.is_empty() {
            return Err(ClientError::Attestation(
                "server did not provide PQC signature but identity key is pinned".to_string(),
            ));
        }
        let sig = &resp_hdrs.server_signatures[0];
        openhttpa_crypto::pqc::MlDsaKeyPair::verify(pub_key_bytes, transcript_hash, sig).map_err(
            |e| ClientError::Attestation(format!("PQC signature verification failed: {e}")),
        )
    }

    /// Perform a preflight `OPTIONS` request to obtain a fresh challenge from the server.
    #[instrument(skip(self), name = "client.preflight")]
    async fn perform_preflight(&self) -> Result<Vec<u8>, ClientError> {
        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| ClientError::Transport("No transport".to_string()))?;

        let uri = format!(
            "{}/attest",
            self.server_uri.to_string().trim_end_matches('/')
        )
        .parse()
        .unwrap();

        let req = TransportRequest {
            method: http::Method::OPTIONS,
            uri,
            headers: http::HeaderMap::new(),
            body: openhttpa_transport::connection::empty_body(),
            trailers: None,
        };

        let resp = transport
            .send(req)
            .await
            .map_err(|e| ClientError::Handshake(format!("preflight failed: {e}")))?;

        if !resp.status.is_success() {
            return Err(ClientError::Handshake(format!(
                "preflight returned error {}",
                resp.status
            )));
        }

        let _resp_bytes = openhttpa_transport::connection::to_bytes(resp.body, 1024 * 1024)
            .await
            .map_err(|e| ClientError::Handshake(format!("preflight body error: {e}")))?;

        let preflight_hdrs =
            openhttpa_headers::attest_headers::PreflightResponseHeaders::decode(&resp.headers)
                .map_err(|e| ClientError::Handshake(format!("invalid preflight headers: {e}")))?;

        Ok(preflight_hdrs.challenge)
    }

    fn generate_client_quote(
        &self,
        client_random: &[u8; 32],
        client_share: &ClientKeyShare,
        challenge: Option<&[u8]>,
    ) -> Result<Vec<openhttpa_proto::AttestQuote>, ClientError> {
        let mut hasher = sha2::Sha384::new();

        // 1. Client Random
        hasher.update((client_random.len() as u64).to_be_bytes());
        hasher.update(client_random);

        // 2. Client Challenge (Hardened: 48 bytes to match server)
        let mut challenge_bytes = [0u8; 48];
        if let Some(c) = challenge {
            let len = c.len().min(48);
            challenge_bytes[..len].copy_from_slice(&c[..len]);
        }
        hasher.update((challenge_bytes.len() as u64).to_be_bytes());
        hasher.update(challenge_bytes);

        // 3. Client Key Share (ECDHE)
        hasher.update((client_share.ecdhe_public.len() as u64).to_be_bytes());
        hasher.update(&client_share.ecdhe_public);

        // 4. Client Key Share (ML-KEM)
        hasher.update((client_share.mlkem_public.len() as u64).to_be_bytes());
        hasher.update(&client_share.mlkem_public);

        let client_binding = hasher.finalize().to_vec();
        let mut report_data = [0u8; 64];
        // T-10 Hardening: Prepend "openhttpa hs client" prefix.
        let prefix = b"openhttpa hs client";
        let plen = prefix.len().min(32);
        report_data[..plen].copy_from_slice(&prefix[..plen]);
        let len = client_binding.len().min(48);
        report_data[32..32 + len.min(32)].copy_from_slice(&client_binding[..len.min(32)]);

        match self
            .tee_provider
            .generate_quotes(&QuoteRequest { report_data })
        {
            Ok(qs) => Ok(qs),
            Err(e) if self.strict_attestation => Err(ClientError::Attestation(e.to_string())),
            Err(_) => Ok(vec![]),
        }
    }

    async fn send_attest_request(
        &self,
        client_random: &[u8; 32],
        client_share_bytes: &[u8],
        client_quotes: Vec<openhttpa_proto::AttestQuote>,
        challenge: Option<Vec<u8>>,
    ) -> Result<openhttpa_transport::connection::TransportResponse, ClientError> {
        let req_headers = openhttpa_headers::attest_headers::AtHsRequestHeaders {
            cipher_suites: vec![CipherSuite::X25519MlKem768Aes256GcmSha384],
            random: client_random.to_vec(),
            versions: vec![ProtocolVersion::V2],
            key_shares_json: client_share_bytes.to_vec(),
            date: chrono::Utc::now().to_rfc3339(),
            base_creation: openhttpa_proto::AtbCreation::New,
            direct_attestation: true,
            allow_untrusted_requests: false,
            client_quotes,
            challenge,
            signatures: vec![],
            ticket: None,
            provenance: None,
            encrypted_hello: None,
        };

        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| ClientError::Transport("No transport".to_string()))?;

        let uri = format!(
            "{}/attest",
            self.server_uri.to_string().trim_end_matches('/')
        )
        .parse()
        .unwrap();

        let req = openhttpa_transport::connection::TransportRequest {
            method: http::Method::from_bytes(b"ATTEST").unwrap(),
            uri,
            headers: req_headers.encode(),
            body: openhttpa_transport::connection::empty_body(),
            trailers: None,
        };

        transport
            .send(req)
            .await
            .map_err(|e| ClientError::Handshake(e.to_string()))
    }

    async fn verify_server_quotes(
        &self,
        resp_hdrs: &openhttpa_headers::attest_headers::AtHsResponseHeaders,
        transcript_hash: &[u8],
    ) -> Result<Option<openhttpa_proto::VerificationResult>, ClientError> {
        let mut composite_result: Option<openhttpa_proto::VerificationResult> = None;
        if resp_hdrs.quotes.is_empty() {
            if self.strict_attestation {
                return Err(ClientError::Attestation(
                    "server attestation required but missing".to_owned(),
                ));
            }
        } else {
            for quote in &resp_hdrs.quotes {
                let mut report_data = [0u8; 64];
                // T-10 Hardening: Prepend "openhttpa hs server" prefix.
                let prefix = b"openhttpa hs server";
                let plen = prefix.len().min(32);
                report_data[..plen].copy_from_slice(&prefix[..plen]);
                let len = transcript_hash.len().min(48);
                report_data[32..32 + len.min(32)].copy_from_slice(&transcript_hash[..len.min(32)]);

                let res = self
                    .verifier
                    .verify(quote, &report_data)
                    .await
                    .map_err(|e| ClientError::Attestation(e.to_string()))?;

                if let Some(ref mut primary) = composite_result {
                    primary.secondary.push(res);
                } else {
                    composite_result = Some(res);
                }
            }
        }
        Ok(composite_result)
    }

    /// Send a trusted request on an attested session.
    ///
    /// AEAD-encrypts the body with the session's `client_write_key` and sends
    /// the `Attest-Base-ID` and `Attest-Ticket` headers.
    ///
    /// # Errors
    /// Returns [`Err`] if encryption, transmission, or decryption fails.
    ///
    /// # Panics
    /// Panics if nonce counter overflows (extremely unlikely).
    #[instrument(skip(self, session, body))]
    pub async fn trusted_request(
        &self,
        session: &AttestSession,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        self.trusted_request_ext(session, method, path, body, None)
            .await
    }

    /// Send a trusted request on an attested session with streaming body.
    ///
    /// Encrypts each chunk of the input stream and returns a stream of encrypted tokens.
    /// Implements Binary Framing: `[Length (4b)] || [Counter (8b)] || [Ciphertext]`.
    ///
    /// # Errors
    /// Returns [`Err`] if encryption or transmission fails.
    #[allow(clippy::too_many_lines, clippy::missing_panics_doc)]
    #[instrument(skip(self, session, body_stream))]
    pub async fn trusted_request_streaming(
        &self,
        session: &AttestSession,
        method: &str,
        path: &str,
        body_stream: openhttpa_transport::connection::TransportBody,
    ) -> Result<openhttpa_transport::connection::TransportBody, ClientError> {
        if !session.is_alive() {
            return Err(ClientError::NotAttested);
        }

        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| ClientError::Transport("No transport configured".to_string()))?;
        let base_id = session.state().id;

        let mut base_uri_str = self.server_uri.to_string();
        if base_uri_str.ends_with('/') && path.starts_with('/') {
            base_uri_str.pop();
        }
        let full_uri_str = format!("{base_uri_str}{path}");
        let full_uri: http::Uri = full_uri_str.parse().map_err(|e| {
            ClientError::Handshake(format!("Invalid request URI '{full_uri_str}': {e}"))
        })?;
        let final_path = full_uri.path();

        // 1. Initial AAD and Headers
        let mut aad = b"openhttpa:".to_vec();
        aad.extend_from_slice(base_id.to_string().as_bytes());

        // We use a dummy seal to get the headers and initial MAC
        let (headers, _, _) = Self::seal_request_body(
            session,
            method,
            final_path,
            full_uri.query(),
            ahl_authority(&full_uri),
            b"", // Empty initial body for header binding
            &aad,
            None,
        )?;

        let mut headers = headers;
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/x-openhttpa-stream"),
        );

        // 2. Wrap body stream in encryption
        use futures::StreamExt;
        use http_body_util::BodyExt;
        let session = session.clone();
        let current_aad = aad.clone();

        let encrypted_stream = body_stream.into_data_stream().scan(
            (session.clone(), current_aad, [0u8; 48]),
            |(session, current_aad, cumulative_hash), chunk_res| {
                let chunk = match chunk_res {
                    Ok(c) => c,
                    Err(e) => return futures::future::ready(Some(Err(std::io::Error::other(e)))),
                };

                // O-03: Unified nonce generation via aws-lc-rs SystemRandom.
                let mut nonce_bytes = [0u8; 8];
                let rng = openhttpa_crypto::rand::SystemRandom::new();
                if openhttpa_crypto::rand::SecureRandom::fill(&rng, &mut nonce_bytes).is_err() {
                    return futures::future::ready(Some(Err(std::io::Error::other("RNG failure"))));
                }
                let nonce = u64::from_be_bytes(nonce_bytes);

                let res = session.with_keys_for_trr(nonce, |keys, counter| {
                    let mut nonce_bytes = [0u8; 12];
                    nonce_bytes.copy_from_slice(&keys.client_write_iv);
                    let count_bytes = counter.to_be_bytes();
                    for (i, b) in count_bytes.iter().enumerate() {
                        nonce_bytes[4 + i] ^= b;
                    }
                    let aead_nonce = openhttpa_crypto::aead::AeadNonce::from_slice(&nonce_bytes)
                        .map_err(|_| {
                            ClientError::Handshake("nonce length invariant violated".to_owned())
                        })?;

                    let key = openhttpa_crypto::aead::AeadKey::new(
                        openhttpa_crypto::aead::AeadAlgorithm::Aes256Gcm,
                        &keys.client_write_key,
                    )
                    .map_err(|e| ClientError::Handshake(e.to_string()))?;

                    let mut chunk_aad = current_aad.clone();
                    chunk_aad.extend_from_slice(cumulative_hash);

                    let mut data = chunk.to_vec();
                    key.seal_in_place(&aead_nonce, &chunk_aad, &mut data)
                        .map_err(|e| ClientError::Handshake(format!("Stream enc fail: {e:?}")))?;

                    // Update cumulative hash
                    let mut hasher = Sha384::new();
                    hasher.update(*cumulative_hash);
                    hasher.update(&data);
                    *cumulative_hash = hasher.finalize().into();

                    let mut frame = Vec::with_capacity(4 + 8 + data.len());
                    frame.extend_from_slice(
                        &u32::try_from(data.len())
                            .expect("frame too large")
                            .to_be_bytes(),
                    );
                    frame.extend_from_slice(&counter.to_be_bytes());
                    frame.extend_from_slice(&data);

                    Ok::<Vec<u8>, ClientError>(frame)
                });

                match res {
                    Ok(Ok(v)) => futures::future::ready(Some(Ok(bytes::Bytes::from(v)))),
                    Ok(Err(e)) => futures::future::ready(Some(Err(std::io::Error::other(e)))),
                    Err(e) => {
                        futures::future::ready(Some(Err(std::io::Error::other(e.to_string()))))
                    }
                }
            },
        );

        let req = TransportRequest {
            method: http::Method::from_bytes(method.as_bytes()).map_err(|e| {
                ClientError::Transport(format!("invalid HTTP method '{method}': {e}"))
            })?,
            uri: full_uri,
            headers,
            body: openhttpa_transport::connection::full_body_from_stream(encrypted_stream),
            trailers: None,
        };

        let resp = transport
            .send(req)
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;

        if !resp.status.is_success() {
            return Err(ClientError::Transport(format!(
                "Server returned error: {}",
                resp.status
            )));
        }

        // 3. Decapsulate Response stream
        let session = session.clone();
        let resp_cumulative_hash = [0u8; 48];
        let reader = StreamFrameReader::new(resp.body.into_data_stream());

        let decrypted_stream = futures::stream::unfold(
            (reader, session, aad, resp_cumulative_hash),
            |(mut reader, session, aad, prev_hash)| async move {
                let frame = match reader.next_frame().await {
                    Ok(Some(f)) => f,
                    Ok(None) => return None,
                    Err(e) => return Some((Err(e), (reader, session, aad, prev_hash))),
                };

                let res = session.with_keys_for_trs(|keys, _counter| {
                    let mut nonce_bytes = [0u8; 12];
                    nonce_bytes.copy_from_slice(&keys.server_write_iv);
                    let count_bytes = frame.counter.to_be_bytes();
                    for (i, b) in count_bytes.iter().enumerate() {
                        nonce_bytes[4 + i] ^= b;
                    }
                    let aead_nonce = AeadNonce::from_slice(&nonce_bytes).map_err(|_| {
                        ClientError::Handshake("nonce length invariant violated".to_owned())
                    })?;

                    let key = openhttpa_crypto::aead::AeadKey::new(
                        AeadAlgorithm::Aes256Gcm,
                        &keys.server_write_key,
                    )
                    .map_err(|e| ClientError::Handshake(e.to_string()))?;

                    let mut chunk_aad = aad.clone();
                    chunk_aad.extend_from_slice(&prev_hash);

                    let mut ciphertext = frame.ciphertext;

                    // Update hash BEFORE in-place decryption
                    let mut hasher = Sha384::new();
                    hasher.update(prev_hash);
                    hasher.update(&ciphertext);
                    let next_hash = hasher.finalize().into();

                    let p = key
                        .open_in_place(&aead_nonce, &chunk_aad, &mut ciphertext)
                        .map_err(|e| ClientError::Handshake(format!("Stream dec fail: {e:?}")))?;

                    Ok::<(Vec<u8>, [u8; 48]), ClientError>((p.to_vec(), next_hash))
                });

                match res {
                    Ok(Ok((p, next_h))) => {
                        Some((Ok(bytes::Bytes::from(p)), (reader, session, aad, next_h)))
                    }
                    Ok(Err(e)) => Some((Err(e), (reader, session, aad, prev_hash))),
                    Err(e) => Some((
                        Err(ClientError::Handshake(e.to_string())),
                        (reader, session, aad, prev_hash),
                    )),
                }
            },
        );

        Ok(openhttpa_transport::connection::full_body_from_stream(
            decrypted_stream,
        ))
    }

    /// Send a trusted request on an attested session with optional extra headers.
    ///
    /// # Errors
    /// Returns [`Err`](`ClientError`) if encryption, transmission, or decryption fails.
    ///
    /// # Panics
    /// Panics if nonce counter overflows (extremely unlikely).
    #[instrument(skip(self, session, body, extra_headers))]
    pub async fn trusted_request_ext(
        &self,
        session: &AttestSession,
        method: &str,
        path: &str,
        body: &[u8],
        extra_headers: Option<http::HeaderMap>,
    ) -> Result<Vec<u8>, ClientError> {
        if !session.is_alive() {
            return Err(ClientError::NotAttested);
        }

        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| ClientError::Transport("No transport configured".to_string()))?;
        let base_id = session.state().id;

        // Construct full URI for transport and extract the path for AHL binding.
        // This ensures that even if the route is nested (e.g. under /api),
        // the client binds to the full path as seen by the server's OriginalUri.
        let mut base_uri_str = self.server_uri.to_string();
        if base_uri_str.ends_with('/') && path.starts_with('/') {
            base_uri_str.pop();
        }
        let full_uri_str = format!("{base_uri_str}{path}");
        let full_uri: http::Uri = full_uri_str.parse().map_err(|e| {
            ClientError::Handshake(format!("Invalid request URI '{full_uri_str}': {e}"))
        })?;
        let final_path = full_uri.path();

        // 1. Seal body with session keys.
        let mut aad = b"openhttpa:".to_vec();
        aad.extend_from_slice(base_id.to_string().as_bytes());

        let (headers, encrypted_body, _) = Self::seal_request_body(
            session,
            method,
            final_path,
            full_uri.query(),
            ahl_authority(&full_uri),
            body,
            &aad,
            extra_headers.as_ref(),
        )?;
        let (mut headers, encrypted_body, _nonce) = (headers, encrypted_body, 0u64);
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );

        let req = TransportRequest {
            method: http::Method::from_bytes(method.as_bytes()).map_err(|e| {
                ClientError::Transport(format!("invalid HTTP method '{method}': {e}"))
            })?,
            uri: full_uri,
            headers,
            body: openhttpa_transport::connection::full_body(
                serde_json::to_vec(&serde_json::json!({
                    "ciphertext": hex::encode(encrypted_body)
                }))
                .map_err(|e| ClientError::Transport(e.to_string()))?,
            ),
            trailers: None,
        };

        let resp = transport
            .send(req)
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;

        if !resp.status.is_success() {
            return Err(ClientError::Transport(format!(
                "Server returned error: {}",
                resp.status
            )));
        }

        // 3. Unseal response body (bounded by max_response_size to prevent DoS).
        let resp_bytes =
            openhttpa_transport::connection::to_bytes(resp.body, self.max_response_size)
                .await
                .map_err(|e| ClientError::Transport(e.to_string()))?;

        Self::unseal_response_body(session, &resp_bytes, &aad)
    }

    /// Send a 0-RTT trusted request using a resumption ticket.
    ///
    /// ## 0-RTT Key Schedule (SA-05 Hardening)
    ///
    /// Derives fresh keys from the ticket's master secret and a random 16-byte salt,
    /// ensuring forward secrecy for the 0-RTT flight.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Handshake`] as this is a placeholder implementation.
    #[instrument(skip(self, ticket, body))]
    pub async fn trusted_request_0rtt(
        &self,
        ticket: &openhttpa_proto::types::SessionTicket,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let _transport = self
            .transport
            .as_ref()
            .ok_or_else(|| ClientError::Transport("No transport configured".to_string()))?;

        // 1. Unseal the ticket locally (the client owns the ticket secrets)
        // For this demo/placeholder, we derive a mock resumption secret from the ticket bytes.
        let mut hasher = sha2::Sha384::new();
        hasher.update(&ticket.ticket);
        let mock_resumption_secret: [u8; 48] = hasher.finalize().into();

        // 2. Generate a random 16-byte salt for forward secrecy of the 0-RTT flight
        let mut rtt0_salt = [0u8; 16];
        let rng = openhttpa_crypto::rand::SystemRandom::new();
        openhttpa_crypto::rand::SecureRandom::fill(&rng, &mut rtt0_salt)
            .map_err(|_| ClientError::Handshake("RNG failure".to_owned()))?;

        // 3. Derive 0-RTT session keys
        let transcript_hash = [0u8; 48]; // Mock transcript hash
        let session_keys = openhttpa_core::handshake::SessionKeys::derive(
            &mock_resumption_secret,
            &transcript_hash,
        )
        .map_err(|e| ClientError::Handshake(format!("key derivation failed: {e}")))?;

        // 4. Create a temporary AttestSession for the 0-RTT flight
        let session = AttestSession::new(
            openhttpa_proto::AtbId::new(),
            ticket.cipher_suite,
            openhttpa_proto::ProtocolVersion::V2,
            session_keys,
            std::time::Instant::now() + std::time::Duration::from_secs(u64::from(ticket.lifetime)),
            openhttpa_core::ReplayStrategy::default(),
            None,
        );

        // 5. Send the trusted request
        self.trusted_request_ext(&session, method, path, body, None)
            .await
    }

    fn seal_request_body(
        session: &AttestSession,
        method: &str,
        path: &str,
        query: Option<&str>,
        authority: &str,
        body: &[u8],
        aad: &[u8],
        extra_headers: Option<&http::HeaderMap>,
    ) -> Result<(http::HeaderMap, Vec<u8>, u64), ClientError> {
        let base_id = session.state().id;
        // O-03: Unified nonce generation via aws-lc-rs SystemRandom.
        let mut nonce_bytes = [0u8; 8];
        let rng = openhttpa_crypto::rand::SystemRandom::new();
        openhttpa_crypto::rand::SecureRandom::fill(&rng, &mut nonce_bytes)
            .map_err(|_| ClientError::Handshake("RNG failure".to_owned()))?;
        let nonce = u64::from_be_bytes(nonce_bytes);

        session
            .with_keys_for_trr(nonce, |keys, counter| {
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes.copy_from_slice(&keys.client_write_iv);
                let count_bytes = counter.to_be_bytes();
                for (i, b) in count_bytes.iter().enumerate() {
                    nonce_bytes[4 + i] ^= b;
                }
                let _aead_nonce = openhttpa_crypto::aead::AeadNonce::from_slice(&nonce_bytes)
                    .map_err(|_| {
                        ClientError::Handshake("nonce length invariant violated".to_owned())
                    })?;

                let bound_key = openhttpa_crypto::aead::BoundAeadKey::new(
                    openhttpa_crypto::aead::AeadAlgorithm::Aes256Gcm,
                    &keys.client_write_key,
                    keys.client_write_iv.clone().try_into().map_err(|_| {
                        ClientError::Handshake("client_write_iv has wrong length".to_owned())
                    })?,
                )
                .map_err(|e| ClientError::Handshake(format!("Key setup failed: {e}")))?;

                let mut data = body.to_vec();
                bound_key
                    .seal(aad, &mut data)
                    .map_err(|e| ClientError::Handshake(format!("Encryption failed: {e:?}")))?;

                let mut hdrs = extra_headers.map_or_else(http::HeaderMap::new, Clone::clone);
                hdrs.insert(
                    &*HDR_ATTEST_BASE_ID,
                    http::HeaderValue::from_str(&base_id.to_string()).map_err(|e| {
                        ClientError::Handshake(format!("invalid base-id header value: {e}"))
                    })?,
                );

                let mut hmac = HmacSha384::new_from_slice(&keys.client_mac_key)
                    .map_err(|e| ClientError::Handshake(format!("HMAC key setup failed: {e}")))?;
                hmac.update(&counter.to_be_bytes());
                // SEC-01: pass query so that parameter manipulation is detected.
                openhttpa_headers::update_ahl(method, path, query, authority, &hdrs, |chunk| {
                    hmac.update(chunk);
                })
                .map_err(|e| ClientError::Handshake(format!("AHL error: {e}")))?;
                let mac = hmac.finalize().into_bytes().to_vec();

                hdrs.insert(
                    &*HDR_ATTEST_TICKET,
                    openhttpa_headers::encode_attest_ticket(counter, &mac, None),
                );

                Ok::<(_, _, _), ClientError>((hdrs, data, counter))
            })
            .map_err(|e| ClientError::Handshake(e.to_string()))?
    }

    fn unseal_response_body(
        session: &AttestSession,
        resp_body: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let body_json: serde_json::Value = serde_json::from_slice(resp_body)
            .map_err(|e| ClientError::Serialisation(e.to_string()))?;

        let ciphertext_hex = body_json["ciphertext"].as_str().ok_or_else(|| {
            ClientError::Serialisation("Missing ciphertext in response".to_string())
        })?;
        let mut ciphertext =
            hex::decode(ciphertext_hex).map_err(|e| ClientError::Serialisation(e.to_string()))?;

        session
            .with_keys_for_trs(|keys, counter| {
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes.copy_from_slice(&keys.server_write_iv);
                let count_bytes = counter.to_be_bytes();
                for (i, b) in count_bytes.iter().enumerate() {
                    nonce_bytes[4 + i] ^= b;
                }
                let aead_nonce = AeadNonce::from_slice(&nonce_bytes).unwrap();

                let bound_key = BoundAeadKey::new(
                    AeadAlgorithm::Aes256Gcm,
                    &keys.server_write_key,
                    keys.server_write_iv.clone().try_into().unwrap(),
                )
                .map_err(|e| ClientError::Handshake(format!("Key setup failed: {e}")))?;

                let p = bound_key
                    .open(&aead_nonce, aad, &mut ciphertext)
                    .map_err(|e| ClientError::Handshake(format!("Decryption failed: {e:?}")))?;

                Ok::<Vec<u8>, ClientError>(p.to_vec())
            })
            .map_err(|e| ClientError::Handshake(e.to_string()))?
    }
}

struct StreamFrame {
    counter: u64,
    ciphertext: Vec<u8>,
}

struct StreamFrameReader<S> {
    stream: S,
    buffer: bytes::BytesMut,
}

impl<S> StreamFrameReader<S>
where
    S: futures::Stream<Item = Result<bytes::Bytes, std::io::Error>> + Unpin,
{
    fn new(stream: S) -> Self {
        Self {
            stream,
            buffer: bytes::BytesMut::new(),
        }
    }

    async fn next_frame(&mut self) -> Result<Option<StreamFrame>, ClientError> {
        use futures::StreamExt;

        loop {
            // Need at least 4 bytes for length
            if self.buffer.len() >= 4 {
                let len = u32::from_be_bytes(self.buffer[..4].try_into().unwrap()) as usize;
                // Need length + 8 bytes for counter
                if self.buffer.len() >= 4 + 8 + len {
                    let _ = self.buffer.split_to(4); // Remove length
                    let counter =
                        u64::from_be_bytes(self.buffer.split_to(8)[..8].try_into().unwrap());
                    let ciphertext = self.buffer.split_to(len).to_vec();
                    return Ok(Some(StreamFrame {
                        counter,
                        ciphertext,
                    }));
                }
            }

            match self.stream.next().await {
                Some(Ok(chunk)) => self.buffer.extend_from_slice(&chunk),
                Some(Err(e)) => return Err(ClientError::Transport(e.to_string())),
                None => {
                    if self.buffer.is_empty() {
                        return Ok(None);
                    }
                    return Err(ClientError::Transport(
                        "Incomplete frame at end of stream".to_owned(),
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyTransport;
    impl openhttpa_transport::connection::AttestTransport for DummyTransport {
        fn send(
            &self,
            req: openhttpa_transport::connection::TransportRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            openhttpa_transport::connection::TransportResponse,
                            openhttpa_transport::connection::SendError,
                        >,
                    > + Send
                    + '_,
            >,
        > {
            Box::pin(async move {
                if req.method == http::Method::OPTIONS {
                    let resp_hdrs = openhttpa_headers::attest_headers::PreflightResponseHeaders {
                        cipher_suites: vec![
                            openhttpa_proto::CipherSuite::X25519MlKem768Aes256GcmSha384,
                        ],
                        versions: vec![openhttpa_proto::ProtocolVersion::V2],
                        challenge: vec![0x42u8; 32],
                        oblivious_supported: false,
                    };
                    return Ok(openhttpa_transport::connection::TransportResponse {
                        status: http::StatusCode::OK,
                        headers: resp_hdrs.encode(),
                        body: openhttpa_transport::connection::empty_body(),
                        trailers: None,
                    });
                }

                let req_hdrs =
                    openhttpa_headers::attest_headers::AtHsRequestHeaders::decode(&req.headers)
                        .unwrap();
                let client_share: openhttpa_core::handshake::ClientKeyShare =
                    serde_json::from_slice(&req_hdrs.key_shares_json).unwrap();

                // Perform a real "server" side of the KEM to get valid ciphertext
                let server_pair =
                    openhttpa_crypto::key_exchange::HybridKemPair::generate().unwrap();
                let server_pub = server_pair.public_key_share();
                let client_ks = openhttpa_crypto::key_exchange::KeyShare {
                    ecdhe_public: client_share.ecdhe_public,
                    mlkem_public: client_share.mlkem_public,
                };
                let (_, ct) = server_pair.server_combine(&client_ks).unwrap();

                let resp_hdrs = openhttpa_headers::attest_headers::AtHsResponseHeaders {
                    cipher_suite: openhttpa_proto::CipherSuite::X25519MlKem768Aes256GcmSha384,
                    random: vec![0u8; 32],
                    key_share_json: serde_json::to_vec(
                        &openhttpa_core::handshake::ServerKeyShare {
                            ecdhe_public: server_pub.ecdhe_public,
                            mlkem_ciphertext: ct,
                            mlkem_public: server_pub.mlkem_public,
                            signature_alg: Some(openhttpa_core::handshake::SIG_ALG_ML_DSA_65),
                        },
                    )
                    .unwrap(),
                    base_id: openhttpa_proto::AtbId::new(),
                    version: openhttpa_proto::ProtocolVersion::V2,
                    expires_secs: 3600,
                    quotes: vec![],
                    secrets: vec![],
                    cargo: None,
                    ticket_resumption: None,
                    server_signatures: vec![],
                    zk_proof: None,
                };
                Ok(openhttpa_transport::connection::TransportResponse {
                    status: http::StatusCode::OK,
                    headers: resp_hdrs.encode(),
                    body: openhttpa_transport::connection::empty_body(),
                    trailers: None,
                })
            })
        }
    }

    #[tokio::test]
    async fn client_handshake_produces_live_session() {
        let client = OpenHttpaClient::builder()
            .server_uri("http://127.0.0.1:8080".parse().unwrap())
            .transport(Arc::new(DummyTransport))
            .build();
        let session = client.attest_handshake().await.unwrap();
        assert!(session.is_alive());
    }
}
