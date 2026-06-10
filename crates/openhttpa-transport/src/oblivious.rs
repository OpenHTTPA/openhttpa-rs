// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Oblivious `OpenHTTPA` transport (O-HTTPA) implementation.
//!
//! Based on RFC 9458 (Oblivious HTTP), upgraded to use ML-KEM-768 (FIPS 203)
//! for Post-Quantum key encapsulation.
//!
//! # Wire Format (Request)
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │  key_id (1 B) │ kem_ct_len (2 B, big-endian)               │
//! │  kem_ciphertext (kem_ct_len bytes, ML-KEM-768 = 1088 B)    │
//! │  aes_nonce (12 B, random)                                   │
//! │  aes_ciphertext (variable)                                  │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Wire Format (Response)
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │  aes_nonce (12 B, random)                                   │
//! │  aes_ciphertext (variable)                                  │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! Session keys are derived from the ML-KEM shared secret via HKDF-SHA-256:
//! - `request_key`  = `HKDF(ikm=mlkem_ss, info=b"req",  len=32)`
//! - `response_key` = `HKDF(ikm=mlkem_ss, info=b"resp", len=32)`

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead as _};
use hkdf::Hkdf;
use openhttpa_crypto::pqc::MlKemPair;
use sha2::Sha256;

use std::sync::Arc;
use thiserror::Error;

use crate::connection::{AttestTransport, SendError, TransportRequest, TransportResponse};

// AES-GCM nonce length.
const NONCE_LEN: usize = 12;
// AES-256 key length.
const KEY_LEN: usize = 32;

#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ObliviousError {
    /// ML-KEM KEM encapsulation or decapsulation failed.
    #[error("KEM error: {0}")]
    Kem(String),
    /// The oblivious message is structurally malformed (too short, truncated).
    #[error("malformed oblivious message")]
    Malformed,
    /// A cryptographic operation (HKDF, AES-GCM) failed.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// The underlying transport returned an error.
    #[error("transport error: {0}")]
    Transport(#[from] SendError),
}

/// Helper: derive `(request_key, response_key)` from a ML-KEM shared secret.
fn derive_session_keys(
    shared_secret: &[u8],
) -> Result<([u8; KEY_LEN], [u8; KEY_LEN]), ObliviousError> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"openhttpa-oblivious"), shared_secret);
    let mut req_key = [0u8; KEY_LEN];
    let mut resp_key = [0u8; KEY_LEN];
    hkdf.expand(b"req", &mut req_key)
        .map_err(|_| ObliviousError::Crypto("HKDF expand(req) failed".to_owned()))?;
    hkdf.expand(b"resp", &mut resp_key)
        .map_err(|_| ObliviousError::Crypto("HKDF expand(resp) failed".to_owned()))?;
    Ok((req_key, resp_key))
}

/// Helper: AES-256-GCM encrypt with a randomly generated nonce.
///
/// Returns `nonce || ciphertext`.
fn aes_encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>, ObliviousError> {
    use rand::RngExt;
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| ObliviousError::Crypto("AES-256-GCM init failed".to_owned()))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| ObliviousError::Crypto(format!("AES-256-GCM encrypt failed: {e:?}")))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Helper: AES-256-GCM decrypt from `nonce || ciphertext` wire format.
fn aes_decrypt(key: &[u8; KEY_LEN], nonce_and_ct: &[u8]) -> Result<Vec<u8>, ObliviousError> {
    if nonce_and_ct.len() < NONCE_LEN {
        return Err(ObliviousError::Malformed);
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| ObliviousError::Crypto("AES-256-GCM init failed".to_owned()))?;
    let nonce = aes_gcm::Nonce::from_slice(&nonce_and_ct[..NONCE_LEN]);
    let ciphertext = &nonce_and_ct[NONCE_LEN..];
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| ObliviousError::Crypto(format!("AES-256-GCM decrypt failed: {e:?}")))
}

// ── Client ────────────────────────────────────────────────────────────────────

/// An oblivious client that encapsulates requests using ML-KEM-768 + AES-256-GCM.
pub struct ObliviousClient {
    inner: Arc<dyn AttestTransport>,
    /// Server's ML-KEM encapsulation (public) key bytes.
    server_public_key: Vec<u8>,
    /// Key identifier sent in each request (RFC 9458 §5.1).
    key_id: u8,
}

impl ObliviousClient {
    /// Create a new oblivious client.
    ///
    /// # Arguments
    /// * `inner`             — underlying attested transport
    /// * `server_public_key` — server's ML-KEM-768 encapsulation key (1184 bytes)
    /// * `key_id`            — opaque key identifier echoed in the request
    pub fn new(inner: Arc<dyn AttestTransport>, server_public_key: Vec<u8>, key_id: u8) -> Self {
        Self {
            inner,
            server_public_key,
            key_id,
        }
    }
}

impl AttestTransport for ObliviousClient {
    fn send(
        &self,
        req: TransportRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TransportResponse, SendError>> + Send + '_>,
    > {
        Box::pin(async move {
            // 1. ML-KEM Encapsulation: generate ephemeral pair and encapsulate
            //    against the server's public encapsulation key.
            let kem_pair = MlKemPair::generate()
                .map_err(|e| SendError::Connection(format!("ML-KEM keygen failed: {e:?}")))?;
            let (shared_secret, kem_ciphertext) = kem_pair
                .encapsulate(&self.server_public_key)
                .map_err(|e| SendError::Connection(format!("ML-KEM encap failed: {e:?}")))?;

            // 2. Derive session keys from the ML-KEM shared secret.
            let (req_key, resp_key) = derive_session_keys(&shared_secret)
                .map_err(|e| SendError::Connection(e.to_string()))?;

            // 3. Collect and encrypt the request body.
            let TransportRequest {
                method,
                uri,
                mut headers,
                body,
                trailers,
            } = req;
            let body_bytes = crate::connection::to_bytes(body, 100 * 1024 * 1024)
                .await
                .map_err(|e| SendError::Protocol(format!("body collect error: {e}")))?;
            let enc_payload = aes_encrypt(&req_key, &body_bytes)
                .map_err(|e| SendError::Connection(e.to_string()))?;

            // 4. Build the wire-format request body:
            //    key_id (1) || kem_ct_len (2, big-endian) || kem_ct || nonce (12) || aes_ct
            let kem_ct_len = u16::try_from(kem_ciphertext.len())
                .expect("ML-KEM-768 ciphertext length exceeds u16::MAX");
            let mut enc_body = Vec::with_capacity(1 + 2 + kem_ciphertext.len() + enc_payload.len());
            enc_body.push(self.key_id);
            enc_body.extend_from_slice(&kem_ct_len.to_be_bytes());
            enc_body.extend_from_slice(&kem_ciphertext);
            enc_body.extend_from_slice(&enc_payload); // already nonce || ct

            headers.insert(
                http::header::CONTENT_TYPE,
                "message/oblivious-http".parse().unwrap(),
            );

            // 5. Send the encapsulated request via the inner transport.
            let resp = self
                .inner
                .send(TransportRequest {
                    method,
                    uri,
                    headers,
                    body: crate::connection::full_body(enc_body),
                    trailers,
                })
                .await?;

            // 6. Decrypt the response.
            let resp_body = crate::connection::to_bytes(resp.body, 100 * 1024 * 1024)
                .await
                .map_err(|e| SendError::Protocol(format!("resp body collect error: {e}")))?;
            let plaintext = aes_decrypt(&resp_key, &resp_body)
                .map_err(|e| SendError::Connection(e.to_string()))?;

            Ok(TransportResponse {
                status: resp.status,
                headers: resp.headers,
                body: crate::connection::full_body(plaintext),
                trailers: resp.trailers,
            })
        })
    }
}

// ── Server ────────────────────────────────────────────────────────────────────

/// An oblivious server that decapsulates requests using ML-KEM-768 + AES-256-GCM.
pub struct ObliviousServer {
    /// Server's ML-KEM-768 key pair. The decapsulation key is secret.
    server_keypair: MlKemPair,
}

impl ObliviousServer {
    /// Create a new oblivious server from a pre-generated ML-KEM key pair.
    #[must_use]
    pub const fn new(server_keypair: MlKemPair) -> Self {
        Self { server_keypair }
    }

    /// Return the server's ML-KEM encapsulation (public) key bytes.
    ///
    /// Publish this key in an OHTTP key configuration resource (RFC 9458 §3).
    #[must_use]
    pub fn public_encap_key(&self) -> &[u8] {
        self.server_keypair.public_encap_key()
    }

    /// Decapsulate an O-HTTPA request.
    ///
    /// Returns `(plaintext_body, response_key)` on success.
    ///
    /// # Errors
    /// - [`ObliviousError::Malformed`] if the wire format is invalid.
    /// - [`ObliviousError::Kem`] if ML-KEM decapsulation fails (e.g., wrong server key).
    /// - [`ObliviousError::Crypto`] if AES-GCM decryption fails (integrity violation).
    pub fn decapsulate(&self, enc_body: &[u8]) -> Result<(Vec<u8>, [u8; KEY_LEN]), ObliviousError> {
        // Parse: key_id (1) || kem_ct_len (2)
        if enc_body.len() < 3 {
            return Err(ObliviousError::Malformed);
        }
        // key_id byte is parsed but reserved for future key rotation.
        let _ = enc_body[0];
        let kem_ct_len = u16::from_be_bytes([enc_body[1], enc_body[2]]) as usize;

        // Parse: kem_ct (kem_ct_len) || nonce (12) || aes_ct
        let header_end = 3 + kem_ct_len;
        if enc_body.len() < header_end + NONCE_LEN {
            return Err(ObliviousError::Malformed);
        }

        let kem_ct = &enc_body[3..header_end];
        let nonce_and_aes_ct = &enc_body[header_end..];

        // ML-KEM decapsulation.
        let shared_secret = self
            .server_keypair
            .decapsulate(kem_ct)
            .map_err(|e| ObliviousError::Kem(format!("{e:?}")))?;

        // Derive session keys.
        let (req_key, resp_key) = derive_session_keys(&shared_secret)?;

        // Decrypt request body.
        let plaintext = aes_decrypt(&req_key, nonce_and_aes_ct)?;

        Ok((plaintext, resp_key))
    }

    /// Encapsulate an O-HTTPA response.
    ///
    /// `resp_key` must be the response key returned by a prior [`Self::decapsulate`] call
    /// for the same session.
    ///
    /// # Errors
    /// Returns [`ObliviousError::Crypto`] if AES-GCM encryption fails.
    pub fn encapsulate_response(
        &self,
        resp_key: &[u8; KEY_LEN],
        body: &[u8],
    ) -> Result<Vec<u8>, ObliviousError> {
        aes_encrypt(resp_key, body)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::{AttestTransport, TransportRequest, TransportResponse};
    use http::{Method, StatusCode};
    use std::sync::Arc;

    /// A test double that wraps an [`ObliviousServer`] in an `Arc` so that it
    /// can be used safely inside the async `send` closure without raw pointers
    /// or `unsafe`.
    struct MockObliviousRelay {
        server: Arc<ObliviousServer>,
    }

    impl AttestTransport for MockObliviousRelay {
        fn send(
            &self,
            req: TransportRequest,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<TransportResponse, SendError>> + Send + '_>,
        > {
            let server = Arc::clone(&self.server);
            Box::pin(async move {
                let body_bytes = crate::connection::to_bytes(req.body, 1024 * 1024)
                    .await
                    .unwrap();
                let (plaintext, resp_key) = server
                    .decapsulate(&body_bytes)
                    .expect("server decapsulate failed");
                assert_eq!(plaintext, b"hello server");

                let resp_bytes = server
                    .encapsulate_response(&resp_key, b"hello client")
                    .expect("server encapsulate_response failed");

                Ok(TransportResponse {
                    status: StatusCode::OK,
                    headers: http::HeaderMap::default(),
                    body: crate::connection::full_body(resp_bytes),
                    trailers: None,
                })
            })
        }
    }

    // ── Unit tests ────────────────────────────────────────────────────────────

    #[test]
    fn test_oblivious_error_display() {
        assert_eq!(
            ObliviousError::Kem("bad".to_owned()).to_string(),
            "KEM error: bad"
        );
        assert_eq!(
            ObliviousError::Malformed.to_string(),
            "malformed oblivious message"
        );
        assert_eq!(
            ObliviousError::Transport(SendError::Protocol("fail".to_owned())).to_string(),
            "transport error: protocol error: fail"
        );
    }

    #[test]
    fn test_decapsulate_too_short() {
        let server = ObliviousServer::new(MlKemPair::generate().unwrap());
        assert!(matches!(
            server.decapsulate(b""),
            Err(ObliviousError::Malformed)
        ));
        assert!(matches!(
            server.decapsulate(b"ab"),
            Err(ObliviousError::Malformed)
        ));
    }

    #[test]
    fn test_decapsulate_kem_ct_len_overflow_is_malformed() {
        let server = ObliviousServer::new(MlKemPair::generate().unwrap());
        // key_id=0x00, kem_ct_len = 0xFFFF (way larger than actual body)
        let mut enc_body = vec![0u8; 3 + NONCE_LEN + 1];
        enc_body[1] = 0xFF;
        enc_body[2] = 0xFF;
        assert!(matches!(
            server.decapsulate(&enc_body),
            Err(ObliviousError::Malformed)
        ));
    }

    #[test]
    fn test_decapsulate_wrong_kem_ct_fails() {
        // ML-KEM-768 ciphertext is 1088 bytes (FIPS 203, Table 2).
        const MLKEM768_CT_LEN: usize = 1088;
        let server = ObliviousServer::new(MlKemPair::generate().unwrap());
        let kem_ct_len = MLKEM768_CT_LEN;
        let body_len = 3 + kem_ct_len + NONCE_LEN + 1;
        // Construct a valid-length but all-zero (garbage) kem_ct.
        let mut enc_body = vec![0u8; body_len];
        enc_body[1] = u8::try_from(kem_ct_len >> 8).unwrap();
        enc_body[2] = u8::try_from(kem_ct_len & 0xFF).unwrap();
        // ML-KEM-768 uses implicit rejection (FIPS 203 §6.4): decapsulation
        // always succeeds but with a pseudorandom shared secret for invalid
        // ciphertexts.  The wrong key makes AES-GCM authentication fail, so
        // the error surfaces as Crypto, not Kem.
        let result = server.decapsulate(&enc_body);
        assert!(matches!(result, Err(ObliviousError::Crypto(_))));
    }

    // ── Integration: full client-server round-trip ────────────────────────────

    #[tokio::test]
    async fn test_oblivious_client_server_round_trip() {
        let server = Arc::new(ObliviousServer::new(MlKemPair::generate().unwrap()));
        let pk_bytes = server.public_encap_key().to_vec();

        let relay = Arc::new(MockObliviousRelay {
            server: Arc::clone(&server),
        });
        let client = ObliviousClient::new(relay, pk_bytes, 0x01);

        let req = TransportRequest {
            method: Method::POST,
            uri: "http://example.com/".parse().unwrap(),
            headers: http::HeaderMap::default(),
            body: crate::connection::full_body("hello server"),
            trailers: None,
        };

        let resp = client.send(req).await.expect("client.send failed");
        assert_eq!(resp.status, StatusCode::OK);

        let resp_body = crate::connection::to_bytes(resp.body, 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(resp_body.as_ref(), b"hello client");
    }

    #[tokio::test]
    async fn test_oblivious_client_invalid_server_key() {
        // NopTransport must be defined before any `let` statements to satisfy
        // clippy::items_after_statements.
        struct NopTransport;
        impl AttestTransport for NopTransport {
            fn send(
                &self,
                _req: TransportRequest,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<TransportResponse, SendError>>
                        + Send
                        + '_,
                >,
            > {
                Box::pin(async { unreachable!("should not reach inner transport") })
            }
        }

        // A 10-byte blob is not a valid ML-KEM-768 encapsulation key.
        let bad_pk = vec![0u8; 10];
        let client = ObliviousClient::new(Arc::new(NopTransport), bad_pk, 0x01);
        let req = TransportRequest {
            method: Method::POST,
            uri: "http://example.com/".parse().unwrap(),
            headers: http::HeaderMap::default(),
            body: crate::connection::full_body("ignored"),
            trailers: None,
        };

        match client.send(req).await {
            Err(e) => assert!(matches!(e, SendError::Connection(_))),
            Ok(_) => panic!("expected a Connection error but got Ok"),
        }
    }
}
