// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Oblivious `OpenHTTPA` transport (O-HTTPA) implementation.
//!
//! Based on RFC 9458 (Oblivious HTTP).

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead as _};
use async_trait::async_trait;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable, aead::AeadCtxR, kem::Kem as KemTrait};
use rand::thread_rng;
use std::sync::Arc;
use thiserror::Error;

use crate::connection::{AttestTransport, SendError, TransportRequest, TransportResponse};

/// HPKE Cipher Suite for O-HTTPA.
type Kem = hpke::kem::X25519HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::AesGcm256;

/// HPKE receiver context type.
type ReceiverCtx = AeadCtxR<Aead, Kdf, Kem>;

#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ObliviousError {
    #[error("HPKE error: {0}")]
    Hpke(String),
    #[error("malformed oblivious message")]
    Malformed,
    #[error("transport error: {0}")]
    Transport(#[from] SendError),
}

/// An oblivious client that encapsulates requests.
pub struct ObliviousClient {
    inner: Arc<dyn AttestTransport>,
    server_public_key: Vec<u8>,
    key_id: u8,
}

impl ObliviousClient {
    pub fn new(inner: Arc<dyn AttestTransport>, server_public_key: Vec<u8>, key_id: u8) -> Self {
        Self {
            inner,
            server_public_key,
            key_id,
        }
    }
}

#[async_trait]
impl AttestTransport for ObliviousClient {
    async fn send(&self, req: TransportRequest) -> Result<TransportResponse, SendError> {
        let (encap, mut sender_ctx) = {
            let mut rng = thread_rng();

            // 1. HPKE Setup
            let pk_server = <Kem as KemTrait>::PublicKey::from_bytes(&self.server_public_key)
                .map_err(|_| SendError::Connection("invalid server public key".to_owned()))?;

            hpke::setup_sender::<Aead, Kdf, Kem, _>(
                &OpModeS::Base,
                &pk_server,
                b"openhttpa-oblivious",
                &mut rng,
            )
            .map_err(|e| SendError::Connection(format!("HPKE setup failed: {e:?}")))?
        };

        // 2. Encapsulate Request
        let TransportRequest {
            method,
            uri,
            mut headers,
            body,
            trailers,
        } = req;

        let body_bytes = axum::body::to_bytes(body, 100 * 1024 * 1024)
            .await
            .map_err(|e| SendError::Protocol(format!("body collect error: {e}")))?;

        let ciphertext = sender_ctx
            .seal(&body_bytes, b"")
            .map_err(|e| SendError::Connection(format!("HPKE seal failed: {e:?}")))?;

        let mut enc_body = Vec::with_capacity(1 + encap.to_bytes().len() + ciphertext.len());
        enc_body.push(self.key_id);
        enc_body.extend_from_slice(&encap.to_bytes());
        enc_body.extend_from_slice(&ciphertext);

        headers.insert(
            http::header::CONTENT_TYPE,
            "message/oblivious-http".parse().unwrap(),
        );

        let enc_req = TransportRequest {
            method,
            uri,
            headers,
            body: axum::body::Body::from(enc_body),
            trailers,
        };

        // 3. Send via inner transport
        let resp = self.inner.send(enc_req).await?;

        // 4. Decapsulate Response using exported key
        let mut response_key = [0u8; 32];
        sender_ctx
            .export(b"openhttpa-oblivious-resp", &mut response_key)
            .map_err(|e| SendError::Connection(format!("HPKE export failed: {e:?}")))?;

        let resp_body = axum::body::to_bytes(resp.body, 100 * 1024 * 1024)
            .await
            .map_err(|e| SendError::Protocol(format!("resp body collect error: {e}")))?;

        let cipher = Aes256Gcm::new_from_slice(&response_key)
            .map_err(|_| SendError::Connection("AES init failed".to_owned()))?;
        let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
        let plaintext = cipher
            .decrypt(nonce, resp_body.as_ref())
            .map_err(|e| SendError::Connection(format!("AEAD open failed: {e:?}")))?;

        Ok(TransportResponse {
            status: resp.status,
            headers: resp.headers,
            body: axum::body::Body::from(plaintext),
            trailers: resp.trailers,
        })
    }
}

/// An oblivious server that decapsulates requests.
pub struct ObliviousServer {
    server_secret_key: <Kem as KemTrait>::PrivateKey,
}

impl ObliviousServer {
    #[must_use]
    pub const fn new(server_secret_key: <Kem as KemTrait>::PrivateKey) -> Self {
        Self { server_secret_key }
    }

    /// Decapsulate an O-HTTP request.
    ///
    /// # Errors
    /// Returns [`ObliviousError::Malformed`] if the message is too short, or
    /// [`ObliviousError::Hpke`] if HPKE decapsulation fails.
    pub fn decapsulate(&self, enc_body: &[u8]) -> Result<(Vec<u8>, ReceiverCtx), ObliviousError> {
        if enc_body.len() < 1 + 32 {
            return Err(ObliviousError::Malformed);
        }

        let encap = <Kem as KemTrait>::EncappedKey::from_bytes(&enc_body[1..33])
            .map_err(|e| ObliviousError::Hpke(format!("{e:?}")))?;
        let ciphertext = &enc_body[33..];

        let mut receiver_ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &self.server_secret_key,
            &encap,
            b"openhttpa-oblivious",
        )
        .map_err(|e| ObliviousError::Hpke(format!("{e:?}")))?;
        let plaintext = receiver_ctx
            .open(ciphertext, b"")
            .map_err(|e| ObliviousError::Hpke(format!("{e:?}")))?;

        Ok((plaintext, receiver_ctx))
    }

    /// Encapsulate an O-HTTP response using exported key.
    ///
    /// # Errors
    /// Returns [`ObliviousError::Hpke`] if key export or encryption fails.
    pub fn encapsulate_response(
        &self,
        receiver_ctx: &ReceiverCtx,
        body: &[u8],
    ) -> Result<Vec<u8>, ObliviousError> {
        let mut response_key = [0u8; 32];
        receiver_ctx
            .export(b"openhttpa-oblivious-resp", &mut response_key)
            .map_err(|e| ObliviousError::Hpke(format!("{e:?}")))?;

        let cipher = Aes256Gcm::new_from_slice(&response_key)
            .map_err(|_| ObliviousError::Hpke("AES init failed".to_owned()))?;
        let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
        let ciphertext = cipher
            .encrypt(nonce, body)
            .map_err(|e| ObliviousError::Hpke(format!("{e:?}")))?;

        Ok(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oblivious_server_malformed() {
        let (sk, _pk) = <Kem as KemTrait>::gen_keypair(&mut rand::thread_rng());
        let server = ObliviousServer::new(sk);

        let result = server.decapsulate(b"short");
        assert!(matches!(result, Err(ObliviousError::Malformed)));

        let enc_body = vec![0u8; 64];
        let result = server.decapsulate(&enc_body);
        assert!(matches!(result, Err(ObliviousError::Hpke(_))));
    }
}
