// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Hybrid Public Key Encryption (HPKE) analogue using Post-Quantum KEM.
//!
//! This module provides a mechanism to encapsulate the initial `AtHS` handshake
//! (Encrypted Client Hello) to protect metadata from network observers and relays.
//! It uses ML-KEM-768 to establish a shared secret, and AES-256-GCM to encrypt
//! the payload.

use crate::aead::{AeadAlgorithm, AeadKey};
use crate::pqc::{MlKemPair, PqcError};

/// Errors from HPKE operations.
#[derive(Debug, thiserror::Error)]
pub enum HpkeError {
    /// Post-quantum encapsulation/decapsulation failed.
    #[error("PQC error: {0}")]
    Pqc(#[from] PqcError),
    /// Payload encryption failed.
    #[error("encryption failed: {0}")]
    Encryption(String),
    /// Payload decryption failed.
    #[error("decryption failed")]
    Decryption,
}

/// The result of an HPKE seal operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HpkeCiphertext {
    /// The ML-KEM ciphertext containing the encapsulated shared secret.
    pub mlkem_ct: Vec<u8>,
    /// The AES-256-GCM ciphertext of the payload.
    pub payload_ct: Vec<u8>,
    /// The authentication tag.
    pub tag: Vec<u8>,
}

/// Client-side HPKE encapsulation.
pub struct HpkeClient;

impl HpkeClient {
    /// Seal a payload using the TEE's semi-static ML-KEM public key.
    ///
    /// Returns `HpkeCiphertext`.
    ///
    /// # Errors
    /// Returns [`HpkeError`] if encapsulation or encryption fails.
    pub fn seal(tee_mlkem_public_key: &[u8], payload: &[u8]) -> Result<HpkeCiphertext, HpkeError> {
        // Generate an ephemeral ML-KEM pair for the client
        let pair = MlKemPair::generate()?;

        // Encapsulate to the TEE's public key
        let (shared_secret, mlkem_ct) = pair.encapsulate(tee_mlkem_public_key)?;

        let mut key_bytes = [0u8; 32];
        let mut nonce_bytes = [0u8; 12];
        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, &shared_secret);
        hkdf.expand(b"openhttpa_hpke_key", &mut key_bytes)
            .map_err(|_| HpkeError::Encryption("hkdf failed".into()))?;
        hkdf.expand(b"openhttpa_hpke_nonce", &mut nonce_bytes)
            .map_err(|_| HpkeError::Encryption("hkdf failed".into()))?;

        let aead_key = AeadKey::new(AeadAlgorithm::Aes256Gcm, &key_bytes)
            .map_err(|e| HpkeError::Encryption(e.to_string()))?;

        let mut data = payload.to_vec();
        aead_key
            .seal_in_place(&crate::aead::AeadNonce(nonce_bytes), b"", &mut data)
            .map_err(|e| HpkeError::Encryption(e.to_string()))?;

        let tag_len = 16;
        let ct_len = data.len() - tag_len;
        let ciphertext = data[..ct_len].to_vec();
        let tag = data[ct_len..].to_vec();

        Ok(HpkeCiphertext {
            mlkem_ct,
            payload_ct: ciphertext,
            tag,
        })
    }
}

/// Server-side HPKE decapsulation.
pub struct HpkeServer;

impl HpkeServer {
    /// Open an HPKE sealed payload using the TEE's semi-static ML-KEM pair.
    ///
    /// # Errors
    /// Returns [`HpkeError`] if decapsulation or decryption fails.
    pub fn open(
        tee_private_pair: &MlKemPair,
        mlkem_ct: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        // Decapsulate using our private key
        let shared_secret = tee_private_pair.decapsulate(mlkem_ct)?;

        let mut key_bytes = [0u8; 32];
        let mut nonce_bytes = [0u8; 12];
        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, &shared_secret);
        hkdf.expand(b"openhttpa_hpke_key", &mut key_bytes)
            .map_err(|_| HpkeError::Decryption)?;
        hkdf.expand(b"openhttpa_hpke_nonce", &mut nonce_bytes)
            .map_err(|_| HpkeError::Decryption)?;

        let aead_key = AeadKey::new(AeadAlgorithm::Aes256Gcm, &key_bytes)
            .map_err(|_| HpkeError::Decryption)?;

        if tag.len() != 16 {
            return Err(HpkeError::Decryption);
        }

        let mut data = ciphertext.to_vec();
        data.extend_from_slice(tag);

        let pt = aead_key
            .open_in_place(&crate::aead::AeadNonce(nonce_bytes), b"", &mut data)
            .map_err(|_| HpkeError::Decryption)?;
        Ok(pt.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpke_round_trip() {
        let tee_pair = MlKemPair::generate().unwrap();
        let payload = b"secret metadata";

        let ct = HpkeClient::seal(tee_pair.public_encap_key(), payload).unwrap();

        let decrypted = HpkeServer::open(&tee_pair, &ct.mlkem_ct, &ct.payload_ct, &ct.tag).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn hpke_tamper_fails() {
        let tee_pair = MlKemPair::generate().unwrap();
        let payload = b"secret metadata";

        let mut ct = HpkeClient::seal(tee_pair.public_encap_key(), payload).unwrap();

        // Tamper with ciphertext
        ct.payload_ct[0] ^= 1;

        let result = HpkeServer::open(&tee_pair, &ct.mlkem_ct, &ct.payload_ct, &ct.tag);
        assert!(result.is_err());
    }
}
