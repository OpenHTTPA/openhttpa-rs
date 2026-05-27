// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Classical digital signatures via `aws-lc-rs`.

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{
        self, ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING,
        EcdsaKeyPair as AwsEcdsaKP, EcdsaSigningAlgorithm, KeyPair,
    },
};
use thiserror::Error;

/// Signature errors.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum SignatureError {
    /// Key generation failed.
    #[error("key generation failed")]
    KeyGen,
    /// Signing operation failed.
    #[error("sign operation failed")]
    Sign,
    /// Signature verification failed.
    #[error("signature verification failed")]
    Verify,
    /// Invalid key bytes provided.
    #[error("invalid key bytes")]
    InvalidKey,
}

/// An ECDSA key pair (P-256 or P-384) for signing `OpenHTTPA` AHLs.
pub struct EcdsaKeyPair {
    inner: AwsEcdsaKP,
    /// DER-encoded public key bytes suitable for inclusion in
    /// `Attest-Signatures` AHF.
    pub public_key_der: Vec<u8>,
}

impl EcdsaKeyPair {
    /// Generate a new P-256 ECDSA key pair.
    ///
    /// # Errors
    /// Returns [`Err`] if key generation or PKCS#8 encoding fails.
    pub fn generate_p256() -> Result<Self, SignatureError> {
        Self::generate_inner(&ECDSA_P256_SHA256_FIXED_SIGNING)
    }

    /// Generate a new P-384 ECDSA key pair.
    ///
    /// # Errors
    /// Returns [`Err`] if key generation or PKCS#8 encoding fails.
    pub fn generate_p384() -> Result<Self, SignatureError> {
        Self::generate_inner(&ECDSA_P384_SHA384_FIXED_SIGNING)
    }

    fn generate_inner(alg: &'static EcdsaSigningAlgorithm) -> Result<Self, SignatureError> {
        let rng = SystemRandom::new();
        let doc = AwsEcdsaKP::generate_pkcs8(alg, &rng).map_err(|_| SignatureError::KeyGen)?;
        let kp =
            AwsEcdsaKP::from_pkcs8(alg, doc.as_ref()).map_err(|_| SignatureError::InvalidKey)?;
        let pub_key = kp.public_key().as_ref().to_vec();
        Ok(Self {
            inner: kp,
            public_key_der: pub_key,
        })
    }

    /// Sign `message` and return the DER-encoded signature.
    ///
    /// # Errors
    /// Returns [`Err`] if the signing operation fails.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignatureError> {
        let rng = SystemRandom::new();
        let sig = self
            .inner
            .sign(&rng, message)
            .map_err(|_| SignatureError::Sign)?;
        Ok(sig.as_ref().to_vec())
    }

    /// Verify an ECDSA-P256 signature.
    ///
    /// # Errors
    /// Returns [`Err`] if the signature is invalid or the key is malformed.
    pub fn verify_p256(
        public_key_bytes: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureError> {
        let peer_pub = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_FIXED,
            public_key_bytes,
        );
        peer_pub
            .verify(message, signature)
            .map_err(|_| SignatureError::Verify)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_p256_sign_verify() {
        let kp = EcdsaKeyPair::generate_p256().unwrap();
        let msg = b"attest header lines";
        let sig = kp.sign(msg).unwrap();
        EcdsaKeyPair::verify_p256(&kp.public_key_der, msg, &sig).unwrap();
    }

    #[test]
    fn ecdsa_p256_tamper_fails() {
        let kp = EcdsaKeyPair::generate_p256().unwrap();
        let msg = b"original";
        let sig = kp.sign(msg).unwrap();
        assert!(EcdsaKeyPair::verify_p256(&kp.public_key_der, b"tampered", &sig).is_err());
    }
}
