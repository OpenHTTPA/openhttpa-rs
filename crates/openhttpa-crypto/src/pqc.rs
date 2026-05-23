// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Post-quantum KEM and signature primitives via `oqs` (liboqs).
//!
//! # Security note
//! The `oqs` crate wraps liboqs, which the Open Quantum Safe project
//! documents as "intended for prototyping and evaluation" rather than
//! production deployment. Monitor upstream liboqs releases for hardened
//! versions. Hybrid classical + PQC use (the default `OpenHTTPA` cipher suites)
//! ensures that security degrades to classical levels if the PQC primitive is
//! ever broken rather than failing completely.
//!
//! # NIST-01: ML-DSA (`MlDsaKeyPair`) migration note
//! `MlDsaKeyPair` is currently backed by `oqs` (liboqs ML-DSA-65).
//! Once `aws-lc-rs` ships stable ML-DSA support (tracked at
//! <https://github.com/aws/aws-lc-rs/issues/532>), migrate to the
//! `aws-lc-rs` provider to benefit from FIPS boundary validation and the
//! same hardware-accelerated code path as the classical primitives.
//! Changing only this module (swapping the `oqs::sig` call for the
//! `aws_lc_rs::signature` equivalent) is sufficient; the rest of the
//! codebase is decoupled through `MlDsaKeyPair`.

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Errors from PQC operations.
// MED-06: non_exhaustive prevents breaking changes when new variants are added.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum PqcError {
    #[error("KEM key generation failed: {0}")]
    KemKeyGen(String),
    #[error("KEM encapsulation failed: {0}")]
    KemEncap(String),
    #[error("KEM decapsulation failed: {0}")]
    KemDecap(String),
    #[error("signature key generation failed: {0}")]
    SigKeyGen(String),
    #[error("signature operation failed: {0}")]
    Sign(String),
    #[error("signature verification failed")]
    Verify,
}

// ─── ML-KEM (CRYSTALS-Kyber) ─────────────────────────────────────────────────

/// An ML-KEM-768 key pair for key encapsulation.
///
/// The encapsulation key is the "public key" sent to the peer. The
/// decapsulation key is secret and zeroized on drop.
///
/// RUST-03: `oqs::kem::SecretKey` does not implement `ZeroizeOnDrop`.
/// The `Drop` impl below explicitly overwrites the key bytes via
/// `oqs::kem::SecretKey::into_vec()` and then zeroizes the resulting
/// `Vec<u8>` so the secret is cleared from memory when this struct is
/// dropped, providing defense-in-depth beyond what `oqs` guarantees.
pub struct MlKemPair {
    kem: oqs::kem::Kem,
    decap_key: Option<oqs::kem::SecretKey>,
    encap_key: oqs::kem::PublicKey,
}

impl Drop for MlKemPair {
    // `raw` is intentionally written-to (zeroized) but never read back.
    // clippy::collection_is_never_read does not understand security-motivated writes.
    #[allow(clippy::collection_is_never_read)]
    fn drop(&mut self) {
        if let Some(key) = self.decap_key.take() {
            // Consume the SecretKey and zeroize the underlying bytes so the
            // secret material does not linger in memory after this value is
            // dropped (RUST-03 defense-in-depth; oqs does not guarantee this).
            let mut raw = key.into_vec();
            Zeroize::zeroize(&mut raw);
        }
    }
}

impl MlKemPair {
    /// Generate a new ML-KEM-768 ephemeral key pair.
    ///
    /// # Errors
    /// Returns [`Err`] if the KEM algorithm is unavailable or key generation fails.
    pub fn generate() -> Result<Self, PqcError> {
        let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem768)
            .map_err(|e| PqcError::KemKeyGen(e.to_string()))?;
        let (encap_key, decap_key) = kem
            .keypair()
            .map_err(|e| PqcError::KemKeyGen(e.to_string()))?;
        Ok(Self {
            kem,
            decap_key: Some(decap_key),
            encap_key,
        })
    }

    /// Return the encapsulation (public) key bytes.
    #[must_use]
    pub fn public_encap_key(&self) -> &[u8] {
        self.encap_key.as_ref()
    }

    /// Encapsulate against a peer's encapsulation key.
    ///
    /// Returns `(shared_secret_bytes, ciphertext_bytes)`.
    ///
    /// # Errors
    /// Returns [`Err`] if the peer key is malformed or encapsulation fails.
    pub fn encapsulate(&self, peer_encap_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PqcError> {
        let peer_key = self
            .kem
            .public_key_from_bytes(peer_encap_key)
            .ok_or_else(|| PqcError::KemEncap("invalid peer encap key".to_owned()))?;
        let (ciphertext, shared_secret) = self
            .kem
            .encapsulate(peer_key)
            .map_err(|e| PqcError::KemEncap(e.to_string()))?;
        Ok((shared_secret.into_vec(), ciphertext.into_vec()))
    }

    /// Decapsulate a ciphertext using this pair's decapsulation key.
    ///
    /// Returns the shared secret bytes.
    ///
    /// # Errors
    /// Returns [`Err`] if the ciphertext is malformed or decapsulation fails.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, PqcError> {
        let ct = self
            .kem
            .ciphertext_from_bytes(ciphertext)
            .ok_or_else(|| PqcError::KemDecap("invalid ciphertext".to_owned()))?;
        let decap_key = self
            .decap_key
            .as_ref()
            .ok_or_else(|| PqcError::KemDecap("decap key already dropped".to_owned()))?;
        let ss = self
            .kem
            .decapsulate(decap_key, ct)
            .map_err(|e| PqcError::KemDecap(e.to_string()))?;
        Ok(ss.into_vec())
    }
}

// ─── ML-DSA (CRYSTALS-Dilithium) ─────────────────────────────────────────────

/// An ML-DSA-65 key pair for post-quantum digital signatures.
///
/// SEC-DSA-01: `oqs::sig::SecretKey` does not implement `ZeroizeOnDrop`.
/// The `Drop` impl below explicitly overwrites the key bytes via
/// `oqs::sig::SecretKey::into_vec()` and then zeroizes the resulting
/// `Vec<u8>` so the secret is cleared from memory when this struct is
/// dropped, mirroring the defense-in-depth pattern of `MlKemPair`.
pub struct MlDsaKeyPair {
    sig: oqs::sig::Sig,
    secret_key: Option<oqs::sig::SecretKey>,
    /// Serialised public key bytes.
    pub public_key: Vec<u8>,
}

impl Drop for MlDsaKeyPair {
    // `raw` is intentionally written-to (zeroized) but never read back.
    // clippy::collection_is_never_read does not understand security-motivated writes.
    #[allow(clippy::collection_is_never_read)]
    fn drop(&mut self) {
        if let Some(key) = self.secret_key.take() {
            // Consume the SecretKey and zeroize the underlying bytes so the
            // secret material does not linger in memory after this value is
            // dropped (SEC-DSA-01 defense-in-depth; oqs does not guarantee this).
            let mut raw = key.into_vec();
            Zeroize::zeroize(&mut raw);
        }
    }
}

impl MlDsaKeyPair {
    /// Generate a new ML-DSA-65 key pair.
    ///
    /// # Errors
    /// Returns [`Err`] if the signature algorithm is unavailable or key generation fails.
    pub fn generate() -> Result<Self, PqcError> {
        let sig = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65)
            .map_err(|e| PqcError::SigKeyGen(e.to_string()))?;
        let (public_key, secret_key) = sig
            .keypair()
            .map_err(|e| PqcError::SigKeyGen(e.to_string()))?;
        Ok(Self {
            sig,
            secret_key: Some(secret_key),
            public_key: public_key.into_vec(),
        })
    }

    /// Sign `message` and return the signature bytes.
    ///
    /// # Errors
    /// Returns [`Err`] if the signing operation fails.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PqcError> {
        let secret_key = self
            .secret_key
            .as_ref()
            .ok_or_else(|| PqcError::Sign("secret key already dropped".to_owned()))?;
        let sig = self
            .sig
            .sign(message, secret_key)
            .map_err(|e| PqcError::Sign(e.to_string()))?;
        Ok(sig.into_vec())
    }

    /// Verify a signature against `public_key_bytes`.
    ///
    /// # Errors
    /// Returns [`Err`] if the signature is invalid or key bytes are malformed.
    pub fn verify(
        public_key_bytes: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), PqcError> {
        let algorithm = oqs::sig::Algorithm::MlDsa65;
        let sig = oqs::sig::Sig::new(algorithm).map_err(|e| PqcError::SigKeyGen(e.to_string()))?;
        let pk = sig
            .public_key_from_bytes(public_key_bytes)
            .ok_or(PqcError::Verify)?;
        let s = sig
            .signature_from_bytes(signature)
            .ok_or(PqcError::Verify)?;
        sig.verify(message, s, pk).map_err(|_| PqcError::Verify)
    }
}

// ─── Wrapped shared-secret from PQC KEM ──────────────────────────────────────

/// A raw ML-KEM shared secret. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlKemSharedSecret(Vec<u8>);

impl MlKemSharedSecret {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlkem_round_trip() {
        let alice = MlKemPair::generate().unwrap();
        let bob = MlKemPair::generate().unwrap();

        let (ss_alice, ct) = bob.encapsulate(alice.public_encap_key()).unwrap();
        let ss_bob = alice.decapsulate(&ct).unwrap();

        assert_eq!(ss_alice, ss_bob);
    }

    #[test]
    fn mldsa_sign_verify() {
        let kp = MlDsaKeyPair::generate().unwrap();
        let msg = b"`OpenHTTPA` handshake transcript";
        let sig = kp.sign(msg).unwrap();
        MlDsaKeyPair::verify(&kp.public_key, msg, &sig).unwrap();
    }

    #[test]
    fn mldsa_wrong_message_fails() {
        let kp = MlDsaKeyPair::generate().unwrap();
        let msg = b"original";
        let sig = kp.sign(msg).unwrap();
        let result = MlDsaKeyPair::verify(&kp.public_key, b"tampered", &sig);
        assert!(result.is_err());
    }
}
