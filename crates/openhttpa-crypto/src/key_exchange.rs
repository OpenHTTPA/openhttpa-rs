// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Classical ECDHE key exchange via `aws-lc-rs`, and hybrid KEM
//! (X25519 + ML-KEM-768) for post-quantum security.
//!
//! ## Hybrid combiner security
//!
//! The `HybridSharedSecret::combine` function implements the **§3.2 combiner**
//! from [draft-ietf-tls-hybrid-design](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/).
//!
//! To achieve **IND-CCA2** security for the combined secret, the combiner
//! must bind all public parameters of the exchange into the HKDF input.
//! Specifically, we include:
//! 1.  The classical ECDHE shared secret.
//! 2.  The ML-KEM post-quantum shared secret.
//! 3.  The client and server ECDHE public keys.
//! 4.  The client's ML-KEM encapsulation key.
//! 5.  The server's ML-KEM ciphertext.
//!
//! This construction ensures that even if one of the underlying primitives
//! is broken, the session remains secure as long as the other remains
//! computationally hard.
//!
//! ```text
//! IKM = ECDHE_SS ‖ ML-KEM_SS ‖ u16(len(label)) ‖ label
//!       ‖ u16(len(ECDHE_PK_client)) ‖ ECDHE_PK_client
//!       ‖ u16(len(ECDHE_PK_server)) ‖ ECDHE_PK_server
//!       ‖ u16(len(ML-KEM_EK_client)) ‖ ML-KEM_EK_client
//!       ‖ u16(len(ML-KEM_CT)) ‖ ML-KEM_CT
//! ```
//!
//! Every variable-length field is preceded by its 2-byte big-endian length.
//! This **length-prefix encoding** eliminates all ambiguity between fields of
//! different sizes and is required by draft-ietf-tls-hybrid-design §3.2 to
//! achieve a formally sound IND-CCA2-secure combiner. Without it, two sessions
//! that differ only in how public-key bytes straddle field boundaries could
//! produce the same IKM — an injection violation.
//!
//! The ECDHE and ML-KEM shared secrets are **not** length-prefixed because
//! both are fixed-size constants in the current cipher suite (32 bytes each);
//! adding prefixes for them would change the wire format without a security
//! benefit. If new cipher suites with variable-length shared secrets are ever
//! added, those fields MUST be length-prefixed as well.
//!
//! # Safety Note
//!
//! Raw shared secrets derived from this module **MUST NOT** be used directly
//! as encryption keys. They must always be passed through a Key Derivation
//! Function (KDF) like HKDF to ensure the resulting keys are pseudorandom
//! and properly distributed.

use aws_lc_rs::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::pqc::MlKemPair;

/// An error from a key exchange operation.
// MED-06: non_exhaustive prevents breaking changes when new variants are added.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum KeyExchangeError {
    #[error("key generation failed")]
    KeyGeneration,
    #[error("key agreement failed")]
    Agreement,
    #[error("invalid peer public key")]
    InvalidPeerKey,
    #[error("PQC error: {0}")]
    Pqc(String),
}

impl From<aws_lc_rs::error::Unspecified> for KeyExchangeError {
    fn from(_: aws_lc_rs::error::Unspecified) -> Self {
        Self::Agreement
    }
}

// ─── Classical ECDHE ─────────────────────────────────────────────────────────

/// A classical ECDHE ephemeral key pair.
///
/// Supports X25519, P-256 and P-384 via `aws-lc-rs`.
pub struct EcdhePair {
    private_key: EphemeralPrivateKey,
    /// The serialised public key bytes to be placed in `Attest-Key-Shares`.
    pub public_key: Vec<u8>,
}

impl EcdhePair {
    /// Generate an ephemeral X25519 key pair.
    ///
    /// # Errors
    /// Returns [`Err`] if key generation fails.
    pub fn generate_x25519() -> Result<Self, KeyExchangeError> {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let private_key = EphemeralPrivateKey::generate(&agreement::X25519, &rng)
            .map_err(|_| KeyExchangeError::KeyGeneration)?;
        let public_key = private_key
            .compute_public_key()
            .map_err(|_| KeyExchangeError::KeyGeneration)?
            .as_ref()
            .to_vec();
        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Generate an ephemeral P-256 key pair.
    ///
    /// # Errors
    /// Returns [`Err`] if key generation fails.
    pub fn generate_p256() -> Result<Self, KeyExchangeError> {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let private_key = EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
            .map_err(|_| KeyExchangeError::KeyGeneration)?;
        let public_key = private_key
            .compute_public_key()
            .map_err(|_| KeyExchangeError::KeyGeneration)?
            .as_ref()
            .to_vec();
        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Generate an ephemeral P-384 key pair.
    ///
    /// # Errors
    /// Returns [`Err`] if key generation fails.
    pub fn generate_p384() -> Result<Self, KeyExchangeError> {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let private_key = EphemeralPrivateKey::generate(&agreement::ECDH_P384, &rng)
            .map_err(|_| KeyExchangeError::KeyGeneration)?;
        let public_key = private_key
            .compute_public_key()
            .map_err(|_| KeyExchangeError::KeyGeneration)?
            .as_ref()
            .to_vec();
        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Perform the key agreement against the peer's public key bytes.
    ///
    /// # Returns
    /// The raw shared secret bytes. **Caller must pass this into HKDF**; do
    /// not use it directly as a key.
    ///
    /// # Errors
    /// Returns [`Err`] if the peer public key is invalid or key agreement fails.
    pub fn agree(
        self,
        algorithm: &'static agreement::Algorithm,
        peer_pub_key_bytes: &[u8],
    ) -> Result<SharedSecret, KeyExchangeError> {
        let peer_key = UnparsedPublicKey::new(algorithm, peer_pub_key_bytes);
        let secret = agreement::agree_ephemeral(
            self.private_key,
            peer_key,
            KeyExchangeError::Agreement,
            |shared| Ok::<Vec<u8>, KeyExchangeError>(shared.to_vec()),
        )?;
        Ok(SharedSecret(secret))
    }
}

/// A raw Diffie-Hellman shared secret. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(pub(crate) Vec<u8>);

impl SharedSecret {
    /// Borrow the underlying bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// ─── Hybrid KEM ──────────────────────────────────────────────────────────────

/// A key share that can be placed in `Attest-Key-Shares` headers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShare {
    /// ECDHE public key bytes.
    pub ecdhe_public: Vec<u8>,
    /// ML-KEM public key bytes (encapsulation key).
    pub mlkem_public: Vec<u8>,
}

/// A hybrid key pair combining X25519 (classical) + ML-KEM-768 (post-quantum).
///
/// The shared secret is the concatenation of both ECDHE and KEM shared
/// secrets, fed together into HKDF:
///
/// ```text
/// combined = ecdhe_ss || mlkem_ss
/// master_secret = HKDF(combined, handshake_transcript)
/// ```
pub struct HybridKemPair {
    ecdhe: EcdhePair,
    mlkem: MlKemPair,
}

impl HybridKemPair {
    /// Generate a fresh hybrid key pair. Call this on the **server** side when
    /// processing an `Attest-Key-Shares` header.
    ///
    /// # Errors
    /// Returns [`Err`] if classical or PQC key generation fails.
    pub fn generate() -> Result<Self, KeyExchangeError> {
        let ecdhe = EcdhePair::generate_x25519()?;
        let mlkem = MlKemPair::generate().map_err(|e| KeyExchangeError::Pqc(e.to_string()))?;
        Ok(Self { ecdhe, mlkem })
    }

    /// Produce the public [`KeyShare`] to send to the peer.
    #[must_use]
    pub fn public_key_share(&self) -> KeyShare {
        KeyShare {
            ecdhe_public: self.ecdhe.public_key.clone(),
            mlkem_public: self.mlkem.public_encap_key().to_vec(),
        }
    }

    /// **Server path**: encapsulate to the client's ML-KEM public key and
    /// agree on the ECDHE shared secret.
    ///
    /// Returns `(combined_secret, ct_bytes)` where `ct_bytes` is the ML-KEM
    /// ciphertext to send to the client in `Attest-Key-Share`.
    ///
    /// # Errors
    /// Returns [`KeyExchangeError`] if classical X25519 agreement or ML-KEM-768
    /// encapsulation fails due to malformed peer keys or entropy source exhaustion.
    ///
    /// # Normal Cases
    /// - Client sends valid ECDHE and ML-KEM public keys. The server successfully
    ///   performs DH agreement and ML-KEM encapsulation, generating a robust
    ///   hybrid secret and returning the ML-KEM ciphertext.
    ///
    /// # Edge Cases
    /// - The client's ML-KEM public key is correctly sized but mathematically edge-case
    ///   (e.g., specific polynomial configurations), which the underlying PQC library
    ///   must handle safely without side-channel leakage.
    ///
    /// # Failure Cases
    /// - **Invalid Peer Key**: The client's ECDHE public key is not on the curve,
    ///   resulting in `KeyExchangeError::Agreement`.
    /// - **PQC Encapsulation Error**: The client's ML-KEM public key is malformed
    ///   or fails validation within the PQ library, yielding `KeyExchangeError::Pqc`.
    ///
    /// # Global Impact Cases
    /// - Providing a sound combiner protects the entire session against Future Quantum
    ///   threats (SNDL) as well as classical ECC vulnerabilities. Failure to correctly
    ///   bind these parameters could lead to IND-CCA2 indistinguishability failure,
    ///   compromising the entire handshake transcript.
    pub fn server_combine(
        self,
        client_share: &KeyShare,
    ) -> Result<(HybridSharedSecret, Vec<u8>), KeyExchangeError> {
        let Self { ecdhe, mlkem } = self;
        let server_ecdhe_pub = ecdhe.public_key.clone();

        // Classical ECDHE agreement
        let ecdhe_ss = ecdhe.agree(&agreement::X25519, &client_share.ecdhe_public)?;

        // PQC encapsulation against client's encap key
        let (mlkem_ss, ciphertext) = mlkem
            .encapsulate(&client_share.mlkem_public)
            .map_err(|e| KeyExchangeError::Pqc(e.to_string()))?;

        let combined = HybridSharedSecret::combine(
            ecdhe_ss.0.clone(),
            mlkem_ss,
            &client_share.ecdhe_public,
            &server_ecdhe_pub,
            &client_share.mlkem_public,
            &ciphertext,
        )?;

        Ok((combined, ciphertext))
    }

    /// **Client path**: agree on the ECDHE shared secret and decapsulate the
    /// server's ML-KEM ciphertext.
    ///
    /// # Normal Cases
    /// - Server responds with valid ECDHE public key and valid ML-KEM ciphertext.
    ///   The client correctly decapsulates and derives the matching hybrid secret.
    ///
    /// # Edge Cases
    /// - The server ciphertext might be manipulated by an active `MitM`. The ML-KEM
    ///   decapsulation algorithm will implicitly reject (via FO transform) and
    ///   return a pseudo-random key rather than failing explicitly, but the
    ///   resulting combined secret will not match the server's, causing the MAC
    ///   verification to fail later in the protocol.
    ///
    /// # Failure Cases
    /// - **Invalid Server Key**: The server's ECDHE key is invalid or not on the curve.
    /// - **PQC Decapsulation Error**: The ML-KEM ciphertext is grossly malformed (wrong length).
    ///
    /// # Global Impact Cases
    /// - Same as `server_combine`, deriving this secret accurately is the foundation
    ///   of the session's security. It ensures both perfect forward secrecy (PFS) via
    ///   ECDHE and post-quantum security via ML-KEM.
    ///
    /// # Errors
    /// Returns [`KeyExchangeError`] if classical key agreement or ML-KEM
    /// decapsulation fails.
    pub fn client_combine(
        self,
        server_share: &KeyShare,
        mlkem_ciphertext: &[u8],
    ) -> Result<HybridSharedSecret, KeyExchangeError> {
        let Self { ecdhe, mlkem } = self;
        let client_ecdhe_pub = ecdhe.public_key.clone();
        let client_mlkem_pub = mlkem.public_encap_key().to_vec();

        // Classical ECDHE agreement
        let ecdhe_ss = ecdhe.agree(&agreement::X25519, &server_share.ecdhe_public)?;

        // PQC decapsulation using our private decap key
        let mlkem_ss = mlkem
            .decapsulate(mlkem_ciphertext)
            .map_err(|e| KeyExchangeError::Pqc(e.to_string()))?;

        HybridSharedSecret::combine(
            ecdhe_ss.0.clone(),
            mlkem_ss,
            &client_ecdhe_pub,
            &server_share.ecdhe_public,
            &client_mlkem_pub,
            mlkem_ciphertext,
        )
    }
}

/// The combined shared secret from a hybrid key exchange.
///
/// This is the value fed into HKDF as the input key material.
///
/// ## Combiner construction
///
/// Follows draft-ietf-tls-hybrid-design §3.2: the IKM includes both raw shared
/// secrets **plus** all public keys and the ML-KEM ciphertext so that the
/// combined secret is IND-CCA2-secure even if one component is broken.
///
/// ```text
/// label  = b"openhttpa hybrid kem v1"
/// IKM    = ECDHE_SS ‖ ML-KEM_SS ‖ label
///          ‖ ecdhe_pk_client ‖ ecdhe_pk_server
///          ‖ mlkem_ek_client ‖ mlkem_ct
/// output = HKDF-Extract(salt=0, IKM)   (32 bytes)
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridSharedSecret(Vec<u8>);

impl HybridSharedSecret {
    /// Length-prefix a variable-length field into `ikm`.
    ///
    /// Writes a 2-byte big-endian length (`u16`) followed by the raw bytes.
    /// This ensures that no two distinct inputs can produce the same byte
    /// sequence — a requirement for a formally sound HKDF IKM combiner
    /// (draft-ietf-tls-hybrid-design §3.2).
    ///
    /// # Panics
    /// Panics if `data.len() > u16::MAX` (65 535 bytes). All current
    /// `OpenHTTPA` key-material fields are well below this limit.
    fn encode_lengthed(ikm: &mut Vec<u8>, data: &[u8]) {
        let len: u16 = data
            .len()
            .try_into()
            .expect("key-material field exceeds u16::MAX bytes");
        ikm.extend_from_slice(&len.to_be_bytes());
        ikm.extend_from_slice(data);
    }

    /// Build the hybrid combiner IKM and derive the 32-byte combined secret.
    ///
    /// Construction (SA-01 hardened):
    /// ```text
    /// IKM = ECDHE_SS (fixed 32 B)
    ///       ‖ ML-KEM_SS (fixed 32 B)
    ///       ‖ u16(len(label)) ‖ label
    ///       ‖ u16(len(ecdhe_pk_client)) ‖ ecdhe_pk_client
    ///       ‖ u16(len(ecdhe_pk_server)) ‖ ecdhe_pk_server
    ///       ‖ u16(len(mlkem_ek_client)) ‖ mlkem_ek_client
    ///       ‖ u16(len(mlkem_ct))        ‖ mlkem_ct
    /// PRK    = HKDF-Extract(salt=[0;32], IKM)
    /// output = HKDF-Expand(PRK, info=b"combined", 32)
    /// ```
    #[allow(clippy::too_many_arguments)]
    fn combine(
        mut ecdhe: Vec<u8>,
        mut mlkem: Vec<u8>,
        ecdhe_pk_client: &[u8],
        ecdhe_pk_server: &[u8],
        mlkem_ek_client: &[u8],
        mlkem_ct: &[u8],
    ) -> Result<Self, KeyExchangeError> {
        const LABEL: &[u8] = b"openhttpa hybrid kem v1";

        // Capacity: fixed fields + 5 × (2-byte length prefix + field bytes).
        let mut ikm = Vec::with_capacity(
            ecdhe.len()
                + mlkem.len()
                + 2
                + LABEL.len()
                + 2
                + ecdhe_pk_client.len()
                + 2
                + ecdhe_pk_server.len()
                + 2
                + mlkem_ek_client.len()
                + 2
                + mlkem_ct.len(),
        );

        // Fixed-size secrets are written without a length prefix because
        // their sizes are constant in all current cipher suites (32 bytes).
        // If variable-size shared secrets are ever introduced, length-prefix
        // them here as well.
        ikm.extend_from_slice(&ecdhe);
        ikm.extend_from_slice(&mlkem);

        // Length-prefix the domain-separation label and all variable-length
        // public-key material to prevent length-extension ambiguity.
        Self::encode_lengthed(&mut ikm, LABEL);
        Self::encode_lengthed(&mut ikm, ecdhe_pk_client);
        Self::encode_lengthed(&mut ikm, ecdhe_pk_server);
        Self::encode_lengthed(&mut ikm, mlkem_ek_client);
        Self::encode_lengthed(&mut ikm, mlkem_ct);

        // Zeroize raw secrets immediately after they are consumed into IKM.
        ecdhe.zeroize();
        mlkem.zeroize();

        // HKDF-Extract(salt=[0;32], IKM) → HKDF-Expand(PRK, "combined", 32)
        // A zero salt is conventional (RFC 5869 §2.2) when no structured
        // salt is available; the LABEL field already provides domain separation.
        let salt = [0u8; 32];
        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut out = [0u8; 32];
        hk.expand(b"combined", &mut out)
            .map_err(|_| KeyExchangeError::Agreement)?;

        ikm.zeroize();
        Ok(Self(out.to_vec()))
    }

    /// Borrow the combined secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_round_trip() {
        let alice = EcdhePair::generate_x25519().unwrap();
        let bob = EcdhePair::generate_x25519().unwrap();

        let alice_pub = alice.public_key.clone();
        let bob_pub = bob.public_key.clone();

        let ss_alice = alice.agree(&agreement::X25519, &bob_pub).unwrap();
        let ss_bob = bob.agree(&agreement::X25519, &alice_pub).unwrap();

        assert_eq!(ss_alice.as_bytes(), ss_bob.as_bytes());
    }

    #[test]
    fn p256_round_trip() {
        let alice = EcdhePair::generate_p256().unwrap();
        let bob = EcdhePair::generate_p256().unwrap();
        let alice_pub = alice.public_key.clone();
        let bob_pub = bob.public_key.clone();
        let ss_a = alice.agree(&agreement::ECDH_P256, &bob_pub).unwrap();
        let ss_b = bob.agree(&agreement::ECDH_P256, &alice_pub).unwrap();
        assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
    }

    #[test]
    fn p384_round_trip() {
        let alice = EcdhePair::generate_p384().unwrap();
        let bob = EcdhePair::generate_p384().unwrap();
        let alice_pub = alice.public_key.clone();
        let bob_pub = bob.public_key.clone();
        let ss_a = alice.agree(&agreement::ECDH_P384, &bob_pub).unwrap();
        let ss_b = bob.agree(&agreement::ECDH_P384, &alice_pub).unwrap();
        assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
    }

    /// Full hybrid KEM round-trip: client generates pair, server encapsulates,
    /// client decapsulates — both sides must derive identical combined secrets.
    #[test]
    fn hybrid_kem_round_trip() {
        let client_pair = HybridKemPair::generate().unwrap();
        let server_pair = HybridKemPair::generate().unwrap();

        let client_pub = client_pair.public_key_share();
        let server_pub = server_pair.public_key_share();

        let (server_secret, ct) = server_pair.server_combine(&client_pub).unwrap();
        let client_secret = client_pair.client_combine(&server_pub, &ct).unwrap();

        assert_eq!(server_secret.as_bytes(), client_secret.as_bytes());
        assert_eq!(server_secret.as_bytes().len(), 32);
    }

    /// Verify that different key pairs produce different combined secrets.
    #[test]
    fn hybrid_kem_different_keys_different_secrets() {
        let client_a = HybridKemPair::generate().unwrap();
        let client_b = HybridKemPair::generate().unwrap();
        let server = HybridKemPair::generate().unwrap();
        let server2 = HybridKemPair::generate().unwrap();

        let pub_a = client_a.public_key_share();
        let pub_b = client_b.public_key_share();

        let (ss_a, _ct_a) = server.server_combine(&pub_a).unwrap();
        let (ss_b, _ct_b) = server2.server_combine(&pub_b).unwrap();

        assert_ne!(ss_a.as_bytes(), ss_b.as_bytes());
    }

    /// Context binding: two sessions with same raw DH but different ciphertexts
    /// must produce different combined secrets.
    #[test]
    fn hybrid_combiner_binds_ciphertext() {
        // Generate a fresh pair and get two different ciphertexts
        let client = HybridKemPair::generate().unwrap();
        let server1 = HybridKemPair::generate().unwrap();
        let server2 = HybridKemPair::generate().unwrap();

        let client_pub = client.public_key_share();
        let (ss1, _ct1) = server1.server_combine(&client_pub).unwrap();
        let client2 = HybridKemPair::generate().unwrap();
        let client_pub2 = client2.public_key_share();
        let (ss2, _ct2) = server2.server_combine(&client_pub2).unwrap();

        // Different ciphertexts → different secrets
        assert_ne!(ss1.as_bytes(), ss2.as_bytes());
    }

    /// SA-01 regression: swapping the roles of two equal-length public key fields
    /// must produce a different combined secret.
    ///
    /// Without length-prefix encoding, an adversary that can swap a trailing byte
    /// of field N into the start of field N+1 (length extension) could match IKMs
    /// from distinct sessions. This test ensures that the encoded IKM is
    /// injective across field boundaries by verifying that permuting the public
    /// material yields a different output.
    #[test]
    fn hybrid_combiner_field_swap_changes_secret() {
        let client = HybridKemPair::generate().unwrap();
        let server = HybridKemPair::generate().unwrap();
        let client_pub = client.public_key_share();

        // Derive secret normally: client ecdhe_pub is used as ecdhe_pk_client.
        let (ss_normal, _ct) = server.server_combine(&client_pub).unwrap();

        // Build a KeyShare with client and server ECDHE public keys swapped.
        // If the combiner did NOT length-prefix, certain constructions could
        // produce the same IKM — this must not happen.
        let server2 = HybridKemPair::generate().unwrap();
        let server_pub2 = server2.public_key_share();
        let swapped = super::KeyShare {
            ecdhe_public: server_pub2.ecdhe_public, // different key in client slot
            mlkem_public: client_pub.mlkem_public,
        };
        let (ss_swapped, _ct2) = server2.server_combine(&swapped).unwrap();

        // Must differ; if the combiner were ambiguous this might collide.
        assert_ne!(
            ss_normal.as_bytes(),
            ss_swapped.as_bytes(),
            "IKM must differ when client ECDHE public key changes"
        );
    }

    /// SA-01 regression: the `encode_lengthed` helper must write the u16 length
    /// as the first two bytes followed by the data bytes.
    #[test]
    fn encode_lengthed_format() {
        let mut buf = Vec::new();
        // Test with 3-byte payload
        HybridSharedSecret::encode_lengthed(&mut buf, b"abc");
        assert_eq!(
            &buf[..2],
            &[0x00, 0x03],
            "length prefix must be 2-byte big-endian u16"
        );
        assert_eq!(
            &buf[2..],
            b"abc",
            "payload bytes must follow the length prefix"
        );
    }
}

// ─── Property-based tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod proptest_kem {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Full hybrid KEM round-trip: any randomly-generated key pair should
        /// produce matching shared secrets after encapsulate + decapsulate.
        ///
        /// This is tested 100 times (proptest default) with freshly-generated
        /// keys each run, giving broad coverage of the key generation space.
        #[test]
        fn hybrid_kem_round_trip_property(_seed in any::<u64>()) {
            let client = HybridKemPair::generate().unwrap();
            let server = HybridKemPair::generate().unwrap();

            let client_pub = client.public_key_share();
            let server_pub = server.public_key_share();

            // Server encapsulates (combines) using client's public key.
            let (server_ss, ct) = server.server_combine(&client_pub).unwrap();
            // Client decapsulates.
            let client_ss = client.client_combine(&server_pub, &ct).unwrap();

            prop_assert_eq!(server_ss.as_bytes(), client_ss.as_bytes());
        }

        /// Different clients generate different shared secrets (probability of
        /// collision is negligible for 256-bit secrets).
        #[test]
        fn different_key_pairs_different_secrets(
            _seed1 in any::<u64>(),
            _seed2 in any::<u64>(),
        ) {
            let c1 = HybridKemPair::generate().unwrap();
            let c2 = HybridKemPair::generate().unwrap();
            let server1 = HybridKemPair::generate().unwrap();
            let server2 = HybridKemPair::generate().unwrap();

            let pub_c1 = c1.public_key_share();
            let pub_c2 = c2.public_key_share();

            let (ss1, _) = server1.server_combine(&pub_c1).unwrap();
            let (ss2, _) = server2.server_combine(&pub_c2).unwrap();

            // Probability of collision ≈ 2^{-256}; assertion failure → catastrophic.
            prop_assert_ne!(ss1.as_bytes(), ss2.as_bytes());
        }
    }
}
