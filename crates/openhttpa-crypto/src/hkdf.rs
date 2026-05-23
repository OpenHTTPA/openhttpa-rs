// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! HKDF wrappers and session-key derivation for `OpenHTTPA`.
//!
//! ## SA-02 Key Schedule Correction (RFC 5869 Alignment)
//!
//! The `OpenHTTPA` session key schedule follows RFC 5869 and TLS 1.3 §7.1:
//!
//! ```text
//! PRK = HKDF-Extract(salt=[0;48], IKM=combined_hybrid_secret)
//!
//! For each derived key:
//!   output = HKDF-Expand(PRK, info=b"openhttpa v2 " || label || transcript_hash, len)
//! ```
//!
//! **Salt**: A zero-value byte string of the hash-length (48 bytes for SHA-384)
//! is conventional (RFC 5869 §2.2) when no session-specific salt is available.
//! The combined hybrid secret itself provides the entropy.
//!
//! **Info / domain separation**: The version prefix (`"openhttpa v2 "`) scopes all
//! derived keys to this protocol version, the `label` identifies the specific
//! key slot, and the `transcript_hash` binds the key to the exact handshake
//! transcript. Together they ensure no two key slots can collide even if the
//! IKM is the same across sessions.
//!
//! **IETF-01 / IANA registration TODO**: The HKDF label prefix `"openhttpa v2 "`
//! (and the per-slot labels used in [`SessionKeys::derive`]) should be
//! registered in the IANA "TLS Exporter Labels" registry (RFC 5705 §6) once
//! the `OpenHTTPA` specification advances to IETF Standards Track.  Until then,
//! the `"openhttpa "` prefix serves as a vendor prefix to avoid collisions.
//!
//! Previous versions incorrectly placed the ASCII label in the salt position
//! of HKDF-Extract. While this still produced pseudorandom outputs, it violated
//! the RFC and could confuse third-party implementations.
use hkdf::Hkdf;
use sha2::Sha384;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// HKDF errors.
#[derive(Debug, Error)]
pub enum HkdfError {
    #[error("HKDF extract failed")]
    ExtractFailed,
    #[error("HKDF expand failed (requested too many bytes)")]
    ExpandFailed,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HkdfExpander {
    /// R-03: Store only the 48-byte PRK (HKDF-Extract output), not the raw IKM.
    ///
    /// The raw IKM (combined hybrid secret) is a highly-sensitive input. Keeping
    /// it alive for the lifetime of `HkdfExpander` was unnecessary — after Extract,
    /// the PRK alone is needed for all Expand calls. The PRK is still secret but
    /// no longer contains the full IKM material; and it is zeroized on drop via
    /// the `ZeroizeOnDrop` derive.
    prk: Vec<u8>,
}

impl HkdfExpander {
    /// Extract a pseudorandom key using HMAC-SHA-384, storing only the PRK.
    ///
    /// The raw IKM is consumed by HKDF-Extract and is **not** retained.
    ///
    /// # Errors
    /// Returns [`Err`] if the salt or IKM are invalid for HMAC-SHA-384.
    pub fn extract_sha384(salt: &[u8], ikm: &[u8]) -> Result<Self, HkdfError> {
        let salt_opt = if salt.is_empty() { None } else { Some(salt) };
        let (prk, _hk) = Hkdf::<Sha384>::extract(salt_opt, ikm);
        Ok(Self { prk: prk.to_vec() })
    }

    /// Expand the pseudorandom key into a derived key of `out_len`.
    ///
    /// # Errors
    /// Returns [`Err`] if the output length is too large for HKDF.
    pub fn expand(&self, info: &[u8], out_len: usize) -> Result<DerivedKey, HkdfError> {
        let hk = Hkdf::<Sha384>::from_prk(&self.prk).map_err(|_| HkdfError::ExtractFailed)?;
        let mut out = vec![0u8; out_len];
        hk.expand(info, &mut out)
            .map_err(|_| HkdfError::ExpandFailed)?;
        Ok(DerivedKey(out))
    }
}

/// A derived key. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey(pub Vec<u8>);

impl DerivedKey {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the key and returns the raw bytes.
    ///
    /// WARNING: The caller is responsible for the security of the returned bytes.
    #[must_use]
    pub fn into_inner(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

// RUST-02: `SessionKeys` intentionally implements `Serialize`/`Deserialize`
// because it must round-trip through `SealedSessionKeys` (AEAD-encrypted
// at-rest tickets).  Direct serialisation to an *unencrypted* wire format is
// prevented at the call-site level: all public APIs that return session key
// material require a `SealedSessionKeys` wrapper.  If this type is ever
// exposed over a network without sealing, that is a misuse at the
// call site, not a structural flaw in the derive.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SessionKeys {
    pub master_secret: Vec<u8>,
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
    pub client_mac_key: Vec<u8>,
    pub server_mac_key: Vec<u8>,
    #[serde(with = "BigArray")]
    pub transcript_hash: [u8; 48],
}

impl SessionKeys {
    /// Derive all session keys from the combined hybrid secret and transcript hash.
    ///
    /// ## Key Schedule (SA-02 corrected, RFC 5869 §2.2 / TLS 1.3 §7.1 aligned)
    ///
    /// ```text
    /// PRK = HKDF-Extract(salt=[0;48], IKM=combined_secret)
    ///
    /// For each key slot:
    ///   output = HKDF-Expand(
    ///       PRK,
    ///       info = b"openhttpa v2 " || label || transcript_hash,
    ///       len,
    ///   )
    /// ```
    ///
    /// The zero salt is conventional for HKDF when no session-specific salt is
    /// available (RFC 5869 §2.2). The `combined_secret` provides all entropy.
    ///
    /// The `info` string binds each derived key to:
    ///   1. The protocol version (`"openhttpa v2 "`), preventing cross-protocol misuse.
    ///   2. The key slot label, preventing two slots from sharing a key.
    ///   3. The transcript hash, binding the key to this exact handshake exchange.
    ///
    /// **BREAKING CHANGE vs. pre-SA-02 builds**: keys derived by this function
    /// differ from those produced by the old (label-as-salt) code.  All endpoints
    /// MUST be updated simultaneously.
    ///
    /// # Errors
    /// Returns [`HkdfError`] if the underlying SHA-384 cryptographic provider fails
    /// during the HKDF extract or expand operations.
    ///
    /// # Normal Cases
    /// - Inputs are the correct combined secret length (32 bytes) and transcript
    ///   hash length (48 bytes). HKDF expands these uniformly into exactly 200
    ///   bytes of deterministic key material across 7 key slots.
    ///
    /// # Edge Cases
    /// - Two handshake sessions produce the same shared secret (astronomically
    ///   unlikely with 256-bit entropy). The `transcript_hash` includes the random
    ///   nonces, so the derived session keys will still be distinct, providing
    ///   cryptographic isolation.
    ///
    /// # Failure Cases
    /// - A failure in the underlying SHA-384 cryptographic provider (e.g. `aws-lc-rs`
    ///   FIPS boundary error) during extract or expand phases, returning `HkdfError`.
    ///
    /// # Global Impact Cases
    /// - These keys determine the AES-256-GCM secrecy and HMAC-SHA-384 integrity
    ///   for all subsequent data frames. Proper domain separation (prefix + label + null
    ///   terminator) prevents cross-protocol attacks and ensures no two keys can ever
    ///   collide.
    pub fn derive(combined_secret: &[u8], transcript_hash: &[u8]) -> Result<Self, HkdfError> {
        // RFC 5869 §2.2: use a zero-value salt of the hash length (48 B for SHA-384)
        // when no external salt is available.  The version label and transcript hash
        // in each Expand info string supply all necessary domain separation.
        const SALT: [u8; 48] = [0u8; 48];
        let expander = HkdfExpander::extract_sha384(&SALT, combined_secret)?;

        // Format:  b"openhttpa v2 "  (10 B, protocol-version prefix)
        //       || label           (variable, key-slot name)
        //       || b"\0"           (1 B, O-01 null separator)
        //       || transcript_hash (fixed 48 B, session binding)
        // `transcript_hash` is always exactly 48 bytes (SHA-384). The null
        // separator ensures that even if labels were to overlap prefixes
        // (e.g. "key" vs "key_iv"), they are parsed as distinct info strings.
        let make_info = |label: &[u8]| -> Vec<u8> {
            const PREFIX: &[u8] = b"openhttpa v2 ";
            let mut v = Vec::with_capacity(PREFIX.len() + label.len() + transcript_hash.len() + 1);
            v.extend_from_slice(PREFIX);
            v.extend_from_slice(label);
            v.push(0u8);
            v.extend_from_slice(transcript_hash);
            v
        };

        let master_secret = expander
            .expand(&make_info(b"master secret"), 48)?
            .into_inner();
        let client_write_key = expander
            .expand(&make_info(b"client write key"), 32)?
            .into_inner();
        let server_write_key = expander
            .expand(&make_info(b"server write key"), 32)?
            .into_inner();
        let client_write_iv = expander
            .expand(&make_info(b"client write iv"), 12)?
            .into_inner();
        let server_write_iv = expander
            .expand(&make_info(b"server write iv"), 12)?
            .into_inner();
        let client_mac_key = expander
            .expand(&make_info(b"client mac key"), 32)?
            .into_inner();
        let server_mac_key = expander
            .expand(&make_info(b"server mac key"), 32)?
            .into_inner();

        let mut transcript_hash_arr = [0u8; 48];
        transcript_hash_arr.copy_from_slice(transcript_hash);

        Ok(Self {
            master_secret,
            client_write_key,
            server_write_key,
            client_write_iv,
            server_write_iv,
            client_mac_key,
            server_mac_key,
            transcript_hash: transcript_hash_arr,
        })
    }

    /// Derive 0-RTT session keys from a resumed master secret and a fresh salt.
    ///
    /// ## 0-RTT Key Schedule (PQ-Resumption)
    ///
    /// ```text
    /// PRK = HKDF-Extract(salt=rtt0_salt, IKM=resumed_master_secret)
    ///
    /// For each key slot:
    ///   output = HKDF-Expand(
    ///       PRK,
    ///       info = b"openhttpa v2 0rtt " || label || rtt0_salt,
    ///       len,
    ///   )
    /// ```
    ///
    /// # Errors
    /// Returns [`HkdfError`] if HKDF operations fail.
    pub fn derive_0rtt(
        resumed_master_secret: &[u8],
        rtt0_salt: &[u8; 16],
    ) -> Result<Self, HkdfError> {
        let expander = HkdfExpander::extract_sha384(rtt0_salt, resumed_master_secret)?;

        let make_info = |label: &[u8]| -> Vec<u8> {
            const PREFIX: &[u8] = b"openhttpa v2 0rtt ";
            let mut v = Vec::with_capacity(PREFIX.len() + label.len() + rtt0_salt.len() + 1);
            v.extend_from_slice(PREFIX);
            v.extend_from_slice(label);
            v.push(0u8);
            v.extend_from_slice(rtt0_salt);
            v
        };

        // 0-RTT uses the same slots but with a different prefix and salt for domain separation.
        let master_secret = expander
            .expand(&make_info(b"master secret"), 48)?
            .into_inner();
        let client_write_key = expander
            .expand(&make_info(b"client write key"), 32)?
            .into_inner();
        let server_write_key = expander
            .expand(&make_info(b"server write key"), 32)?
            .into_inner();
        let client_write_iv = expander
            .expand(&make_info(b"client write iv"), 12)?
            .into_inner();
        let server_write_iv = expander
            .expand(&make_info(b"server write iv"), 12)?
            .into_inner();
        let client_mac_key = expander
            .expand(&make_info(b"client mac key"), 32)?
            .into_inner();
        let server_mac_key = expander
            .expand(&make_info(b"server mac key"), 32)?
            .into_inner();

        let mut transcript_hash_arr = [0u8; 48];
        transcript_hash_arr[..16].copy_from_slice(rtt0_salt);

        Ok(Self {
            master_secret,
            client_write_key,
            server_write_key,
            client_write_iv,
            server_write_iv,
            client_mac_key,
            server_mac_key,
            transcript_hash: transcript_hash_arr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SA-02 regression: same inputs must always produce identical keys (determinism).
    #[test]
    fn session_keys_are_deterministic() {
        let secret = [0x42u8; 32];
        let transcript = [0xABu8; 48];
        let k1 = SessionKeys::derive(&secret, &transcript).unwrap();
        let k2 = SessionKeys::derive(&secret, &transcript).unwrap();
        assert_eq!(k1.client_write_key, k2.client_write_key);
        assert_eq!(k1.server_write_key, k2.server_write_key);
        assert_eq!(k1.client_write_iv, k2.client_write_iv);
        assert_eq!(k1.master_secret.len(), 48);
    }

    /// SA-02 regression: different transcripts MUST yield different key material
    /// even for the same combined secret — transcript binding is the invariant.
    #[test]
    fn different_transcripts_produce_different_keys() {
        let secret = [0x99u8; 32];
        let t1 = [0x01u8; 48];
        let t2 = [0x02u8; 48];
        let k1 = SessionKeys::derive(&secret, &t1).unwrap();
        let k2 = SessionKeys::derive(&secret, &t2).unwrap();
        assert_ne!(
            k1.client_write_key, k2.client_write_key,
            "different transcripts must yield different keys"
        );
        assert_ne!(k1.server_write_key, k2.server_write_key);
        assert_ne!(k1.client_write_iv, k2.client_write_iv);
    }

    /// SA-02 regression: every key slot must be distinct for the same session —
    /// no two slots may share bytes (label domain separation).
    #[test]
    fn all_key_slots_are_distinct() {
        let secret = [0x11u8; 32];
        let transcript = [0xCCu8; 48];
        let k = SessionKeys::derive(&secret, &transcript).unwrap();

        // All 32-byte keys must be pairwise distinct.
        let keys: &[&[u8]] = &[
            &k.client_write_key,
            &k.server_write_key,
            &k.client_mac_key,
            &k.server_mac_key,
        ];
        for (i, a) in keys.iter().enumerate() {
            for (j, b) in keys.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "key slot {i} must differ from slot {j}");
                }
            }
        }
        // IVs must differ from each other.
        assert_ne!(k.client_write_iv, k.server_write_iv);
        // Sizes must be correct.
        assert_eq!(k.client_write_iv.len(), 12);
        assert_eq!(k.server_write_iv.len(), 12);
        assert_eq!(k.client_write_key.len(), 32);
        assert_eq!(k.master_secret.len(), 48);
    }

    /// SA-02 regression: the corrected schedule produces DIFFERENT keys than the
    /// old (label-as-salt) implementation.  This explicitly documents the
    /// intentional wire-format break so no future refactor silently reverts it.
    #[test]
    fn new_schedule_differs_from_old_label_as_salt() {
        let secret = [0xFFu8; 32];
        let transcript = [0x00u8; 48];

        // New (corrected) derivation.
        let new_keys = SessionKeys::derive(&secret, &transcript).unwrap();

        // Manually replicate the old (broken) derivation:
        //   extract_sha384(salt=b"openhttpa handshake v2", ikm=secret)
        //   expand(info=transcript || b"client write key", 32)
        let old_expander =
            HkdfExpander::extract_sha384(b"openhttpa handshake v2", &secret).unwrap();
        let mut old_info = transcript.to_vec();
        old_info.extend_from_slice(b"client write key");
        let old_client_key = old_expander.expand(&old_info, 32).unwrap();

        assert_ne!(
            new_keys.client_write_key,
            old_client_key.as_bytes(),
            "SA-02 fix must produce different key material (intentional wire break)"
        );
    }
}
