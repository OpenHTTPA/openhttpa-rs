// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Pure-Rust crypto helpers matching the server-side IKM combiner.
//!
//! ## Hybrid combiner (mirrors `crates/openhttpa-crypto/src/key_exchange.rs`)
//!
//! ```text
//! label  = b"openhttpa hybrid kem v1"          (20 bytes)
//! IKM    = ECDHE_SS ‖ ML-KEM_SS ‖ label
//!          ‖ ecdhe_pk_client ‖ ecdhe_pk_server
//!          ‖ mlkem_ek_client ‖ mlkem_ek_server
//!          ‖ mlkem_ct
//! combined = HKDF-SHA256-Extract(salt=[0u8;32], IKM) → Expand("combined", 32)
//! ```
//!
//! ## Session key derivation (mirrors `crates/openhttpa-crypto/src/hkdf.rs`)
//!
//! ```text
//! PRK              = HKDF-SHA384-Extract(salt=b"openhttpa handshake v2", combined)
//! master_secret    = HKDF-Expand(PRK, transcript ‖ "master secret",    48 B)
//! client_write_key = HKDF-Expand(PRK, transcript ‖ "client write key", 32 B)
//! server_write_key = HKDF-Expand(PRK, transcript ‖ "server write key", 32 B)
//! client_write_iv  = HKDF-Expand(PRK, transcript ‖ "client write iv",  12 B)
//! server_write_iv  = HKDF-Expand(PRK, transcript ‖ "server write iv",  12 B)
//! ```

use hkdf::Hkdf;
use sha2::{Sha256, Sha384};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Derived `OpenHTTPA` session keys.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    pub master_secret: Vec<u8>,    // 48 B
    pub client_write_key: Vec<u8>, // 32 B  (AES-256-GCM)
    pub server_write_key: Vec<u8>, // 32 B
    pub client_write_iv: Vec<u8>,  // 12 B
    pub server_write_iv: Vec<u8>,  // 12 B
    pub client_mac_key: Vec<u8>,   // 32 B
    pub server_mac_key: Vec<u8>,   // 32 B
}

/// Length-prefix a variable-length field into `ikm`.
fn encode_lengthed(ikm: &mut Vec<u8>, data: &[u8]) {
    let len: u16 = data
        .len()
        .try_into()
        .expect("key-material field exceeds u16::MAX bytes");
    ikm.extend_from_slice(&len.to_be_bytes());
    ikm.extend_from_slice(data);
}

/// Produce the 32-byte combined `OpenHTTPA` hybrid secret.
///
/// This is a **byte-exact** port of `HybridSharedSecret::combine` (SA-01 hardened)
/// in the server crate, including length-prefix encoding for all variable fields.
pub fn combine(
    ecdhe_ss: &[u8],
    mlkem_ss: &[u8],
    ecdhe_pk_client: &[u8],
    ecdhe_pk_server: &[u8],
    mlkem_ek_client: &[u8],
    mlkem_ct: &[u8],
) -> [u8; 32] {
    const LABEL: &[u8] = b"openhttpa hybrid kem v1";

    // Capacity: fixed fields + 5 × (2-byte length prefix + field bytes).
    let mut ikm: Vec<u8> = Vec::with_capacity(
        ecdhe_ss.len()
            + mlkem_ss.len()
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

    // Fixed-size shared secrets (fixed 32 B) are written without prefixes.
    ikm.extend_from_slice(ecdhe_ss);
    ikm.extend_from_slice(mlkem_ss);

    // Length-prefix all public key material to prevent ambiguity.
    encode_lengthed(&mut ikm, LABEL);
    encode_lengthed(&mut ikm, ecdhe_pk_client);
    encode_lengthed(&mut ikm, ecdhe_pk_server);
    encode_lengthed(&mut ikm, mlkem_ek_client);
    encode_lengthed(&mut ikm, mlkem_ct);

    // HKDF-Extract(salt=[0u8;32], IKM) → Expand("combined", 32)
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &ikm);
    let mut combined = [0u8; 32];
    hk.expand(b"combined", &mut combined)
        .expect("HKDF-SHA256 expand to 32 bytes always succeeds");

    ikm.zeroize();
    combined
}

/// Derive `OpenHTTPA` session keys from the combined secret and transcript hash.
///
/// This is a byte-exact port of `SessionKeys::derive` (SA-02 hardened)
/// in the server crate, using the corrected salt and info structure.
pub fn derive_session_keys(combined: &[u8; 32], transcript_hash: &[u8]) -> SessionKeys {
    // RFC 5869 §2.2: use a zero-value salt of the hash length (48 B for SHA-384).
    const SALT: [u8; 48] = [0u8; 48];
    let hk = Hkdf::<Sha384>::new(Some(&SALT), combined);

    let expand = |label: &[u8], len: usize| -> Vec<u8> {
        const PREFIX: &[u8] = b"openhttpa_v2";
        // Format: PREFIX || label || \0 || transcript_hash
        let mut info = Vec::with_capacity(PREFIX.len() + label.len() + 1 + transcript_hash.len());
        info.extend_from_slice(PREFIX);
        info.extend_from_slice(label);
        info.push(0u8);
        info.extend_from_slice(transcript_hash);

        let mut out = vec![0u8; len];
        hk.expand(&info, &mut out)
            .expect("HKDF-SHA384 expand failed");
        out
    };

    SessionKeys {
        master_secret: expand(b"master secret", 48),
        client_write_key: expand(b"client write key", 32),
        server_write_key: expand(b"server write key", 32),
        client_write_iv: expand(b"client write iv", 12),
        server_write_iv: expand(b"server write iv", 12),
        client_mac_key: expand(b"client mac key", 32),
        server_mac_key: expand(b"server mac key", 32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke-test: combine() must produce 32 bytes deterministically.
    #[test]
    fn combine_is_deterministic() {
        let a = combine(
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
            &[4u8; 32],
            &[5u8; 1184],
            &[7u8; 1088],
        );
        let b = combine(
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
            &[4u8; 32],
            &[5u8; 1184],
            &[7u8; 1088],
        );
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    /// Smoke-test: different input must produce different output.
    #[test]
    fn combine_is_sensitive_to_input() {
        let a = combine(
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
            &[4u8; 32],
            &[5u8; 1184],
            &[7u8; 1088],
        );
        let b = combine(
            &[1u8; 32],
            &[9u8; 32], // changed mlkem_ss
            &[3u8; 32],
            &[4u8; 32],
            &[5u8; 1184],
            &[7u8; 1088],
        );
        assert_ne!(a, b);
    }

    #[test]
    fn session_keys_lengths() {
        let combined = combine(
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
            &[4u8; 32],
            &[5u8; 1184],
            &[7u8; 1088],
        );
        let transcript = [0u8; 48];
        let keys = derive_session_keys(&combined, &transcript);
        assert_eq!(keys.master_secret.len(), 48);
        assert_eq!(keys.client_write_key.len(), 32);
        assert_eq!(keys.server_write_key.len(), 32);
        assert_eq!(keys.client_write_iv.len(), 12);
        assert_eq!(keys.server_write_iv.len(), 12);
    }
}
