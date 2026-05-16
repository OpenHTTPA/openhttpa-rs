// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! AEAD encryption and decryption using AES-256-GCM and ChaCha20-Poly1305
//! via `aws-lc-rs`.
//!
//! ## Nonce safety
//!
//! `AeadKey` is a low-level primitive that accepts a caller-supplied nonce.
//! For session-level encryption use `BoundAeadKey`, which owns a monotonic
//! counter and an IV, constructs nonces via TLS 1.3 §5.3 XOR construction,
//! and rejects any attempt to reuse a nonce (overflow → session must be
//! renegotiated).

use std::sync::atomic::{AtomicU64, Ordering};

pub use aws_lc_rs::aead::NONCE_LEN;
use aws_lc_rs::aead::{self, Aad, BoundKey, LessSafeKey, Nonce, SealingKey, UnboundKey};
use fs2::FileExt;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// AEAD algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    /// AES-256-GCM (recommended; hardware-accelerated on x86-64 / `AArch64`).
    Aes256Gcm,
    /// ChaCha20-Poly1305 (good on platforms without AES hardware).
    ChaCha20Poly1305,
}

impl AeadAlgorithm {
    const fn aws_algorithm(self) -> &'static aead::Algorithm {
        match self {
            Self::Aes256Gcm => &aead::AES_256_GCM,
            Self::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }

    /// Key length in bytes (32 for both supported algorithms).
    #[must_use]
    pub const fn key_len(self) -> usize {
        32
    }
}

/// AEAD errors.
// MED-06: non_exhaustive prevents breaking changes when new variants are added.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum AeadError {
    #[error("AEAD key construction failed")]
    KeyConstruction,
    #[error("AEAD seal (encrypt) failed")]
    SealFailed,
    #[error("AEAD open (decrypt + verify) failed — ciphertext is corrupted or tampered")]
    OpenFailed,
    #[error("nonce length must be exactly {NONCE_LEN} bytes")]
    InvalidNonceLength,
    #[error("I/O or system error: {0}")]
    IoError(String),
}

/// A 12-byte AEAD nonce. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AeadNonce(pub [u8; NONCE_LEN]);

impl AeadNonce {
    /// Build from a 12-byte slice.
    ///
    /// # Errors
    /// Returns [`Err`] if `b` is not exactly 12 bytes.
    pub fn from_slice(b: &[u8]) -> Result<Self, AeadError> {
        b.try_into()
            .map(Self)
            .map_err(|_| AeadError::InvalidNonceLength)
    }
}

/// An AEAD key. Zeroized on drop.
pub struct AeadKey {
    raw: Vec<u8>,
    algorithm: AeadAlgorithm,
}

impl zeroize::Zeroize for AeadKey {
    fn zeroize(&mut self) {
        self.raw.zeroize();
    }
}

impl Drop for AeadKey {
    fn drop(&mut self) {
        self.raw.zeroize();
    }
}

impl AeadKey {
    /// Construct from raw key bytes.
    ///
    /// `key_bytes` must be 32 bytes for both AES-256-GCM and ChaCha20-Poly1305.
    ///
    /// # Errors
    /// Returns [`Err`] if `key_bytes` has an invalid length for the algorithm.
    pub fn new(algorithm: AeadAlgorithm, key_bytes: &[u8]) -> Result<Self, AeadError> {
        // Validate by constructing and discarding an UnboundKey.
        UnboundKey::new(algorithm.aws_algorithm(), key_bytes)
            .map_err(|_| AeadError::KeyConstruction)?;
        Ok(Self {
            raw: key_bytes.to_vec(),
            algorithm,
        })
    }

    /// Encrypt `plaintext` in place, appending the authentication tag.
    ///
    /// `aad` is authenticated but **not** encrypted.
    /// Returns the nonce used (must be sent to the peer alongside the
    /// ciphertext).
    ///
    /// # Errors
    /// Returns [`Err`] if key construction or the AEAD seal operation fails.
    pub fn seal_in_place(
        &self,
        nonce: &AeadNonce,
        aad: &[u8],
        data: &mut Vec<u8>,
    ) -> Result<(), AeadError> {
        let unbound = UnboundKey::new(self.algorithm.aws_algorithm(), &self.raw)
            .map_err(|_| AeadError::KeyConstruction)?;
        let nonce_seq = SingleUseNonce(Some(Nonce::assume_unique_for_key(nonce.0)));
        let mut sealing_key = SealingKey::new(unbound, nonce_seq);
        sealing_key
            .seal_in_place_append_tag(Aad::from(aad), data)
            .map_err(|_| AeadError::SealFailed)
    }

    /// Decrypt `ciphertext_with_tag` in place, verifying the authentication tag.
    ///
    /// Returns a slice of the plaintext within `ciphertext_with_tag`.
    ///
    /// # Errors
    /// Returns [`Err`] if key construction fails or authentication/decryption fails.
    pub fn open_in_place<'a>(
        &self,
        nonce: &AeadNonce,
        aad: &[u8],
        ciphertext_with_tag: &'a mut [u8],
    ) -> Result<&'a [u8], AeadError> {
        let unbound = UnboundKey::new(self.algorithm.aws_algorithm(), &self.raw)
            .map_err(|_| AeadError::KeyConstruction)?;
        let nonce_value = Nonce::assume_unique_for_key(nonce.0);
        let less_safe = LessSafeKey::new(unbound);
        let plaintext = less_safe
            .open_in_place(nonce_value, Aad::from(aad), ciphertext_with_tag)
            .map_err(|_| AeadError::OpenFailed)?;
        Ok(plaintext)
    }
}

struct SingleUseNonce(Option<Nonce>);

impl aead::NonceSequence for SingleUseNonce {
    fn advance(&mut self) -> Result<Nonce, aws_lc_rs::error::Unspecified> {
        self.0.take().ok_or(aws_lc_rs::error::Unspecified)
    }
}

// ─── Nonce-safe bound key ─────────────────────────────────────────────────────

/// AEAD errors specific to `BoundAeadKey`.
#[derive(Debug, Error)]
pub enum BoundAeadError {
    #[error("nonce counter overflowed — session must be renegotiated")]
    NonceOverflow,
    #[error("AEAD operation failed: {0}")]
    Aead(#[from] AeadError),
}

/// A sequence of nonces for use with a `BoundAeadKey`.
pub trait NonceSequence: Send + Sync {
    /// Generate the next nonce by combining the sequence counter with the IV.
    ///
    /// # Errors
    /// Returns [`Err`] if the counter overflows.
    fn next_nonce(&self, iv: &[u8; NONCE_LEN]) -> Result<AeadNonce, BoundAeadError>;
}

/// A standard in-memory atomic nonce counter.
pub struct AtomicNonceSequence {
    counter: AtomicU64,
}

impl AtomicNonceSequence {
    #[must_use]
    pub const fn new(start: u64) -> Self {
        Self {
            counter: AtomicU64::new(start),
        }
    }
}

impl NonceSequence for AtomicNonceSequence {
    fn next_nonce(&self, iv: &[u8; NONCE_LEN]) -> Result<AeadNonce, BoundAeadError> {
        loop {
            let count = self.counter.load(Ordering::SeqCst);
            if count == u64::MAX {
                return Err(BoundAeadError::NonceOverflow);
            }
            if self
                .counter
                .compare_exchange(count, count + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                let mut nonce = *iv;
                let counter_bytes = count.to_be_bytes();
                for (n, c) in nonce[4..].iter_mut().zip(counter_bytes.iter()) {
                    *n ^= c;
                }
                return Ok(AeadNonce(nonce));
            }
        }
    }
}

/// A durable file-backed nonce counter.
///
/// Ensures that the counter is persisted to disk before returning a nonce,
/// protecting against replay attacks even if the process restarts.
pub struct FileNonceSequence {
    path: PathBuf,
    mutex: Mutex<()>,
}

impl FileNonceSequence {
    /// Open or create a nonce file at `path`.
    ///
    /// # Errors
    /// Returns [`Err`] if the file cannot be opened or locked.
    pub fn new(path: PathBuf) -> Result<Self, std::io::Error> {
        let _file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        Ok(Self {
            path,
            mutex: Mutex::new(()),
        })
    }

    fn read_counter(file: &mut std::fs::File) -> Result<u64, std::io::Error> {
        let mut buf = [0u8; 8];
        file.seek(SeekFrom::Start(0))?;
        match file.read_exact(&mut buf) {
            Ok(()) => Ok(u64::from_be_bytes(buf)),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(1),
            Err(e) => Err(e),
        }
    }

    fn write_counter(file: &mut std::fs::File, counter: u64) -> Result<(), std::io::Error> {
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&counter.to_be_bytes())?;
        file.sync_all()?;
        Ok(())
    }
}

impl NonceSequence for FileNonceSequence {
    fn next_nonce(&self, iv: &[u8; NONCE_LEN]) -> Result<AeadNonce, BoundAeadError> {
        let _guard = self.mutex.lock().unwrap();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.path)
            .map_err(|e| AeadError::IoError(e.to_string()))?;

        file.lock_exclusive()
            .map_err(|e| AeadError::IoError(format!("lock failed: {e}")))?;

        let count = Self::read_counter(&mut file)
            .map_err(|e| AeadError::IoError(format!("read failed: {e}")))?;

        if count == u64::MAX {
            let _ = FileExt::unlock(&file);
            return Err(BoundAeadError::NonceOverflow);
        }

        Self::write_counter(&mut file, count + 1)
            .map_err(|e| AeadError::IoError(format!("write failed: {e}")))?;

        let _ = FileExt::unlock(&file);

        let mut nonce = *iv;
        let counter_bytes = count.to_be_bytes();
        for (n, c) in nonce[4..].iter_mut().zip(counter_bytes.iter()) {
            *n ^= c;
        }
        Ok(AeadNonce(nonce))
    }
}

/// A session-level AEAD key that owns its nonce sequence.
///
/// Nonces are typically constructed following TLS 1.3 §5.3:
/// ```text
/// nonce = write_iv XOR (counter as big-endian 64-bit, right-aligned in 12 bytes)
/// ```
pub struct BoundAeadKey {
    key: AeadKey,
    write_iv: [u8; NONCE_LEN],
    sequence: Box<dyn NonceSequence>,
}

impl BoundAeadKey {
    /// Construct from a raw key and the write IV derived from HKDF.
    ///
    /// # Errors
    /// Returns [`Err`] if the key bytes are invalid for the chosen algorithm.
    pub fn new(
        algorithm: AeadAlgorithm,
        key_bytes: &[u8],
        write_iv: [u8; NONCE_LEN],
    ) -> Result<Self, AeadError> {
        Ok(Self {
            key: AeadKey::new(algorithm, key_bytes)?,
            write_iv,
            sequence: Box::new(AtomicNonceSequence::new(1)),
        })
    }

    /// Construct with a custom nonce sequence (e.g. for persistence).
    ///
    /// # Errors
    /// Returns [`Err`] if the key bytes are invalid for the chosen algorithm.
    pub fn with_sequence(
        algorithm: AeadAlgorithm,
        key_bytes: &[u8],
        write_iv: [u8; NONCE_LEN],
        sequence: Box<dyn NonceSequence>,
    ) -> Result<Self, AeadError> {
        Ok(Self {
            key: AeadKey::new(algorithm, key_bytes)?,
            write_iv,
            sequence,
        })
    }

    /// Encrypt `data` in place. Returns the nonce used (send alongside ciphertext).
    ///
    /// # Errors
    /// Returns [`Err`] if the nonce counter overflows or the AEAD seal fails.
    pub fn seal(&self, aad: &[u8], data: &mut Vec<u8>) -> Result<AeadNonce, BoundAeadError> {
        let nonce = self.sequence.next_nonce(&self.write_iv)?;
        self.key.seal_in_place(&nonce, aad, data)?;
        Ok(nonce)
    }

    /// Decrypt `data` in place using an externally-supplied nonce.
    ///
    /// # Errors
    /// Returns [`Err`] if the AEAD authentication or decryption fails.
    pub fn open<'a>(
        &self,
        nonce: &AeadNonce,
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Result<&'a [u8], AeadError> {
        self.key.open_in_place(nonce, aad, data)
    }
}

impl Zeroize for BoundAeadKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.write_iv.zeroize();
        // sequence is a trait object, we don't zeroize it here.
    }
}

impl Drop for BoundAeadKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_nonce(n: u64) -> AeadNonce {
        let mut buf = [0u8; NONCE_LEN];
        buf[4..].copy_from_slice(&n.to_be_bytes());
        AeadNonce(buf)
    }

    #[test]
    fn aes256gcm_round_trip() {
        let key_bytes = [0x42u8; 32];
        let key = AeadKey::new(AeadAlgorithm::Aes256Gcm, &key_bytes).unwrap();
        let plaintext = b"`OpenHTTPA` trusted payload";
        let mut buf = plaintext.to_vec();
        key.seal_in_place(&make_nonce(1), b"aad", &mut buf).unwrap();
        assert_ne!(&buf, plaintext);

        let key2 = AeadKey::new(AeadAlgorithm::Aes256Gcm, &key_bytes).unwrap();
        let pt = key2
            .open_in_place(&make_nonce(1), b"aad", &mut buf)
            .unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn chacha20_round_trip() {
        let key_bytes = [0x99u8; 32];
        let key = AeadKey::new(AeadAlgorithm::ChaCha20Poly1305, &key_bytes).unwrap();
        let mut buf = b"hello world".to_vec();
        key.seal_in_place(&make_nonce(7), b"", &mut buf).unwrap();
        let key2 = AeadKey::new(AeadAlgorithm::ChaCha20Poly1305, &key_bytes).unwrap();
        let pt = key2.open_in_place(&make_nonce(7), b"", &mut buf).unwrap();
        assert_eq!(pt, b"hello world");
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let key_bytes = [0xdeu8; 32];
        let key = AeadKey::new(AeadAlgorithm::Aes256Gcm, &key_bytes).unwrap();
        let mut buf = b"secret".to_vec();
        key.seal_in_place(&make_nonce(5), b"aad", &mut buf).unwrap();
        buf[0] ^= 0xFF; // tamper
        let key2 = AeadKey::new(AeadAlgorithm::Aes256Gcm, &key_bytes).unwrap();
        assert!(key2
            .open_in_place(&make_nonce(5), b"aad", &mut buf)
            .is_err());
    }

    // ─── BoundAeadKey tests ────────────────────────────────────────────────

    fn make_write_iv(seed: u8) -> [u8; NONCE_LEN] {
        [seed; NONCE_LEN]
    }

    #[test]
    fn bound_key_seal_open_round_trip() {
        let key_bytes = [0x11u8; 32];
        let iv = make_write_iv(0xAA);
        let sealer = BoundAeadKey::new(AeadAlgorithm::Aes256Gcm, &key_bytes, iv).unwrap();
        let opener = BoundAeadKey::new(AeadAlgorithm::Aes256Gcm, &key_bytes, iv).unwrap();

        let plaintext = b"`OpenHTTPA` session data";
        let mut buf = plaintext.to_vec();
        let nonce = sealer.seal(b"aad", &mut buf).unwrap();
        assert_ne!(&buf, plaintext);

        let pt = opener.open(&nonce, b"aad", &mut buf).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn bound_key_unique_nonces_per_call() {
        let key_bytes = [0x22u8; 32];
        let iv = make_write_iv(0xBB);
        let key = BoundAeadKey::new(AeadAlgorithm::Aes256Gcm, &key_bytes, iv).unwrap();

        let mut buf1 = b"msg1".to_vec();
        let mut buf2 = b"msg2".to_vec();
        let n1 = key.seal(b"", &mut buf1).unwrap();
        let n2 = key.seal(b"", &mut buf2).unwrap();
        // Each seal must produce a distinct nonce
        assert_ne!(n1.0, n2.0);
    }

    #[test]
    fn bound_key_wrong_nonce_rejected() {
        let key_bytes = [0x33u8; 32];
        let iv = make_write_iv(0xCC);
        let sealer = BoundAeadKey::new(AeadAlgorithm::Aes256Gcm, &key_bytes, iv).unwrap();
        let opener = BoundAeadKey::new(AeadAlgorithm::Aes256Gcm, &key_bytes, iv).unwrap();

        let mut buf = b"data".to_vec();
        let _nonce = sealer.seal(b"aad", &mut buf).unwrap();
        // Use a different nonce for decryption → must fail
        let wrong_nonce = AeadNonce([0u8; NONCE_LEN]);
        assert!(opener.open(&wrong_nonce, b"aad", &mut buf).is_err());
    }

    #[test]
    fn bound_key_counter_increments() {
        let key_bytes = [0x44u8; 32];
        let iv = [0u8; NONCE_LEN];
        let key = BoundAeadKey::new(AeadAlgorithm::Aes256Gcm, &key_bytes, iv).unwrap();
        let mut buf = b"test".to_vec();
        // Counter starts at 1, so first nonce = IV XOR 1 (last 8 bytes)
        let n = key.seal(b"", &mut buf).unwrap();
        assert_eq!(n.0[4..], 1u64.to_be_bytes());
    }

    #[test]
    fn bound_key_overflow_protection() {
        let key_bytes = [0x55u8; 32];
        let iv = [0u8; NONCE_LEN];
        // Start counter at u64::MAX - 1
        let seq = Box::new(AtomicNonceSequence::new(u64::MAX - 1));
        let key =
            BoundAeadKey::with_sequence(AeadAlgorithm::Aes256Gcm, &key_bytes, iv, seq).unwrap();
        let mut buf = b"data".to_vec();

        // First call: returns u64::MAX - 1, increments to u64::MAX
        key.seal(b"", &mut buf).unwrap();

        // Second call: counter is u64::MAX, returns Error, stays at u64::MAX
        assert!(matches!(
            key.seal(b"", &mut buf),
            Err(BoundAeadError::NonceOverflow)
        ));

        // Third call: still u64::MAX, still Error (must NOT wrap to 0)
        assert!(matches!(
            key.seal(b"", &mut buf),
            Err(BoundAeadError::NonceOverflow)
        ));
    }
}

// ─── Property-based tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod proptest_aead {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Seal then open must recover the original plaintext for arbitrary
        /// plaintext (0–1024 bytes) and AAD (0–64 bytes).
        #[test]
        fn aes256gcm_seal_open_roundtrip(
            plaintext in proptest::collection::vec(any::<u8>(), 0..=1024),
            aad in proptest::collection::vec(any::<u8>(), 0..=64),
            nonce_bytes in proptest::array::uniform12(any::<u8>()),
        ) {
            let key_bytes = [0u8; 32];
            let key = AeadKey::new(AeadAlgorithm::Aes256Gcm, &key_bytes).unwrap();
            let nonce = AeadNonce(nonce_bytes);

            let mut buf = plaintext.clone();
            key.seal_in_place(&nonce, &aad, &mut buf).unwrap();
            let nonce2 = AeadNonce(nonce_bytes);
            let result = key.open_in_place(&nonce2, &aad, &mut buf).unwrap();
            prop_assert_eq!(result, plaintext.as_slice());
        }

        /// Wrong AAD must cause decryption to fail (authentication failure).
        #[test]
        fn aes256gcm_wrong_aad_rejected(
            plaintext in proptest::collection::vec(any::<u8>(), 1..=512),
            aad in proptest::collection::vec(any::<u8>(), 1..=32),
            nonce_bytes in proptest::array::uniform12(any::<u8>()),
            flip_byte in any::<u8>().prop_filter("non-zero", |&b| b != 0),
            flip_idx in any::<usize>(),
        ) {
            let key_bytes = [0u8; 32];
            let key = AeadKey::new(AeadAlgorithm::Aes256Gcm, &key_bytes).unwrap();

            let mut buf = plaintext;
            key.seal_in_place(&AeadNonce(nonce_bytes), &aad, &mut buf).unwrap();

            // Flip one byte of the AAD so it no longer matches.
            let mut bad_aad = aad.clone();
            let flip_at = flip_idx % bad_aad.len();
            bad_aad[flip_at] ^= flip_byte;
            prop_assert!(key.open_in_place(&AeadNonce(nonce_bytes), &bad_aad, &mut buf).is_err());
        }

        /// `BoundAeadKey` seal→open round-trip for arbitrary data and AAD.
        #[test]
        fn bound_key_seal_open_property(
            plaintext in proptest::collection::vec(any::<u8>(), 0..=512),
            aad in proptest::collection::vec(any::<u8>(), 0..=32),
        ) {
            let key_bytes = [0u8; 32];
            let write_iv = [0u8; NONCE_LEN];
            let bound = BoundAeadKey::new(AeadAlgorithm::Aes256Gcm, &key_bytes, write_iv)
                .unwrap();

            let mut buf = plaintext.clone();
            let nonce = bound.seal(&aad, &mut buf).unwrap();
            let result = bound.open(&nonce, &aad, &mut buf).unwrap();
            prop_assert_eq!(result, plaintext.as_slice());
        }
    }
}
