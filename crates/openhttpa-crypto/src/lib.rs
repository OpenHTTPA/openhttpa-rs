// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! # openhttpa-crypto
//!
//! Cryptographic primitives used by the `OpenHTTPA` protocol:
//!
//! * Classical ECDHE key exchange (X25519, P-256, P-384) via `aws-lc-rs`
//! * Post-quantum KEM (ML-KEM-768, ML-KEM-1024) via `oqs`
//! * Hybrid KEM (classical + PQC combined shared secret)
//! * Digital signatures (ECDSA P-256/P-384, ML-DSA-65/87, SLH-DSA-SHA2-128f)
//! * HKDF key derivation (HMAC-SHA-256 / HMAC-SHA-384)
//! * AEAD encryption (AES-256-GCM, ChaCha20-Poly1305)
//! * Nonce management with replay-window tracking
//!
//! All secret key types implement [`zeroize::ZeroizeOnDrop`] so that key
//! material is wiped from memory on drop.

#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

pub mod aead;
pub mod hkdf;
pub mod key_exchange;
pub mod nonce;
pub mod pqc;
pub mod signature;
pub use aws_lc_rs::rand;

pub use aead::{AeadAlgorithm, AeadError, AeadKey, AeadNonce, BoundAeadError, BoundAeadKey};
pub use hkdf::HkdfExpander;
pub use key_exchange::{EcdhePair, HybridKemPair, KeyShare};
pub use nonce::NonceManager;
pub use pqc::{MlDsaKeyPair, MlKemPair};
pub use signature::EcdsaKeyPair;
