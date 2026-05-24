# openhttpa-crypto — API Specification

**Crate**: `openhttpa-crypto`  
**License**: Apache-2.0 OR MIT  
**Edition**: Rust 2024  
**Repository**: [openhttpa-rs](file:///home/ub/tmp/openhttpa-rs)

---

## Overview

`openhttpa-crypto` is the **cryptographic primitives library** for the OpenHTTPA protocol. It provides all low-level building blocks used by the handshake executor (`openhttpa-core`) and the session layer:

- Classical ECDHE key exchange: X25519, P-256, P-384 (via `aws-lc-rs`)
- Post-quantum KEM: ML-KEM-768, ML-KEM-1024 (via `oqs` / liboqs)
- Hybrid KEM combiner following draft-ietf-tls-hybrid-design §3.2
- Post-quantum digital signatures: ML-DSA-65 (via `oqs`)
- Classical digital signatures: ECDSA P-256/P-384 (via `aws-lc-rs`)
- HKDF key derivation: HMAC-SHA-256 / HMAC-SHA-384 (SA-02 corrected schedule)
- AEAD encryption: AES-256-GCM, ChaCha20-Poly1305 with nonce-safety guarantees
- Monotonic nonce management with durable file-backed counters

All secret key types implement `ZeroizeOnDrop`. Raw shared secrets **must never** be used directly as encryption keys; they must always be passed through HKDF.

---

## Table of Contents

1. [AEAD Encryption (`aead`)](#1-aead-encryption)
2. [HKDF Key Derivation (`hkdf`)](#2-hkdf-key-derivation)
3. [Key Exchange (`key_exchange`)](#3-key-exchange)
4. [Post-Quantum Cryptography (`pqc`)](#4-post-quantum-cryptography)
5. [Classical Signatures (`signature`)](#5-classical-signatures)
6. [Nonce Management (`nonce`)](#6-nonce-management)

---

## 1. AEAD Encryption

Source: [aead.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-crypto/src/aead.rs)

### `AeadAlgorithm` (Enum)

Selects the symmetric AEAD algorithm for a session.

```rust
pub enum AeadAlgorithm {
    Aes256Gcm,          // Hardware-accelerated on x86-64 / AArch64 (recommended)
    ChaCha20Poly1305,   // Good on platforms without AES hardware acceleration
}
```

| Method     | Signature                         | Description                             |
| ---------- | --------------------------------- | --------------------------------------- |
| Key length | `const fn key_len(self) -> usize` | Returns 32 (bytes) for both algorithms. |

### `AeadError` (Enum)

`#[non_exhaustive]`. Errors from AEAD operations.

| Variant              | Description                                                                    |
| -------------------- | ------------------------------------------------------------------------------ |
| `KeyConstruction`    | Key bytes have invalid length for the chosen algorithm.                        |
| `SealFailed`         | Encryption (seal) operation failed.                                            |
| `OpenFailed`         | Decryption/authentication (open) failed — ciphertext is corrupted or tampered. |
| `InvalidNonceLength` | Nonce was not exactly `NONCE_LEN` (12) bytes.                                  |
| `IoError(String)`    | I/O or system error (used by `FileNonceSequence`).                             |

### `AeadNonce` (Struct)

A 12-byte AEAD nonce. Implements `Zeroize` and `ZeroizeOnDrop`.

```rust
pub struct AeadNonce(pub [u8; NONCE_LEN]);
```

| Method      | Signature                                            | Description                                                                                  |
| ----------- | ---------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Constructor | `fn from_slice(b: &[u8]) -> Result<Self, AeadError>` | Builds from a 12-byte slice. Returns `Err(InvalidNonceLength)` if the slice is not 12 bytes. |

### `AeadKey` (Struct)

A low-level AEAD key for caller-managed nonces. Implements `Zeroize` and `Drop` (zeroes on drop).

> **Warning**: Prefer `BoundAeadKey` for session-level use to avoid nonce reuse.

| Method      | Signature                                                                                                                      | Description                                                         |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- |
| Constructor | `fn new(algorithm: AeadAlgorithm, key_bytes: &[u8]) -> Result<Self, AeadError>`                                                | Validates key length against the algorithm requirements.            |
| Seal        | `fn seal_in_place(&self, nonce: &AeadNonce, aad: &[u8], data: &mut Vec<u8>) -> Result<(), AeadError>`                          | Encrypts `data` in place, appending the authentication tag.         |
| Open        | `fn open_in_place<'a>(&self, nonce: &AeadNonce, aad: &[u8], ciphertext_with_tag: &'a mut [u8]) -> Result<&'a [u8], AeadError>` | Decrypts and verifies in place. Returns a slice of plaintext bytes. |

### `BoundAeadError` (Enum)

Errors specific to `BoundAeadKey`.

| Variant           | Description                                                            |
| ----------------- | ---------------------------------------------------------------------- |
| `NonceOverflow`   | 64-bit nonce counter reached `u64::MAX`. Session must be renegotiated. |
| `Aead(AeadError)` | Underlying AEAD error.                                                 |

### `NonceSequence` (Trait)

Abstraction over nonce generation strategies.

```rust
pub trait NonceSequence: Send + Sync {
    fn next_nonce(&self, iv: &[u8; NONCE_LEN]) -> Result<AeadNonce, BoundAeadError>;
}
```

Constructs the next nonce by XORing the counter (big-endian `u64`) into the last 8 bytes of `iv`, following TLS 1.3 §5.3.

### `AtomicNonceSequence` (Struct)

In-memory atomic nonce counter implementing `NonceSequence`.

| Method      | Signature                          | Description                            |
| ----------- | ---------------------------------- | -------------------------------------- |
| Constructor | `const fn new(start: u64) -> Self` | Creates a counter starting at `start`. |

### `FileNonceSequence` (Struct)

Durable file-backed nonce counter implementing `NonceSequence`. Persists the counter to disk before returning a nonce, protecting against replay attacks across process restarts.

| Method      | Signature                                               | Description                              |
| ----------- | ------------------------------------------------------- | ---------------------------------------- |
| Constructor | `fn new(path: PathBuf) -> Result<Self, std::io::Error>` | Opens or creates a nonce file at `path`. |

### `BoundAeadKey` (Struct)

A session-level AEAD key that owns its nonce sequence. Implements `Zeroize` and `Drop`. Prevents nonce reuse via an internal monotonic counter.

**Nonce construction** follows TLS 1.3 §5.3:

```
nonce = write_iv XOR (counter as big-endian u64, right-aligned in 12 bytes)
```

| Method          | Signature                                                                                                                                              | Description                                                      |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------- |
| Constructor     | `fn new(algorithm: AeadAlgorithm, key_bytes: &[u8], write_iv: [u8; NONCE_LEN]) -> Result<Self, AeadError>`                                             | Creates with default `AtomicNonceSequence` starting at 1.        |
| Custom sequence | `fn with_sequence(algorithm: AeadAlgorithm, key_bytes: &[u8], write_iv: [u8; NONCE_LEN], sequence: Box<dyn NonceSequence>) -> Result<Self, AeadError>` | Creates with a custom nonce sequence (e.g. `FileNonceSequence`). |
| Seal            | `fn seal(&self, aad: &[u8], data: &mut Vec<u8>) -> Result<AeadNonce, BoundAeadError>`                                                                  | Encrypts `data` in place; returns the nonce used.                |
| Open            | `fn open<'a>(&self, nonce: &AeadNonce, aad: &[u8], data: &'a mut [u8]) -> Result<&'a [u8], AeadError>`                                                 | Decrypts using an externally-supplied nonce.                     |

---

## 2. HKDF Key Derivation

Source: [hkdf.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-crypto/src/hkdf.rs)

### Key Schedule (SA-02 Corrected, RFC 5869 / TLS 1.3 §7.1 Aligned)

```
PRK = HKDF-Extract(salt=[0; 48], IKM=combined_hybrid_secret)

For each key slot:
  output = HKDF-Expand(
      PRK,
      info = b"openhttpa v2 " || label || 0x00 || transcript_hash,
      len,
  )
```

**Domain separation**: the `"openhttpa v2 "` prefix scopes all keys to this protocol version; the `label` identifies the key slot; the null separator prevents label prefix collisions; the `transcript_hash` binds the key to the exact handshake.

### `HkdfError` (Enum)

| Variant         | Description                                    |
| --------------- | ---------------------------------------------- |
| `ExtractFailed` | HKDF extract phase failed.                     |
| `ExpandFailed`  | Requested output length is too large for HKDF. |

### `HkdfExpander` (Struct)

Holds only the 48-byte PRK (HKDF-Extract output), not the raw IKM. Implements `Zeroize` and `ZeroizeOnDrop`.

| Method  | Signature                                                                        | Description                                                                                 |
| ------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Extract | `fn extract_sha384(salt: &[u8], ikm: &[u8]) -> Result<Self, HkdfError>`          | Performs HKDF-Extract using HMAC-SHA-384. The raw IKM is **not retained** after extraction. |
| Expand  | `fn expand(&self, info: &[u8], out_len: usize) -> Result<DerivedKey, HkdfError>` | Performs HKDF-Expand with the stored PRK, producing `out_len` bytes of key material.        |

### `DerivedKey` (Struct)

A derived key. Implements `Zeroize` and `ZeroizeOnDrop`.

| Method  | Signature                            | Description                                                                           |
| ------- | ------------------------------------ | ------------------------------------------------------------------------------------- |
| Borrow  | `fn as_bytes(&self) -> &[u8]`        | Borrows key bytes.                                                                    |
| Consume | `fn into_inner(mut self) -> Vec<u8>` | Consumes and returns the raw bytes. Caller is responsible for security of the result. |

### `SessionKeys` (Struct)

Complete symmetric key material derived after a successful `AtHS`. Implements `Zeroize` and `ZeroizeOnDrop`. Serialisable (for encrypted at-rest session tickets only).

| Field              | Type       | Length   | Description                                     |
| ------------------ | ---------- | -------- | ----------------------------------------------- |
| `master_secret`    | `Vec<u8>`  | 48 bytes | HKDF PRK (session master secret).               |
| `client_write_key` | `Vec<u8>`  | 32 bytes | Client-to-server AEAD key.                      |
| `server_write_key` | `Vec<u8>`  | 32 bytes | Server-to-client AEAD key.                      |
| `client_write_iv`  | `Vec<u8>`  | 12 bytes | Client-to-server AEAD IV.                       |
| `server_write_iv`  | `Vec<u8>`  | 12 bytes | Server-to-client AEAD IV.                       |
| `client_mac_key`   | `Vec<u8>`  | 32 bytes | Client-to-server HMAC key (AHL authentication). |
| `server_mac_key`   | `Vec<u8>`  | 32 bytes | Server-to-client HMAC key.                      |
| `transcript_hash`  | `[u8; 48]` | 48 bytes | SHA-384 of the handshake transcript.            |

#### Methods

```rust
pub fn derive(combined_secret: &[u8], transcript_hash: &[u8]) -> Result<Self, HkdfError>
```

Derives all 7 key slots from the hybrid combined secret and transcript hash. **Breaking change vs pre-SA-02 builds**: keys differ from the old label-as-salt implementation.

```rust
pub fn derive_0rtt(resumed_master_secret: &[u8], rtt0_salt: &[u8; 16]) -> Result<Self, HkdfError>
```

Derives 0-RTT session keys from a resumed master secret and a fresh 16-byte salt. Uses label prefix `"openhttpa v2 0rtt "` for domain separation from regular session keys.

---

## 3. Key Exchange

Source: [key_exchange.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-crypto/src/key_exchange.rs)

### `KeyExchangeError` (Enum)

`#[non_exhaustive]`.

| Variant          | Description                                       |
| ---------------- | ------------------------------------------------- |
| `KeyGeneration`  | Key pair generation failed.                       |
| `Agreement`      | Key agreement (DH) operation failed.              |
| `InvalidPeerKey` | Peer's public key is malformed or invalid.        |
| `Pqc(String)`    | Error from the post-quantum cryptography library. |

### `EcdhePair` (Struct)

A classical ECDHE ephemeral key pair.

| Field        | Type      | Description                                          |
| ------------ | --------- | ---------------------------------------------------- |
| `public_key` | `Vec<u8>` | Serialised public key bytes for `Attest-Key-Shares`. |

| Method | Signature                                                                                                                       | Description                                                                                  |
| ------ | ------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| X25519 | `fn generate_x25519() -> Result<Self, KeyExchangeError>`                                                                        | Generates an ephemeral X25519 key pair using `aws-lc-rs`.                                    |
| P-256  | `fn generate_p256() -> Result<Self, KeyExchangeError>`                                                                          | Generates an ephemeral P-256 key pair.                                                       |
| P-384  | `fn generate_p384() -> Result<Self, KeyExchangeError>`                                                                          | Generates an ephemeral P-384 key pair.                                                       |
| Agree  | `fn agree(self, algorithm: &'static agreement::Algorithm, peer_pub_key_bytes: &[u8]) -> Result<SharedSecret, KeyExchangeError>` | Performs ECDH agreement. Returns raw shared secret bytes. **Caller must pass through HKDF.** |

### `SharedSecret` (Struct)

A raw DH shared secret. Implements `Zeroize` and `ZeroizeOnDrop`.

| Method | Signature                     | Description               |
| ------ | ----------------------------- | ------------------------- |
| Bytes  | `fn as_bytes(&self) -> &[u8]` | Borrows raw secret bytes. |

### `KeyShare` (Struct)

A hybrid key share sent in `Attest-Key-Shares` headers.

| Field          | Type      | Description                       |
| -------------- | --------- | --------------------------------- |
| `ecdhe_public` | `Vec<u8>` | Classical ECDHE public key bytes. |
| `mlkem_public` | `Vec<u8>` | ML-KEM encapsulation key bytes.   |

### `HybridKemPair` (Struct)

A hybrid key pair combining X25519 (classical) + ML-KEM-768 (post-quantum). Used on both client and server sides of the `AtHS`.

| Method       | Signature                                                                                                                   | Description                                                                                                     |
| ------------ | --------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Generate     | `fn generate() -> Result<Self, KeyExchangeError>`                                                                           | Generates a fresh hybrid key pair.                                                                              |
| Public share | `fn public_key_share(&self) -> KeyShare`                                                                                    | Returns the public `KeyShare` to send to the peer.                                                              |
| Server path  | `fn server_combine(self, client_share: &KeyShare) -> Result<(HybridSharedSecret, Vec<u8>), KeyExchangeError>`               | Server: encapsulates to client's ML-KEM key and agrees on ECDHE. Returns `(combined_secret, mlkem_ciphertext)`. |
| Client path  | `fn client_combine(self, server_share: &KeyShare, mlkem_ciphertext: &[u8]) -> Result<HybridSharedSecret, KeyExchangeError>` | Client: agrees on ECDHE and decapsulates server's ML-KEM ciphertext.                                            |

### `HybridSharedSecret` (Struct)

The combined 32-byte shared secret from a hybrid KEM exchange. Implements `Zeroize` and `ZeroizeOnDrop`.

**Combiner construction** (draft-ietf-tls-hybrid-design §3.2, IND-CCA2 hardened):

```
label  = b"openhttpa hybrid kem v1"
IKM    = ECDHE_SS (fixed 32 B)
         ‖ ML-KEM_SS (fixed 32 B)
         ‖ u16(len(label)) ‖ label
         ‖ u16(len(ecdhe_pk_client)) ‖ ecdhe_pk_client
         ‖ u16(len(ecdhe_pk_server)) ‖ ecdhe_pk_server
         ‖ u16(len(mlkem_ek_client)) ‖ mlkem_ek_client
         ‖ u16(len(mlkem_ct))        ‖ mlkem_ct
PRK    = HKDF-Extract(salt=[0;32], IKM)
output = HKDF-Expand(PRK, info=b"combined", 32)
```

Length-prefix encoding (2-byte big-endian `u16`) is mandatory for all variable-length public-key fields to prevent length-extension injection attacks (SA-01).

| Method | Signature                     | Description                          |
| ------ | ----------------------------- | ------------------------------------ |
| Bytes  | `fn as_bytes(&self) -> &[u8]` | Borrows the 32-byte combined secret. |

---

## 4. Post-Quantum Cryptography

Source: [pqc.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-crypto/src/pqc.rs)

> **Security Note**: The `oqs` crate wraps liboqs, which the Open Quantum Safe project documents as "intended for prototyping and evaluation." OpenHTTPA uses hybrid classical+PQC suites by default so security degrades gracefully to classical levels if the PQC primitive is ever broken.

### `PqcError` (Enum)

`#[non_exhaustive]`.

| Variant             | Description                           |
| ------------------- | ------------------------------------- |
| `KemKeyGen(String)` | ML-KEM key generation failed.         |
| `KemEncap(String)`  | ML-KEM encapsulation failed.          |
| `KemDecap(String)`  | ML-KEM decapsulation failed.          |
| `SigKeyGen(String)` | ML-DSA key generation failed.         |
| `Sign(String)`      | ML-DSA signing operation failed.      |
| `Verify`            | ML-DSA signature verification failed. |

### `MlKemPair` (Struct)

An ML-KEM-768 ephemeral key pair. Implements `Drop` with explicit zeroization of the secret key (defense-in-depth; liboqs does not guarantee this — see RUST-03).

| Method      | Signature                                                                              | Description                                                                                    |
| ----------- | -------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Generate    | `fn generate() -> Result<Self, PqcError>`                                              | Generates a new ML-KEM-768 key pair using liboqs.                                              |
| Public key  | `fn public_encap_key(&self) -> &[u8]`                                                  | Returns the encapsulation (public) key bytes.                                                  |
| Encapsulate | `fn encapsulate(&self, peer_encap_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PqcError>` | Encapsulates to a peer's encapsulation key. Returns `(shared_secret_bytes, ciphertext_bytes)`. |
| Decapsulate | `fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, PqcError>`                | Decapsulates a ciphertext using this pair's decapsulation key. Returns the shared secret.      |

### `MlDsaKeyPair` (Struct)

An ML-DSA-65 key pair for post-quantum digital signatures. Implements `Drop` with explicit zeroization (SEC-DSA-01).

> **Migration note** (NIST-01): Once `aws-lc-rs` ships stable ML-DSA support, this module will migrate from `oqs` to `aws-lc-rs` for FIPS boundary validation. Only this module needs to change; the rest of the codebase is decoupled via `MlDsaKeyPair`.

| Field        | Type      | Description                            |
| ------------ | --------- | -------------------------------------- |
| `public_key` | `Vec<u8>` | Serialised ML-DSA-65 public key bytes. |

| Method   | Signature                                                                                      | Description                                                                                                   |
| -------- | ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Generate | `fn generate() -> Result<Self, PqcError>`                                                      | Generates a new ML-DSA-65 key pair.                                                                           |
| Sign     | `fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PqcError>`                                  | Signs a message with the secret key.                                                                          |
| Verify   | `fn verify(public_key_bytes: &[u8], message: &[u8], signature: &[u8]) -> Result<(), PqcError>` | Verifies a signature against raw public key bytes. Static method; does not require a `MlDsaKeyPair` instance. |

### `MlKemSharedSecret` (Struct)

A raw ML-KEM shared secret. Implements `Zeroize` and `ZeroizeOnDrop`.

| Method | Signature                     | Description                          |
| ------ | ----------------------------- | ------------------------------------ |
| Bytes  | `fn as_bytes(&self) -> &[u8]` | Borrows the raw shared secret bytes. |

---

## 5. Classical Signatures

Source: [signature.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-crypto/src/signature.rs)

### `EcdsaKeyPair` (Struct)

ECDSA key pair (P-256 or P-384) for classical digital signatures via `aws-lc-rs`. Implements `ZeroizeOnDrop`.

| Method         | Signature                                                                                                 | Description                                                   |
| -------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| Generate P-256 | `fn generate_p256() -> Result<Self, ...>`                                                                 | Generates a new P-256 ECDSA key pair.                         |
| Generate P-384 | `fn generate_p384() -> Result<Self, ...>`                                                                 | Generates a new P-384 ECDSA key pair.                         |
| Public key     | `fn public_key_bytes(&self) -> Vec<u8>`                                                                   | Returns the serialised public key.                            |
| Sign           | `fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ...>`                                                  | Signs a message with the private key (DER-encoded signature). |
| Verify         | `fn verify(public_key_bytes: &[u8], algorithm: ..., message: &[u8], signature: &[u8]) -> Result<(), ...>` | Verifies a DER-encoded signature.                             |

---

## 6. Nonce Management

Source: [nonce.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-crypto/src/nonce.rs)

### `NonceManager` (Struct)

Manages per-session counters for client-to-server and server-to-client message streams.

| Method      | Signature                            | Description                                                          |
| ----------- | ------------------------------------ | -------------------------------------------------------------------- |
| Constructor | `fn new() -> Self`                   | Creates a new manager with both counters at 0.                       |
| Next client | `fn next_client_nonce(&self) -> u64` | Atomically increments and returns the next client-to-server counter. |
| Next server | `fn next_server_nonce(&self) -> u64` | Atomically increments and returns the next server-to-client counter. |

---

## Re-exports (Public API Surface)

```rust
// From lib.rs
pub use aead::{AeadAlgorithm, AeadError, AeadKey, AeadNonce, BoundAeadError, BoundAeadKey};
pub use hkdf::HkdfExpander;
pub use key_exchange::{EcdhePair, HybridKemPair, KeyShare};
pub use nonce::NonceManager;
pub use pqc::{MlDsaKeyPair, MlKemPair};
pub use signature::EcdsaKeyPair;
pub use aws_lc_rs::rand;  // Re-exported for unified entropy generation
```

---

## Dependency Graph Position

```
openhttpa-crypto
├── openhttpa-proto
├── aws-lc-rs        (classical cryptography, FIPS-eligible)
├── oqs              (liboqs PQC — ML-KEM-768, ML-DSA-65)
├── hkdf             (RFC 5869 HKDF)
└── zeroize          (memory sanitisation)
```
