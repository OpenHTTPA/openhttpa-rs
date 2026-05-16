# openhttpa-crypto

Cryptographic primitives and hybrid post-quantum key exchange for `OpenHTTPA`.

This crate provides a unified API for the cryptographic operations required by the `OpenHTTPA` protocol, focusing on hybrid post-quantum security and memory safety.

## Primitives

- **Hybrid KEM**: Combines classical ECDH (X25519, P-384) with post-quantum KEM (ML-KEM-768, ML-KEM-1024).
- **AEAD**: Authenticated Encryption with Associated Data using AES-256-GCM and ChaCha20-Poly1305.
- **KDF**: Key derivation using HKDF-SHA256 and HKDF-SHA384.
- **Signatures**: Support for ML-DSA-65 (post-quantum) and classical ECDSA/Ed25519.
- **Hashing**: SHA-2 and SHA-3 family support.

## Key Features

- **Zeroize on Drop**: All sensitive types (keys, shared secrets) implement `zeroize::ZeroizeOnDrop` to ensure memory is cleared after use.
- **Hybrid Combiner**: Implements the dual-IKM HKDF combiner to ensure security as long as _either_ the classical or the post-quantum component remains secure.
- **Protocol Binding**: Support for deriving session keys bound to a transcript hash.

## Usage Example (Hybrid KEM)

```rust
use openhttpa_crypto::key_exchange::{HybridKemPair, KeyShare};

// Generate an ephemeral hybrid key pair (Client)
let client_pair = HybridKemPair::generate().unwrap();
let client_share = client_pair.public_key_share();

// ... send share to server ...

// Encapsulate (Server)
let server_pair = HybridKemPair::generate().unwrap();
let (shared_secret, server_share) = server_pair.server_combine(&client_share).unwrap();
```

## Security

This crate relies on `aws-lc-rs` for high-performance FIPS-grade classical primitives and pure-Rust implementations for post-quantum algorithms.
