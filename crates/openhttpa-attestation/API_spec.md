# openhttpa-attestation — API Specification

**Crate**: `openhttpa-attestation`  
**License**: Apache-2.0 OR MIT  
**Edition**: Rust 2024  
**Repository**: [openhttpa-rs](file:///home/ub/tmp/openhttpa-rs)

---

## Overview

`openhttpa-attestation` is the **pluggable TEE quote verification library** for OpenHTTPA. It provides a trait-based verifier architecture that supports multiple attestation backends, a composable policy engine, and a collateral-fetching abstraction.

The `QuoteVerifier` trait is the primary extension point. Implementors are responsible for verifying the cryptographic authenticity of a raw hardware attestation quote against platform collateral and returning a structured `VerificationResult`.

**Supported backends** (feature-gated):

| Feature Flag | Backend                               | Notes                                                |
| ------------ | ------------------------------------- | ---------------------------------------------------- |
| _(default)_  | Mock verifier (`MockVerifier`)        | SHA-384 pseudo-quote; test/CI use only               |
| `dcap`       | Intel DCAP (`DcapZkVerifier`)         | Calls `libsgx_dcap_quoteverify.so` via FFI           |
| `maa`        | Azure MAA (`MaaVerifier`)             | Submits to Microsoft Azure Attestation REST endpoint |
| `amd_snp`    | AMD SNP                               | Verifies VCEK-signed SEV-SNP attestation reports     |
| `ita`        | Intel Trust Authority (`ItaVerifier`) | Cloud-agnostic verification as a service             |
| `nvidia`     | NVIDIA GPU (`NvidiaGpuVerifier`)      | H100 Confidential Computing attestation              |

---

## Table of Contents

1. [Core Trait: `QuoteVerifier`](#1-core-trait-quoteverifier)
2. [Policy Trait: `PolicyEngine`](#2-policy-trait-policyengine)
3. [Revocation Trait: `RevocationProvider`](#3-revocation-trait-revocationprovider)
4. [Result and Error Types](#4-result-and-error-types)
5. [Concrete Implementations](#5-concrete-implementations)
6. [Composite Verifier (`composite`)](#6-composite-verifier)
7. [Collateral Fetcher (`collateral_fetcher`)](#7-collateral-fetcher)
8. [ZK Verifier (`DcapZkVerifier`)](#8-zk-verifier)
9. [Deprecated Types](#9-deprecated-types)

---

## 1. Core Trait: `QuoteVerifier`

Source: [verifier.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-attestation/src/verifier.rs)

```rust
#[async_trait]
pub trait QuoteVerifier: Send + Sync {
    async fn verify(
        &self,
        quote: &AttestQuote,
        report_data: &[u8; 64],
    ) -> Result<VerificationResult, VerificationError>;

    async fn verify_bundle(
        &self,
        quotes: &[AttestQuote],
        report_data: &[u8; 64],
    ) -> Result<VerificationResult, VerificationError>;
}
```

### `verify`

Verifies a single `AttestQuote` and returns a structured `VerificationResult`.

**Parameters**:

- `quote`: The raw attestation quote as produced by the TEE quoting service.
- `report_data`: The 64-byte QUDD (Quote User-Defined Data) buffer expected to be present inside the quote. For OpenHTTPA, this is `"openhttpa hs server" (19 B) ‖ SHA-384(transcript)[..32]`, with domain prefix (T-10).

**Returns**:

- `Ok(VerificationResult)` — quote is valid; EAT claims and TCB status are available.
- `Err(VerificationError)` — any form of verification failure (malformed, invalid signature, TCB out-of-date, policy violation).

**Thread safety**: Implementors must be `Send + Sync`; verifiers are expected to be held behind `Arc<dyn QuoteVerifier>`.

### `verify_bundle`

Verifies a slice of quotes (composite attestation bundle). The default implementation verifies each quote individually via `verify` and fails immediately on the first failure (fail-fast). The primary result corresponds to `quotes[0]`; secondary results are appended to `primary.secondary`.

**Returns**:

- `Err(VerificationError::MalformedQuote("empty quote bundle"))` if the slice is empty.

---

## 2. Policy Trait: `PolicyEngine`

```rust
#[async_trait]
pub trait PolicyEngine: Send + Sync + std::fmt::Debug {
    async fn evaluate(&self, result: &VerificationResult) -> Result<(), VerificationError>;
}
```

Evaluates a `VerificationResult` against a configured policy. Returns `Ok(())` if the result satisfies the policy; `Err(VerificationError::PolicyViolation(...))` otherwise.

Intended to be composed with a `QuoteVerifier` in the call chain:

```rust
let result = verifier.verify(&quote, &report_data).await?;
policy_engine.evaluate(&result).await?;
```

---

## 3. Revocation Trait: `RevocationProvider`

```rust
#[async_trait]
pub trait RevocationProvider: Send + Sync + std::fmt::Debug {
    async fn check_revocation(&self, result: &VerificationResult) -> Result<(), VerificationError>;
}
```

Checks if any identity in a `VerificationResult` appears on a revocation list.

**Contract**: Implementors must check **all** available identity fields (`boot_progress`, `measurement`, `signer_id`) to prevent a revoked enclave from evading revocation by omitting one identifier while supplying the same identity via another field (SEC-06).

---

## 4. Result and Error Types

These are re-exported from `openhttpa-proto` for ergonomic use:

```rust
pub use openhttpa_proto::{AttestQuote, EatClaims, VerificationResult};
pub use openhttpa_proto::AttestError as VerificationError;
```

See `openhttpa-proto` API specification for full field documentation of `EatClaims`, `VerificationResult`, and `AttestError`.

---

## 5. Concrete Implementations

### `MockVerifier`

Source: [mock_verifier.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-attestation/src/mock_verifier.rs)

A deterministic verifier for test and CI environments. It verifies SHA-384 pseudo-quotes generated by `openhttpa_tee::mock::MockTeeProvider`. It does **not** call any hardware or network service.

```rust
pub use mock_verifier::MockVerifier;
```

**Usage**:

```rust
use openhttpa_attestation::MockVerifier;
use std::sync::Arc;

let verifier: Arc<dyn QuoteVerifier> = Arc::new(MockVerifier::default());
```

**Security Warning**: `MockVerifier` accepts any quote that contains a valid SHA-384 hash of the `report_data`. It provides **no** hardware root of trust. Never use in production. The server logs a security-level `ERROR` when a mock verifier is active.

### `NvidiaGpuVerifier`

```rust
pub use nvidia_verifier::NvidiaGpuVerifier;
```

Verifies NVIDIA Hopper GPU Confidential Computing attestation quotes. Validates the RIM certificate chain and the GPU measurement against NVIDIA's attestation service.

### `DcapZkVerifier` (feature: `dcap`)

See section 8.

### `ItaVerifier` (feature: `ita`)

```rust
#[cfg(feature = "ita")]
pub use ita_verifier::ItaVerifier;
```

Sends quotes to the Intel Trust Authority API for cloud-agnostic verification.

### `MaaVerifier` (feature: `maa`)

```rust
#[cfg(feature = "maa")]
pub use maa_verifier::MaaVerifier;
```

Submits quotes to the Microsoft Azure Attestation REST endpoint. The verifier must be hardened against SSRF, DoS, and slow-loris attacks.

### `NvidiaRemoteVerifier` (feature: `ita`)

```rust
#[cfg(feature = "ita")]
pub use nvidia_remote_verifier::NvidiaRemoteVerifier;
```

Submits NVIDIA GPU quotes to a remote NVIDIA attestation service.

---

## 6. Composite Verifier

Source: [composite.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-attestation/src/composite.rs)

The `composite` module provides a verifier that orchestrates multiple underlying verifiers based on the `QuoteType` of each incoming quote. This enables transparent multi-TEE verification (e.g. SGX + GPU) with a single `verify_bundle` call.

---

## 7. Collateral Fetcher

Source: [collateral_fetcher.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-attestation/src/collateral_fetcher.rs)

The `collateral_fetcher` module provides an HTTP client for fetching attestation collateral (PCK certificates, TCB Info, QE Identity) from Intel PCS, AMD KDS, or URIs embedded in `AttestQuote.collateral_uris`.

Security hardening requirements:

- SSRF prevention: only permit `https://` URIs that resolve to publicly routable addresses.
- Connection timeout: 10 seconds.
- Response size limit: must not buffer unbounded responses.
- TLS minimum version: 1.2.

---

## 8. ZK Verifier

Source: [dcap_zk_verifier.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-attestation/src/dcap_zk_verifier.rs)

### `DcapZkVerifier` (Struct)

Verifies an `AttestQuote` of type `QuoteType::ZkCompressed`. The quote contains a RISC Zero STARK receipt covering a ZK-compressed Intel DCAP verification (ZAA — ZK-Aggregated Attestation). Instead of repeating the full multi-KB DCAP certificate chain verification on-chain or in the server, the ZK proof represents the entire verification succinctly.

```rust
pub use dcap_zk_verifier::DcapZkVerifier;
```

The verifier:

1. Deserialises the `AttestQuote.raw` field as a RISC Zero `Receipt`.
2. Verifies the STARK proof using the known `OPENHTTPA_GUEST_ID` (from `openhttpa-zk`).
3. Decodes the `ZkOutput` from the receipt journal and checks `is_valid` and `dcap_verified`.
4. Constructs a `VerificationResult` from the decoded `ZkOutput`.

---

## 9. Deprecated Types

### `SimpleRevocationProvider`

```rust
#[deprecated(note = "M-01: test-only — does not persist or load revocations from a CRL/OCSP endpoint.")]
pub struct SimpleRevocationProvider {
    pub revoked_identities: DashSet<String>,
}
```

An in-memory revocation provider. **Test-only.** Not suitable for production:

- State does not persist across process restarts.
- Not distributed across server replicas.
- Not loaded from a CRL or OCSP endpoint.

Use a production-grade `RevocationProvider` backed by a distributed CRL/OCSP source in deployed environments.

---

## `SimplePolicy`

Source: [policy.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-attestation/src/policy.rs)

```rust
pub use policy::SimplePolicy;
```

A simple in-process `PolicyEngine` implementation.

| Field                  | Type             | Default | Description                                                                    |
| ---------------------- | ---------------- | ------- | ------------------------------------------------------------------------------ |
| `min_security_version` | `Option<u16>`    | `None`  | If set, rejects results with `claims.security_version < min_security_version`. |
| `allow_debug_builds`   | `bool`           | `false` | If `false`, rejects enclave results with `claims.dbgstat != 0`.                |
| `required_tcb_status`  | `Option<String>` | `None`  | If set, rejects results with non-matching `tcb_status`.                        |
| `required_measurement` | `Option<String>` | `None`  | If set, rejects results with non-matching `measurement`.                       |

---

## Public API Surface

```rust
// Re-exported from openhttpa-proto
pub use verifier::{EatClaims, PolicyEngine, QuoteVerifier, RevocationProvider, VerificationError, VerificationResult};

// Concrete types
pub use dcap_zk_verifier::DcapZkVerifier;
pub use mock_verifier::MockVerifier;
pub use nvidia_verifier::NvidiaGpuVerifier;
pub use policy::SimplePolicy;

// Feature-gated
#[cfg(feature = "ita")]
pub use ita_verifier::ItaVerifier;
#[cfg(feature = "ita")]
pub use nvidia_remote_verifier::NvidiaRemoteVerifier;
#[cfg(feature = "maa")]
pub use maa_verifier::MaaVerifier;
```

---

## Dependency Graph Position

```
openhttpa-attestation
├── openhttpa-proto       (AttestQuote, VerificationResult, EatClaims, AttestError)
├── openhttpa-zk          (ZkOutput, OPENHTTPA_GUEST_ID — for DcapZkVerifier)
├── async-trait
├── dashmap               (SimpleRevocationProvider.revoked_identities)
└── reqwest (optional)    (MaaVerifier, ItaVerifier, NvidiaRemoteVerifier)
```
