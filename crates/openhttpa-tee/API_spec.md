# openhttpa-tee — API Specification

**Crate**: `openhttpa-tee`  
**License**: Apache-2.0 OR MIT  
**Edition**: Rust 2021  
**Repository**: [openhttpa-rs](file:///home/ub/tmp/openhttpa-rs)

---

## Overview

`openhttpa-tee` is the **Trusted Execution Environment (TEE) abstraction layer** for OpenHTTPA. It provides two complementary trait hierarchies:

- **`TeeProvider`** — legacy/wire interface returning flat `AttestQuote` bytes; backward-compatible.
- **`TeeAdapter`** — modern interface returning structured `AttestationEvidence`; preferred for new backends.

Both traits are used from the `AtHS` server executor and the client SDK to generate hardware attestation quotes that bind the handshake transcript. The library also provides composite and ZK-compressed provider wrappers, and a feature-gated mock provider for testing.

**Supported hardware backends** (feature-gated):

| Feature Flag | Hardware               | Implementation                |
| ------------ | ---------------------- | ----------------------------- |
| `sgx`        | Intel SGX              | `SgxTeeProvider` (ECDSA DCAP) |
| `tdx`        | Intel TDX              | `TdxTeeProvider`              |
| `sev_snp`    | AMD SEV-SNP            | `SevSnpTeeProvider`           |
| `trustzone`  | Arm TrustZone / OP-TEE | `TrustZoneTeeProvider`        |
| `tpm`        | TPM 2.0                | `TpmTeeAdapter`               |
| `nvidia_gpu` | NVIDIA Hopper GPU CC   | `NvidiaGpuTeeProvider`        |
| `aws_nitro`  | AWS Nitro Enclaves     | `AwsNitroTeeProvider`         |
| `mock`       | Simulated / software   | `MockTeeProvider`             |
| `zaa`        | ZK-compressed quotes   | `ZkCompressedTeeProvider`     |

---

## Table of Contents

1. [Core Types](#1-core-types)
2. [Trait: `TeeProvider`](#2-trait-teeprovider)
3. [Trait: `TeeAdapter`](#3-trait-teeadapter)
4. [Provider Selection: `detect_best_provider`](#4-provider-selection-detect_best_provider)
5. [Composite Provider: `CompositeTeeProvider`](#5-composite-provider-compositeTeeprovider)
6. [ZK Provider: `ZkCompressedTeeProvider` (feature: `zaa`)](#6-zk-provider-zkcompressedteeprovider)
7. [Mock Provider: `MockTeeProvider` (feature: `mock`)](#7-mock-provider-mockteeprovider)
8. [Evidence Types (`AttestationEvidence`, `EvidenceBundle`)](#8-evidence-types)
9. [Collateral Types (`collateral`)](#9-collateral-types)

---

## 1. Core Types

Source: [provider.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-tee/src/provider.rs)

### `QuoteRequest` (Struct)

A request to a `TeeProvider` or `TeeAdapter` to generate an attestation quote.

| Field         | Type       | Description                                                                                                                                                                          |
| ------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `report_data` | `[u8; 64]` | 64-byte QUDD embedded in the generated quote. For OpenHTTPA, this is `"openhttpa hs server/client" (≤32 B) ‖ SHA-384(transcript)[..32]`, following the T-10 domain-prefix hardening. |

### `TeeProviderError` (Enum)

`#[non_exhaustive]`. Errors from TEE hardware detection, initialisation, or quote generation.

| Variant                   | Description                                                            |
| ------------------------- | ---------------------------------------------------------------------- |
| `NotAvailable(String)`    | The required TEE SDK or device driver is not present on this system.   |
| `QuoteGeneration(String)` | The hardware successfully initialised but failed to produce a quote.   |
| `NotInitialised`          | The TEE device was found but is not in an operational state.           |
| `Enclave(String)`         | An error occurred within the secure enclave or TCB.                    |
| `Driver(String)`          | A failure in the low-level hardware driver (e.g. `/dev/tdx-guest`).    |
| `Config(String)`          | The platform configuration (e.g. BIOS/UEFI settings) prevents TEE use. |

### `TeeConfig` (Struct)

Configuration for TEE provider selection and fallback behaviour. Serialisable for embedding in server configuration files.

| Field            | Type             | Default                                    | Description                                                                                                                                                                                                                                                |
| ---------------- | ---------------- | ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `allow_mock`     | `bool`           | `true` in debug builds, `false` in release | Allows fallback to `MockTeeProvider` when no hardware TEE is found. **Never set `true` in production.**                                                                                                                                                    |
| `preferred_type` | `Option<String>` | `None`                                     | Overrides priority-based auto-detection. Accepted values: `"sgx"`, `"tdx"`, `"sev_snp"`, `"aws_nitro"`, `"trustzone"`, `"tpm"`, `"nvidia_gpu"`, `"nvidia"`, `"hopper"`, `"mock"`. Overridden in turn by the `OPENHTTPA_TEE_PROVIDER` environment variable. |

#### `Default` Implementation

```rust
impl Default for TeeConfig {
    fn default() -> Self {
        Self {
            allow_mock: cfg!(any(debug_assertions, feature = "mock")),
            preferred_type: None,
        }
    }
}
```

---

## 2. Trait: `TeeProvider`

The primary interface for generating TEE attestation quotes. Used by `openhttpa-server` and `openhttpa-client`.

```rust
pub trait TeeProvider: Send + Sync {
    fn quote_type(&self) -> QuoteType;

    fn generate_quote(&self, request: &QuoteRequest) -> Result<AttestQuote, TeeProviderError>;

    fn generate_quotes(
        &self,
        request: &QuoteRequest,
    ) -> Result<Vec<AttestQuote>, TeeProviderError>;

    fn is_available(&self) -> bool;
}
```

### Methods

| Method            | Signature                                                                                         | Description                                                                                                                                                                                         |
| ----------------- | ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `quote_type`      | `fn quote_type(&self) -> QuoteType`                                                               | Returns the `QuoteType` produced by this provider (e.g. `QuoteType::Tdx`, `QuoteType::SevSnp`).                                                                                                     |
| `generate_quote`  | `fn generate_quote(&self, request: &QuoteRequest) -> Result<AttestQuote, TeeProviderError>`       | Generates a **single** attestation quote binding `request.report_data`. Returns the raw quote as an `AttestQuote`.                                                                                  |
| `generate_quotes` | `fn generate_quotes(&self, request: &QuoteRequest) -> Result<Vec<AttestQuote>, TeeProviderError>` | Generates **multiple** quotes (for composite TEEs, e.g. CPU + GPU). Default implementation calls `generate_quote` and wraps the result in a single-element vector. Override for composite hardware. |
| `is_available`    | `fn is_available(&self) -> bool`                                                                  | Returns `true` if the TEE hardware and driver are present and operational. Called by `detect_best_provider` during auto-detection.                                                                  |

---

## 3. Trait: `TeeAdapter`

A modern adapter for TEE hardware that produces typed `AttestationEvidence` rather than raw bytes. Preferred for new backend implementations.

```rust
pub trait TeeAdapter: Send + Sync {
    fn quote_type(&self) -> QuoteType;

    fn generate_evidence(
        &self,
        request: &QuoteRequest,
    ) -> Result<AttestationEvidence, TeeProviderError>;

    fn is_available(&self) -> bool;

    fn initialize(&self) -> Result<(), TeeProviderError>;  // no-op by default
    fn shutdown(&self) -> Result<(), TeeProviderError>;    // no-op by default
}
```

### Methods (additional to `TeeProvider` equivalents)

| Method              | Signature                                                                                              | Description                                                                                               |
| ------------------- | ------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| `generate_evidence` | `fn generate_evidence(&self, request: &QuoteRequest) -> Result<AttestationEvidence, TeeProviderError>` | Generates structured attestation evidence, preserving typed metadata (PCR banks, RIM certificates, etc.). |
| `initialize`        | `fn initialize(&self) -> Result<(), TeeProviderError>`                                                 | Optional one-time hardware initialisation. No-op default.                                                 |
| `shutdown`          | `fn shutdown(&self) -> Result<(), TeeProviderError>`                                                   | Optional resource cleanup. No-op default.                                                                 |

---

## 4. Provider Selection: `detect_best_provider`

Source: [provider.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-tee/src/provider.rs#L170)

```rust
pub fn detect_best_provider(config: &TeeConfig) -> Result<Arc<dyn TeeProvider>, TeeProviderError>
```

Automatically selects the best available TEE provider based on current system capabilities and configuration.

### Selection Priority

1. `OPENHTTPA_TEE_PROVIDER` environment variable (highest priority).
2. `config.preferred_type` if set.
3. Priority-based hardware auto-detection in the following order:
   1. NVIDIA GPU (`nvidia_gpu` feature)
   2. Intel TDX (`tdx` feature)
   3. AMD SEV-SNP (`sev_snp` feature)
   4. AWS Nitro Enclaves (`aws_nitro` feature)
   5. Intel SGX (`sgx` feature)
   6. TPM 2.0 (`tpm` feature)
   7. Arm TrustZone (`trustzone` feature)
4. MockTeeProvider fallback (only if `config.allow_mock` is `true` and the `mock` feature is enabled).

### Returns

- `Ok(Arc<dyn TeeProvider>)` — the selected provider, wrapped in an `Arc` for shared ownership.
- `Err(TeeProviderError::NotAvailable(...))` — no hardware TEE was found and mock is disabled.

### Security Logging

When falling back to `MockTeeProvider`, the function logs at `tracing::error!` level with `security = true`, explicitly flagging the mock fallback as a security-relevant misconfiguration.

```rust
let provider = detect_best_provider(&TeeConfig::default())?;
```

### Environment Variable Override

Setting the `OPENHTTPA_TEE_PROVIDER` environment variable bypasses config and hardware detection:

```bash
OPENHTTPA_TEE_PROVIDER=mock cargo run  # Force mock in development
OPENHTTPA_TEE_PROVIDER=tdx cargo run   # Force TDX detection
```

---

## 5. Composite Provider: `CompositeTeeProvider`

```rust
pub struct CompositeTeeProvider {
    providers: Vec<Arc<dyn TeeProvider>>,
}
```

Combines multiple underlying providers for composite TEE attestation (e.g. a CPU TEE + GPU TEE). Used in `OpenHttpaClientBuilder::add_tee_provider`.

| Method      | Signature                                              | Description                                   |
| ----------- | ------------------------------------------------------ | --------------------------------------------- |
| Constructor | `fn new(providers: Vec<Arc<dyn TeeProvider>>) -> Self` | Creates a composite from a list of providers. |

### `TeeProvider` Implementation

| Method              | Behaviour                                                                                                        |
| ------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `quote_type()`      | Returns the first provider's `QuoteType` as the primary identity.                                                |
| `generate_quote()`  | Returns the **first** provider's quote only.                                                                     |
| `generate_quotes()` | Calls `generate_quote()` on each provider in order; returns all quotes. Fails immediately if any provider fails. |
| `is_available()`    | Returns `true` if **any** constituent provider reports available.                                                |

---

## 6. ZK Provider: `ZkCompressedTeeProvider` (feature: `zaa`)

```rust
#[cfg(feature = "zaa")]
pub struct ZkCompressedTeeProvider {
    inner: Arc<dyn TeeProvider>,
}
```

Wraps another provider to produce ZK-SNARK compressed quotes. Instead of returning a raw multi-KB DCAP quote, it:

1. Calls `inner.generate_quote()` to get the raw hardware quote.
2. Invokes `openhttpa_zk::prover::ZkProver::prove()` to compress the quote into a RISC Zero STARK receipt.
3. Returns an `AttestQuote` with `QuoteType::ZkCompressed` carrying the serialised receipt bytes.

This reduces the attestation payload size from ~4 KB to ~200 bytes (a ZK-SNARK receipt), at the cost of proving time (~2–10 seconds depending on hardware).

```rust
#[cfg(feature = "zaa")]
impl ZkCompressedTeeProvider {
    pub fn new(inner: Arc<dyn TeeProvider>) -> Self;
}
```

---

## 7. Mock Provider: `MockTeeProvider` (feature: `mock`)

Source: [mock.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-tee/src/mock.rs)

A fully software-simulated `TeeProvider`. Used exclusively for unit tests and CI pipelines where no real TEE hardware is available. Paired with `openhttpa_attestation::MockVerifier`.

**Behaviour**:

- Generates a deterministic SHA-384 hash of `report_data` as the quote payload.
- `quote_type()` returns `QuoteType::Mock`.
- `is_available()` always returns `true` (when the feature is enabled).

**Security restriction**: `MockTeeProvider` does **not** provide any real hardware root of trust. The server logs an `ERROR`-level security event when this provider is active. Never enable in production.

```rust
#[cfg(feature = "mock")]
use openhttpa_tee::mock::MockTeeProvider;

let provider = MockTeeProvider::default();
```

---

## 8. Evidence Types

Source: [evidence.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-tee/src/evidence.rs)

### `AttestationEvidence` (Enum)

Strongly typed evidence produced by `TeeAdapter::generate_evidence`.

| Variant                                                                           | Fields                                                                     | Description |
| --------------------------------------------------------------------------------- | -------------------------------------------------------------------------- | ----------- |
| `Tdx { tdx_report: Vec<u8>, cert_chain: Vec<u8> }`                                | Raw TDX TD-Report and DER certificate chain.                               |
| `SevSnp { report: Vec<u8>, vcek_cert: Vec<u8>, cert_chain: Vec<u8> }`             | SNP attestation report, VCEK certificate, and full chain.                  |
| `Tpm { pcr_quote: Vec<u8>, pcr_values: HashMap<u32, Vec<u8>>, ak_cert: Vec<u8> }` | TPM 2.0 PCR quote, individual PCR values, and Attestation Key certificate. |
| `NvidiaGpu { rim_cert: Vec<u8>, gpu_attestation_cert: Vec<u8>, nonce: [u8; 32] }` | NVIDIA RIM certificate, GPU attestation certificate, and the fresh nonce.  |
| `AwsNitro { document: Vec<u8> }`                                                  | AWS Nitro Enclave attestation document (CBOR-encoded).                     |
| `Mock { fake_quote: Vec<u8> }`                                                    | Simulated evidence for testing.                                            |

### `EvidenceBundle` (Struct)

A container pairing structured `AttestationEvidence` with the raw `AttestQuote` wire representation.

| Field      | Type                  | Description                                                                 |
| ---------- | --------------------- | --------------------------------------------------------------------------- |
| `evidence` | `AttestationEvidence` | Typed attestation evidence.                                                 |
| `quote`    | `AttestQuote`         | Wire-format quote derived from `evidence` for transport in `Attest-Quotes`. |

---

## 9. Collateral Types

Source: [collateral.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-tee/src/collateral.rs)

The `collateral` module defines types for attestation collateral fetched by verifiers:

| Type         | Description                                                    |
| ------------ | -------------------------------------------------------------- |
| `PckCert`    | Intel PCK (Platform Certification Key) leaf certificate (DER). |
| `TcbInfo`    | Intel TCB Info JSON blob.                                      |
| `QeIdentity` | Intel QE (Quoting Enclave) identity JSON blob.                 |
| `VcekCert`   | AMD VCEK (Versioned Chip Endorsement Key) certificate (DER).   |

---

## Public API Surface

```rust
pub use evidence::{AttestationEvidence, EvidenceBundle};
pub use provider::{detect_best_provider, QuoteRequest, TeeAdapter, TeeConfig, TeeProvider};
pub use provider::TeeProviderError;
pub use provider::CompositeTeeProvider;

#[cfg(feature = "mock")]
pub mod mock;                      // MockTeeProvider

#[cfg(feature = "zaa")]
pub use provider::ZkCompressedTeeProvider;
```

---

## Dependency Graph Position

```
openhttpa-tee
├── openhttpa-proto     (AttestQuote, QuoteType)
├── openhttpa-zk        (ZkProver — ZkCompressedTeeProvider only, feature: zaa)
├── thiserror
└── (hardware SDKs via FFI, feature-gated)
    ├── sgx-sdk         (feature: sgx)
    ├── tdx-attest      (feature: tdx)
    ├── sev              (feature: sev_snp)
    ├── tss-esapi        (feature: tpm)
    └── liboqs           (indirect, via openhttpa-crypto)
```
