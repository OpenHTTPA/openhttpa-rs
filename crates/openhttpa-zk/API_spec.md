# openhttpa-zk — API Specification

**Crate**: `openhttpa-zk`  
**License**: Apache-2.0 OR MIT  
**Edition**: Rust 2021  
**Repository**: [openhttpa-rs](file:///home/ub/tmp/openhttpa-rs)

---

## Overview

`openhttpa-zk` provides **Zero-Knowledge proving and verification** for the OpenHTTPA protocol using RISC Zero STARK proofs. It enables:

- **ZK-Aggregated Attestation (ZAA)**: Compresses a multi-KB Intel DCAP quote into a concise STARK receipt, eliminating the need for verifiers to re-run the full certificate-chain validation.
- **Handshake attestation**: Proves the validity of an OpenHTTPA handshake inside a ZK circuit.
- **Verified AI (V-AI)**: Proves that a specific LLM model (identified by weight hash) produced a specific output (identified by output hash) from a specific input, without revealing the model weights.
- **Oracle data verification**: Proves that a TEE fetched a specific URL and that the response data matches a given hash.

---

## Table of Contents

1. [Operation Mode: `ZkMode`](#1-operation-mode-zkmode)
2. [Guest Input: `ZkInput`](#2-guest-input-zkinput)
3. [Guest Output: `ZkOutput`](#3-guest-output-zkoutput)
4. [AI Provenance: `VaiInput`, `VaiOutput`](#4-ai-provenance-vaiinput-vaioutput)
5. [DCAP Collateral: `DcapCollateral`](#5-dcap-collateral-dcapcollateral)
6. [Configuration: `ZkConfig`](#6-configuration-zkconfig)
7. [Error: `ZkError`](#7-error-zkerror)
8. [Prover: `ZkProver`](#8-prover-zkprover)
9. [Verifier: `ZkVerifier`](#9-verifier-zkverifier)

---

## 1. Operation Mode: `ZkMode`

```rust
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ZkMode {
    Handshake,        // OpenHTTPA handshake attestation
    VerifiedAi,       // Verified AI (V-AI) model provenance
    Oracle,           // Web2-to-Web3 oracle data verification
    DcapCompression,  // Intel DCAP quote compression (ZAA)
}
```

| Variant           | Use Case                                                                             |
| ----------------- | ------------------------------------------------------------------------------------ |
| `Handshake`       | Proves validity of an OpenHTTPA handshake transcript in a ZK circuit.                |
| `VerifiedAi`      | Proves that a model with a known weight hash produced a specific output.             |
| `Oracle`          | Proves that a TEE fetched a URL and the response data hashes correctly.              |
| `DcapCompression` | Compresses a DCAP quote by verifying the full certificate chain inside the ZK guest. |

---

## 2. Guest Input: `ZkInput`

The input struct serialised and committed to the RISC Zero STARK circuit (the "journal"). Implements `Serialize` / `Deserialize`.

```rust
pub struct ZkInput {
    pub mode: ZkMode,
    pub transcript_hash: [u8; 48],      // SHA-384 of the handshake transcript
    pub quote_bytes: Vec<u8>,           // Raw hardware attestation quote
    pub report_data: [u8; 64],          // Expected QUDD in the quote
    pub oracle_data: Option<Vec<u8>>,   // Web2 response bytes (mode: Oracle)
    pub vai_data: Option<VaiInput>,     // AI provenance input (mode: VerifiedAi)
    pub dcap_collateral: Option<DcapCollateral>, // DCAP cert chain (mode: DcapCompression)
}
```

| Field             | Type                     | Required For      | Description                                   |
| ----------------- | ------------------------ | ----------------- | --------------------------------------------- |
| `mode`            | `ZkMode`                 | All               | Selects the circuit logic to execute.         |
| `transcript_hash` | `[u8; 48]`               | All               | SHA-384 of the handshake transcript.          |
| `quote_bytes`     | `Vec<u8>`                | All               | Raw attestation quote bytes.                  |
| `report_data`     | `[u8; 64]`               | All               | Expected QUDD to verify against.              |
| `oracle_data`     | `Option<Vec<u8>>`        | `Oracle`          | Web2 API response body bytes.                 |
| `vai_data`        | `Option<VaiInput>`       | `VerifiedAi`      | AI model/input/output hashes.                 |
| `dcap_collateral` | `Option<DcapCollateral>` | `DcapCompression` | PKI chain and metadata for DCAP verification. |

---

## 3. Guest Output: `ZkOutput`

The output struct written to the RISC Zero journal (publicly verifiable).

```rust
pub struct ZkOutput {
    pub mode: ZkMode,
    pub transcript_hash: [u8; 48],
    pub is_valid: bool,                  // Overall verification result
    pub oracle_payload_hash: [u8; 32],  // SHA-256 of oracle_data
    pub vai_output: Option<VaiOutput>,  // V-AI provenance results
    pub dcap_verified: bool,            // DCAP chain verification result
    pub iat: u64,                       // Unix timestamp of verification
}
```

| Field                 | Description                                                                                                  |
| --------------------- | ------------------------------------------------------------------------------------------------------------ |
| `mode`                | Echo of `ZkInput.mode`.                                                                                      |
| `transcript_hash`     | Echo of `ZkInput.transcript_hash`.                                                                           |
| `is_valid`            | `true` if all ZK circuit checks passed.                                                                      |
| `oracle_payload_hash` | SHA-256 hash of the fetched web2 payload (`Oracle` mode).                                                    |
| `vai_output`          | AI provenance verification results (`VerifiedAi` mode).                                                      |
| `dcap_verified`       | `true` if the DCAP quote and full certificate chain were verified inside the guest (`DcapCompression` mode). |
| `iat`                 | Issued-At Unix timestamp.                                                                                    |

---

## 4. AI Provenance: `VaiInput`, `VaiOutput`

### `VaiInput`

```rust
pub struct VaiInput {
    pub model_id: [u8; 32],   // SHA-256 hash of model weights + config
    pub input_hash: [u8; 32], // SHA-256 hash of the input/prompt transcript
    pub output_hash: [u8; 32],// SHA-256 hash of the generated output
}
```

Embedded in `ZkInput.vai_data` for `ZkMode::VerifiedAi`. The ZK guest verifies that the model identified by `model_id` could produce `output_hash` from `input_hash`.

### `VaiOutput`

```rust
pub struct VaiOutput {
    pub model_id: [u8; 32],
    pub input_hash: [u8; 32],
    pub output_hash: [u8; 32],
    pub verified_at_secs: u64,  // Unix timestamp of in-guest verification
}
```

Written to `ZkOutput.vai_output` on successful V-AI verification.

---

## 5. DCAP Collateral: `DcapCollateral`

```rust
pub struct DcapCollateral {
    pub pck_cert: Vec<u8>,       // PCK leaf certificate (DER)
    pub intermediate_ca: Vec<u8>,// Intel Intermediate CA certificate (DER)
    pub root_ca: Vec<u8>,        // Intel Root CA certificate (DER)
    pub tcb_info: Vec<u8>,       // TCB Info JSON blob (from Intel PCS)
    pub qe_identity: Vec<u8>,    // QE Identity JSON blob (from Intel PCS)
}
```

All five fields are required for `ZkMode::DcapCompression`. The ZK guest performs the full DCAP verification inside the circuit, producing a succinct proof that the certificate chain and TCB status are valid.

---

## 6. Configuration: `ZkConfig`

```rust
pub struct ZkConfig {
    pub enabled: bool,              // Enable ZK-proving for handshakes (default: false)
    pub use_mock_prover: bool,      // Use RISC Zero executor-only (no STARK proof, fast)
    pub compression_enabled: bool, // Enable DcapCompression mode (default: false)
}
```

| Field                 | Default                  | Description                                                                                                    |
| --------------------- | ------------------------ | -------------------------------------------------------------------------------------------------------------- |
| `enabled`             | `false`                  | If `false`, the server completes handshakes without generating ZK proofs.                                      |
| `use_mock_prover`     | `cfg!(debug_assertions)` | If `true`, the prover runs in executor-only mode (fast, but no proof output). Suitable for development and CI. |
| `compression_enabled` | `false`                  | If `true`, all Intel DCAP quotes are ZK-compressed via `DcapCompression` mode before being sent to clients.    |

---

## 7. Error: `ZkError`

`#[non_exhaustive]`.

| Variant                 | Description                                                    |
| ----------------------- | -------------------------------------------------------------- |
| `Prover(String)`        | The RISC Zero prover returned an error.                        |
| `Verification(String)`  | Receipt verification failed (invalid proof or wrong image ID). |
| `Serialization(String)` | Input/output serialisation failure.                            |

---

## 8. Prover: `ZkProver`

Source: [prover.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-zk/src/prover.rs)

```rust
pub struct ZkProver;
```

### Constants

```rust
pub static OPENHTTPA_GUEST_ELF: &[u8]; // RISC Zero ELF binary of the ZK guest program
pub static OPENHTTPA_GUEST_ID: [u32; 8]; // Image ID of the guest (commitment to ELF)
```

The `OPENHTTPA_GUEST_ID` is the cryptographic commitment to the guest ELF binary. Verifiers use this ID to check that the proof was generated by the authentic OpenHTTPA ZK circuit, not a modified or adversarial version.

### `prove`

```rust
pub fn prove(input: &ZkInput) -> Result<risc0_zkvm::Receipt, ZkError>
```

Executes the OpenHTTPA ZK guest circuit and generates a STARK proof.

**Modes**:

- **Mock prover** (`ZkConfig.use_mock_prover = true`): Executes the guest in executor-only mode. Fast (~milliseconds); does not produce a proof. For development and CI use.
- **Production prover**: Executes the guest and generates a full STARK receipt (~2–10 seconds depending on hardware and proof segment size).

**Returns**: A `risc0_zkvm::Receipt` containing:

- The public journal (`ZkOutput`).
- The full STARK proof (omitted in mock mode).

**Errors**: `Err(ZkError::Prover(...))` if the guest panics or the prover fails.

---

## 9. Verifier: `ZkVerifier`

Source: [verifier.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-zk/src/verifier.rs)

```rust
pub struct ZkVerifier;
```

### `verify`

```rust
pub fn verify(receipt: &risc0_zkvm::Receipt, expected_image_id: [u32; 8]) -> Result<ZkOutput, ZkError>
```

Verifies a RISC Zero `Receipt` and decodes the `ZkOutput` from its journal.

1. Calls `receipt.verify(expected_image_id)` to cryptographically verify the STARK proof against the known guest image ID.
2. Decodes the journal bytes as a `ZkOutput`.
3. Returns `Err(ZkError::Verification(...))` if the proof is invalid or `Err(ZkError::Serialization(...))` if the journal cannot be decoded.

**Usage in `DcapZkVerifier`**:

```rust
let output = ZkVerifier::verify(&receipt, OPENHTTPA_GUEST_ID)?;
assert!(output.is_valid && output.dcap_verified);
```

---

## Public API Surface

```rust
pub use prover::{OPENHTTPA_GUEST_ELF, OPENHTTPA_GUEST_ID};

// Types shared between host and guest
pub use ZkMode;
pub use ZkInput;
pub use ZkOutput;
pub use VaiInput;
pub use VaiOutput;
pub use DcapCollateral;
pub use ZkConfig;
pub use ZkError;

// Prover / Verifier
pub mod prover;   // ZkProver::prove
pub mod verifier; // ZkVerifier::verify
```

---

## Dependency Graph Position

```
openhttpa-zk
├── risc0-zkvm      (STARK proving and verification)
├── risc0-build     (guest ELF compilation, build script)
├── serde + serde_json
├── serde-big-array (for [u8; 48] / [u8; 64] Serialize support)
└── thiserror
```

### Integration Points

| Crate                   | Usage                                                 |
| ----------------------- | ----------------------------------------------------- |
| `openhttpa-tee`         | `ZkCompressedTeeProvider` calls `ZkProver::prove`     |
| `openhttpa-attestation` | `DcapZkVerifier` calls `ZkVerifier::verify`           |
| `openhttpa-oracle`      | `OracleNode::fetch_and_prove` calls `ZkProver::prove` |
| `openhttpa-llm`         | V-AI provenance proving calls `ZkProver::prove`       |
