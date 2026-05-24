# openhttpa-proto — API Specification

**Crate**: `openhttpa-proto`  
**License**: Apache-2.0 OR MIT  
**Edition**: Rust 2021  
**Repository**: [openhttpa-rs](file:///home/ub/tmp/openhttpa-rs)

---

## Overview

`openhttpa-proto` is the **canonical shared type library** for the entire OpenHTTPA workspace. It defines every wire-protocol type, every error variant, and every EAT-aligned claim structure that crosses process, network, or storage boundaries. All other crates depend on this crate.

This crate is deliberately free of async code and network I/O to remain suitable for future `no_std` environments. It does not perform cryptography; it only defines the _shapes_ of cryptographic artefacts.

**Key design rules:**

- Secret-bearing types implement [`zeroize::ZeroizeOnDrop`] to wipe key material on drop.
- All public enumerations are `#[non_exhaustive]` to allow backward-compatible extension.
- All publicly visible numeric wire identifiers are guaranteed stable across enum reorderings.

---

## Table of Contents

1. [Protocol Versioning (`ProtocolVersion`)](#1-protocol-versioning)
2. [Cipher Suites (`CipherSuite`)](#2-cipher-suites)
3. [TEE Quote Types (`QuoteType`)](#3-tee-quote-types)
4. [Attest Base Semantics (`AtbCreation`, `AtbPolicy`, `AtbTermination`)](#4-attest-base-semantics)
5. [Core Identifiers (`AtbId`)](#5-core-identifiers)
6. [Attestation Quotes (`AttestQuote`, `ReportData`)](#6-attestation-quotes)
7. [Session Resumption (`SessionTicket`, `AttestTicket`, `AttestBinder`)](#7-session-resumption)
8. [Trusted Cargo & Secrets (`TrustedCargo`, `AttestSecret`)](#8-trusted-cargo--secrets)
9. [Attest Base Records (`AttestBaseRecord`)](#9-attest-base-records)
10. [Session Key Material (`SessionKeyMaterial`, `SessionKeys`)](#10-session-key-material)
11. [Agent & Provenance Types (`AgentMetadata`, `ProvenanceChain`)](#11-agent--provenance-types)
12. [Attestation Result Types (`EatClaims`, `VerificationResult`)](#12-attestation-result-types)
13. [Error Hierarchy (`OpenHttpaError`, `TeeError`, `AttestError`)](#13-error-hierarchy)

---

## 1. Protocol Versioning

Source: [types.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-proto/src/types.rs)

### `ProtocolVersion` (Enum)

Represents the HTTPA specification version advertised in `Attest-Versions` / `Attest-Version` headers.

```rust
#[non_exhaustive]
pub enum ProtocolVersion {
    V1,  // HTTPA/1 — TLS-backed, legacy (rejected by this library)
    V2,  // OpenHTTPA — L7 message-level protection, SIGMA key exchange
}
```

| Variant | Wire Token    | Numeric ID | Notes                                                            |
| ------- | ------------- | ---------- | ---------------------------------------------------------------- |
| `V1`    | `"httpa/1"`   | `0x01`     | Legacy; not implemented; present only for negotiation rejection. |
| `V2`    | `"openhttpa"` | `0x02`     | Current OpenHTTPA specification.                                 |

#### Methods

| Signature                         | Description                                                              |
| --------------------------------- | ------------------------------------------------------------------------ |
| `const fn numeric_id(self) -> u8` | Returns the 1-byte wire identifier used in transcript binding.           |
| `impl Display`                    | Serialises to the wire token string (e.g. `"openhttpa"`).                |
| `impl FromStr`                    | Parses from a wire token string; returns `Err(())` for unknown variants. |

---

## 2. Cipher Suites

### `CipherSuite` (Enum)

Fully describes the key-exchange algorithm, AEAD algorithm, and HKDF hash function for a session. The server always selects the highest-preference suite from the client's offered list.

```rust
#[non_exhaustive]
pub enum CipherSuite {
    X25519MlKem768Aes256GcmSha384,    // Recommended default — PQC hybrid
    P384MlKem1024Aes256GcmSha384,     // PQC hybrid, stronger classical component
    X25519Aes256GcmSha384,            // Classical only
    #[deprecated(note = "S-04: asymmetric security-level mismatch")]
    P256Aes256GcmSha256,              // Classical only (retained for wire compat)
    X25519ChaCha20Poly1305Sha256,     // Classical only, software-friendly
}
```

| Variant                         | Numeric ID | Post-Quantum | Notes                        |
| ------------------------------- | ---------- | ------------ | ---------------------------- |
| `X25519MlKem768Aes256GcmSha384` | `0x0001`   | ✓            | Recommended default          |
| `P384MlKem1024Aes256GcmSha384`  | `0x0002`   | ✓            | Stronger classical component |
| `X25519Aes256GcmSha384`         | `0x0101`   | ✗            | Classical-only deployments   |
| `P256Aes256GcmSha256`           | `0x0102`   | ✗            | **Deprecated** (S-04)        |
| `X25519ChaCha20Poly1305Sha256`  | `0x0103`   | ✗            | Software-optimised           |

#### Methods

| Signature                                      | Description                                                                                   |
| ---------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `const fn preferred_list() -> &'static [Self]` | Returns all suites ordered from most to least preferred (excludes deprecated `P256` variant). |
| `const fn is_post_quantum(&self) -> bool`      | Returns `true` if this suite uses an ML-KEM component.                                        |
| `const fn numeric_id(self) -> u16`             | Returns the stable 16-bit wire identifier used in transcript binding.                         |
| `impl Display`                                 | Serialises to the wire token string (e.g. `"X25519_ML_KEM768_AES256GCM_SHA384"`).             |
| `impl FromStr`                                 | Parses from a wire token string; returns `Err(())` for unknown variants.                      |

---

## 3. TEE Quote Types

### `QuoteType` (Enum)

Identifies the Trusted Execution Environment technology that generated an `AttestQuote`.

```rust
#[non_exhaustive]
pub enum QuoteType {
    Sgx,          // Intel® SGX ECDSA-256 DCAP quote
    Tdx,          // Intel® TDX DCAP quote
    SevSnp,       // AMD SEV-SNP attestation report
    TrustZone,    // Arm TrustZone / OP-TEE attestation
    Tpm,          // TPM 2.0 PCR quote
    NvidiaGpu,    // NVIDIA Hopper GPU Confidential Computing attestation
    AwsNitro,     // AWS Nitro Enclaves attestation document
    ZkCompressed, // ZK-SNARK compressed hardware quote (ZAA)
    Mock,         // Simulated/mock quote — NEVER trust in production
    Unknown(String),
}
```

Wire token strings (used in `Attest-Quotes` headers): `"sgx"`, `"tdx"`, `"sev_snp"`, `"trustzone"`, `"tpm"`, `"nvidia_gpu"`, `"aws_nitro"`, `"zk_compressed"`, `"mock"`. Unknown strings become `Unknown(String)`.

---

## 4. Attest Base Semantics

### `AtbCreation` (Enum)

How the client requests an Attest Base (`AtB`) to be allocated.

```rust
#[non_exhaustive]
pub enum AtbCreation {
    New    = 0,  // Fresh allocation; no residual state from prior clients
    Reuse  = 1,  // Reuse a clean AtB (TEE must guarantee erasure)
    Shared = 2,  // Accept a shared AtB; residual data may be present
}
```

> **Warning**: `Reuse` and `Shared` weaken isolation guarantees. Prefer `New` in production.

### `AtbPolicy` (Struct)

Security policy in effect for a particular Attest Base.

| Field                      | Type   | Default | Description                                                                     |
| -------------------------- | ------ | ------- | ------------------------------------------------------------------------------- |
| `direct_attestation`       | `bool` | `true`  | If `true`, every instance in the AtB must be directly attested.                 |
| `allow_untrusted_requests` | `bool` | `false` | If `true`, un-trusted requests (`UtR`) are accepted (weakens security posture). |

### `AtbTermination` (Enum)

How the client requests an `AtB` to be terminated.

```rust
#[non_exhaustive]
pub enum AtbTermination {
    Cleanup, // Wipe and allow reuse by other clients
    Destroy, // Permanently destroy; cannot be reused or shared
    Keep,    // Leave alive and sharable (use with caution)
}
```

---

## 5. Core Identifiers

### `AtbId` (Struct)

An opaque, server-assigned identifier for an allocated Attest Base. Included in the `Attest-Base-ID` header on all subsequent OpenHTTPA requests.

```rust
pub struct AtbId(Uuid);
```

| Method      | Signature                         | Description                                   |
| ----------- | --------------------------------- | --------------------------------------------- |
| Constructor | `fn new() -> Self`                | Generates a cryptographically random UUID v4. |
| UUID access | `const fn as_uuid(&self) -> Uuid` | Returns the inner UUID.                       |
| Display     | `impl Display`                    | Formats as a hyphenated UUID string.          |
| Parse       | `impl FromStr<Err = uuid::Error>` | Parses a hyphenated UUID string.              |

---

## 6. Attestation Quotes

### `AttestQuote` (Struct)

An opaque attestation quote produced by a TEE's quoting service. The quote encapsulates TEE identity, code measurement, security version, and a QUDD (Quote User-Defined Data) that binds the quote to the OpenHTTPA handshake.

| Field             | Type          | Description                                                                |
| ----------------- | ------------- | -------------------------------------------------------------------------- |
| `quote_type`      | `QuoteType`   | The TEE technology that generated this quote.                              |
| `raw`             | `Bytes`       | Raw quote bytes as returned by the quoting service.                        |
| `qudd`            | `Bytes`       | Embedded QUDD: `SHA-384(all AHLs of the current handshake)`.               |
| `collateral_uris` | `Vec<String>` | Optional URIs to attestation collateral (certs, CRLs). Omitted when empty. |

#### Method

| Signature                        | Description                                |
| -------------------------------- | ------------------------------------------ |
| `fn raw_base64(&self) -> String` | Encodes `raw` as unpadded standard Base64. |

### `ReportData` (Struct)

A 64-byte buffer passed as QUDD input to the TEE quoting service. For OpenHTTPA, this is `SHA-384(serialised AHLs)` zero-padded to 64 bytes. Implements `Zeroize` and `ZeroizeOnDrop`.

| Method      | Signature                                   | Description                                                |
| ----------- | ------------------------------------------- | ---------------------------------------------------------- |
| Constructor | `fn from_sha384(digest: &[u8; 48]) -> Self` | Builds from a SHA-384 digest, zero-padding bytes `48..64`. |
| Bytes       | `const fn as_bytes(&self) -> &[u8; 64]`     | Returns the underlying 64-byte buffer.                     |

---

## 7. Session Resumption

### `SessionTicket` (Struct)

Allows a client to resume a previous session without a full hybrid KEM handshake.

| Field           | Type          | Description                                                                            |
| --------------- | ------------- | -------------------------------------------------------------------------------------- |
| `ticket`        | `Vec<u8>`     | Opaque AEAD-encrypted state: `[Master Secret, Client Identity, Expiry, Nonce Window]`. |
| `lifetime`      | `u32`         | Ticket validity in seconds.                                                            |
| `cipher_suite`  | `CipherSuite` | Cipher suite associated with this ticket.                                              |
| `rtt0_eligible` | `bool`        | Whether this ticket permits 0-RTT data.                                                |

### `AttestTicket` (Struct)

Placed as the **last trailer** of every OpenHTTPA request (except `AtHS`). Authenticates the AHLs and prevents replay. In 0-RTT flights it is sent in the headers. Implements `Zeroize` and `ZeroizeOnDrop`.

| Field       | Type               | Description                                                                |
| ----------- | ------------------ | -------------------------------------------------------------------------- |
| `nonce`     | `u64`              | Monotonically-increasing nonce for this session.                           |
| `mac`       | `Vec<u8>`          | AEAD tag / MAC computed over all AHLs of the request with the session key. |
| `rtt0_salt` | `Option<[u8; 16]>` | Optional 0-RTT indicator and binding.                                      |

### `AttestBinder` (Struct)

Placed as the **last trailer** of every OpenHTTPA response (except `AtHS` response). Binds the response to its corresponding request. Implements `Zeroize` and `ZeroizeOnDrop`.

| Field           | Type      | Description                                                   |
| --------------- | --------- | ------------------------------------------------------------- |
| `request_nonce` | `u64`     | Echo of the request's `AttestTicket.nonce`.                   |
| `mac`           | `Vec<u8>` | MAC over all response AHLs concatenated with `request_nonce`. |

---

## 8. Trusted Cargo & Secrets

### `TrustedCargo` (Struct)

Carries AEAD-encrypted metadata about sensitive payload bytes. Placed in a trailer; itself encrypted. Implements `Zeroize` and `ZeroizeOnDrop`.

| Field                | Type      | Description                                         |
| -------------------- | --------- | --------------------------------------------------- |
| `key_index`          | `u8`      | Identifies which derived session key was used.      |
| `encrypted_metadata` | `Vec<u8>` | AEAD-encrypted metadata blob (application-defined). |
| `tag`                | `Vec<u8>` | AEAD authentication tag for `encrypted_metadata`.   |

### `AttestSecret` (Struct)

A single wrapped secret provisioned via `Attest-Secrets`. The plaintext is AEAD-encrypted with the session key from `AtHS`. Implements `Zeroize` and `ZeroizeOnDrop`.

| Field        | Type      | Description                       |
| ------------ | --------- | --------------------------------- |
| `index`      | `u8`      | Secret index for later reference. |
| `ciphertext` | `Vec<u8>` | AEAD-encrypted secret bytes.      |
| `tag`        | `Vec<u8>` | AEAD authentication tag.          |

---

## 9. Attest Base Records

### `AttestBaseRecord` (Struct)

Server-side record of an allocated Attest Base.

| Field         | Type         | Description                               |
| ------------- | ------------ | ----------------------------------------- |
| `id`          | `AtbId`      | Unique identifier assigned by `TService`. |
| `service_uri` | `String`     | Client identity — URI of the service.     |
| `created_at`  | `SystemTime` | Timestamp of allocation.                  |
| `max_age`     | `Duration`   | Lifetime of this `AtB`.                   |
| `policy`      | `AtbPolicy`  | Security policy in effect.                |
| `terminated`  | `bool`       | Whether this `AtB` has been terminated.   |

#### Method

| Signature                      | Description                                                            |
| ------------------------------ | ---------------------------------------------------------------------- |
| `fn is_expired(&self) -> bool` | Returns `true` if the `AtB` has exceeded `max_age` or been terminated. |

---

## 10. Session Key Material

### `SessionKeyMaterial` (Struct)

Symmetric key material derived after a successful `AtHS`. Implements `Zeroize` and `ZeroizeOnDrop`.

| Field              | Type      | Description                            |
| ------------------ | --------- | -------------------------------------- |
| `master_secret`    | `Vec<u8>` | 48-byte master secret (PRK).           |
| `client_write_key` | `Vec<u8>` | 32-byte key for client-to-server AEAD. |
| `server_write_key` | `Vec<u8>` | 32-byte key for server-to-client AEAD. |
| `client_write_iv`  | `Vec<u8>` | 12-byte IV for client-to-server AEAD.  |
| `server_write_iv`  | `Vec<u8>` | 12-byte IV for server-to-client AEAD.  |

> **Note**: The full `SessionKeys` type (including MAC keys) is defined in `openhttpa-crypto::hkdf`.

---

## 11. Agent & Provenance Types

### `AgentMetadata` (Struct)

Metadata describing an autonomous agent in the OpenHTTPA mesh.

| Field          | Type                  | Description                                      |
| -------------- | --------------------- | ------------------------------------------------ |
| `id`           | `Uuid`                | Unique identifier.                               |
| `name`         | `String`              | Human-readable agent name.                       |
| `capabilities` | `Vec<String>`         | List of capability tokens (e.g. MCP tool names). |
| `endpoint`     | `String`              | Base URI for this agent's server.                |
| `public_key`   | `Vec<u8>`             | Agent's ML-DSA post-quantum public key bytes.    |
| `last_quote`   | `Option<AttestQuote>` | Most recent TEE attestation quote.               |

### `ProvenanceChain` (Struct)

An ordered chain of agents that have handled a request, enabling multi-hop traceability.

| Field  | Type                 | Description                                       |
| ------ | -------------------- | ------------------------------------------------- |
| `hops` | `Vec<AgentMetadata>` | Ordered list of agents that handled this request. |

#### Methods

| Signature                                            | Description                                             |
| ---------------------------------------------------- | ------------------------------------------------------- |
| `fn append(&mut self, agent: AgentMetadata)`         | Appends a new agent hop to the chain.                   |
| `fn contains_agent(&self, agent_name: &str) -> bool` | Returns `true` if the named agent appears in the chain. |
| `fn origin(&self) -> Option<&AgentMetadata>`         | Returns the originating agent (first hop).              |
| `fn previous(&self) -> Option<&AgentMetadata>`       | Returns the most-recent preceding agent (last hop).     |

---

## 12. Attestation Result Types

### `EatClaims` (Struct)

Standard EAT (Entity Attestation Token) claims as per RFC 9334.

| Field              | Type              | Description                                            |
| ------------------ | ----------------- | ------------------------------------------------------ | --- | ----------- |
| `ueid`             | `Option<Vec<u8>>` | Unique Entity ID (e.g. `MRENCLAVE                      |     | MRSIGNER`). |
| `hwmodel`          | `Option<String>`  | Hardware model (e.g. `"Intel SGX"`, `"NVIDIA H100"`).  |
| `hwversion`        | `Option<String>`  | Hardware version / TCB level.                          |
| `oemid`            | `Option<String>`  | OEM identifier.                                        |
| `dbgstat`          | `Option<u8>`      | Debug status: `0` = production, non-zero = debug/test. |
| `boot_progress`    | `Option<String>`  | Boot measurement / enclave measurement string.         |
| `security_version` | `Option<u16>`     | Security Version Number (SVN) of the TCB.              |
| `iat`              | `Option<u64>`     | Issued-At Unix timestamp.                              |

### `VerificationResult` (Struct)

The outcome of a successful quote verification, EAT-aligned.

| Field         | Type                      | Description                                                |
| ------------- | ------------------------- | ---------------------------------------------------------- |
| `eat_token`   | `Option<Vec<u8>>`         | Raw EAT token (CBOR/COSE), if produced by the verifier.    |
| `claims`      | `EatClaims`               | Structured EAT claims.                                     |
| `tcb_status`  | `String`                  | Backward-compatible TCB status string (e.g. `"UpToDate"`). |
| `measurement` | `Option<String>`          | Backward-compatible measurement string (e.g. `MRENCLAVE`). |
| `signer_id`   | `Option<String>`          | Backward-compatible signer ID string (e.g. `MRSIGNER`).    |
| `secondary`   | `Vec<VerificationResult>` | Secondary results for composite TEEs (e.g. GPU + CPU).     |

#### Method

```rust
pub fn reject_debug_builds(&self, allow_debug: bool) -> Result<(), AttestError>
```

Enforces that production environments do not accept debug-mode TEE builds.

- **Returns**: `Ok(())` if the enclave is non-debug or if `allow_debug` is `true`.
- **Errors**: `Err(AttestError::PolicyViolation(...))` if `claims.dbgstat != 0` and `allow_debug` is `false`.

---

## 13. Error Hierarchy

Source: [error.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-proto/src/error.rs)

### `OpenHttpaError` (Enum)

Top-level error type for the OpenHTTPA protocol library. `#[non_exhaustive]`.

| Variant                                  | Description                                       |
| ---------------------------------------- | ------------------------------------------------- |
| `NegotiationFailed`                      | No common cipher suite between client and server. |
| `ReplayDetected { nonce: u64 }`          | Duplicate or out-of-window nonce detected.        |
| `HandshakeIntegrityFailed`               | AHL integrity verification failed.                |
| `AttestationFailed { reason: String }`   | Quote verification failed.                        |
| `AtbAllocationFailed { reason: String }` | AtB allocation failed on the server.              |
| `AtbNotFound { atb_id: String }`         | AtB ID is unknown or has expired.                 |
| `SessionNotAttested`                     | AtHS has not yet completed; TrR is premature.     |
| `AeadFailure`                            | AEAD encryption or decryption operation failed.   |
| `KeyDerivationFailed`                    | HKDF key derivation failed.                       |
| `UnsupportedVersion { version: String }` | Protocol version is not supported.                |
| `Serialisation(String)`                  | Serialisation / deserialisation error.            |
| `Transport(String)`                      | Transport-layer error.                            |
| `Tee(TeeError)`                          | Wraps a `TeeError`.                               |
| `Io(std::io::Error)`                     | Generic I/O error.                                |

### `TeeError` (Enum)

Errors originating inside or around a Trusted Execution Environment. `#[non_exhaustive]`.

| Variant                                      | Description                                 |
| -------------------------------------------- | ------------------------------------------- |
| `NotAvailable`                               | TEE platform is not available on this host. |
| `QuoteGenerationFailed { reason: String }`   | Quote generation failed.                    |
| `QuoteVerificationFailed { reason: String }` | Quote verification failed.                  |
| `SdkError { code: u32, message: String }`    | Error returned by the underlying TEE SDK.   |

### `AttestError` (Enum)

Errors from the attestation verification layer. `#[non_exhaustive]`. Used as `VerificationError` in `openhttpa-attestation`.

| Variant                            | Description                                                 |
| ---------------------------------- | ----------------------------------------------------------- |
| `MalformedQuote(String)`           | Quote bytes are syntactically invalid.                      |
| `SignatureInvalid`                 | Quote signature does not verify.                            |
| `TcbOutOfDate { details: String }` | TCB level is below the required minimum.                    |
| `ServiceError(String)`             | Verifier service returned a non-success response.           |
| `NetworkError(String)`             | Network failure reaching the verifier.                      |
| `PolicyViolation(String)`          | Quote is valid but violates the configured policy.          |
| `Revoked(String)`                  | TEE platform or enclave identity is on the revocation list. |
| `Malformed(String)`                | Generic malformed-input error.                              |

---

## Dependency Graph Position

```
openhttpa-proto
└── (no workspace deps) — leaf crate
```

All other crates in the workspace depend on `openhttpa-proto` either directly or transitively. Changes to this crate constitute **breaking wire-format changes** and must be versioned carefully.
