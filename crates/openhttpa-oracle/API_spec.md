# openhttpa-oracle — API Specification

**Crate**: `openhttpa-oracle`  
**License**: Apache-2.0 OR MIT  
**Edition**: Rust 2021  
**Repository**: [openhttpa-rs](file:///home/ub/tmp/openhttpa-rs)

---

## Overview

`openhttpa-oracle` implements the **OpenHTTPA Web2-to-Web3 Oracle Node** — a TEE-attested service that bridges verifiable off-chain data into decentralised systems. The oracle:

1. Fetches data from an external Web2 API endpoint (HTTPS-only, hardened HTTP client).
2. Generates a TEE attestation quote binding the fetched data to the handshake transcript hash, proving the data was retrieved inside a trusted enclave.
3. Optionally generates a RISC Zero STARK proof (ZK proof) over the fetched data, enabling trustless on-chain verification without exposing TEE-specific quote formats.

The oracle binary (`openhttpa-oracle`) is a standalone executable that exposes an HTTP endpoint for submitting oracle requests and returning attested, optionally ZK-proven responses.

---

## Table of Contents

1. [Error Type: `OracleError`](#1-error-type-oracleerror)
2. [Response Type: `OracleResponse`](#2-response-type-oracleresponse)
3. [Oracle Node: `OracleNode`](#3-oracle-node-oraclenode)
4. [Protocol: HTTP API](#4-protocol-http-api)

---

## 1. Error Type: `OracleError`

Source: [oracle.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-oracle/src/oracle.rs)

| Variant                               | Description                                                           |
| ------------------------------------- | --------------------------------------------------------------------- |
| `FetchFailed(#[from] reqwest::Error)` | HTTP request to the Web2 endpoint failed (DNS, timeout, TLS, status). |
| `TeeError(String)`                    | TEE quote generation failed, or the URL scheme is not `https://`.     |
| `ZkError(String)`                     | RISC Zero proof generation or serialisation failed.                   |

---

## 2. Response Type: `OracleResponse`

Source: [oracle.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-oracle/src/oracle.rs)

```rust
pub struct OracleResponse {
    pub data: Vec<u8>,
    pub quote: Vec<u8>,
    pub quote_type: String,
    pub transcript_hash: [u8; 48],
    pub zk_receipt: Option<Vec<u8>>,
}
```

| Field             | Type              | Description                                                                            |
| ----------------- | ----------------- | -------------------------------------------------------------------------------------- |
| `data`            | `Vec<u8>`         | Raw HTTP response body from the Web2 endpoint.                                         |
| `quote`           | `Vec<u8>`         | Raw TEE attestation quote bytes binding `data` to `transcript_hash`.                   |
| `quote_type`      | `String`          | Debug-format string of the `QuoteType` (e.g. `"Mock"`, `"Tdx"`).                       |
| `transcript_hash` | `[u8; 48]`        | The SHA-384 transcript hash passed to `fetch_and_prove`, embedded in the quote's QUDD. |
| `zk_receipt`      | `Option<Vec<u8>>` | `bincode`-serialised RISC Zero receipt (when `generate_zk_proof` is `true`).           |

---

## 3. Oracle Node: `OracleNode`

Source: [oracle.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-oracle/src/oracle.rs#L33)

```rust
pub struct OracleNode {
    http_client: reqwest::Client,  // Hardened HTTPS client (private)
    tee_provider: Arc<dyn TeeProvider>,
}
```

### Constructor

```rust
pub fn new(tee_provider: Arc<dyn TeeProvider>) -> Self
```

Creates a new oracle node with a hardened `reqwest::Client`:

- `timeout`: 10 seconds for all network operations.
- `user_agent`: `"OPENHTTPA-Oracle/1.0 (Confidential TEE Node)"`.
- `min_tls_version`: TLS 1.2 (enforced via `reqwest::tls::Version::TLS_1_2`).
- Scheme validation is performed in `fetch_and_prove` (not the builder) to allow HTTP for local test addresses.

---

### `fetch_and_prove`

```rust
pub async fn fetch_and_prove(
    &self,
    url: &str,
    transcript_hash: [u8; 48],
    generate_zk_proof: bool,
) -> Result<OracleResponse, OracleError>
```

Fetches data from `url`, generates a TEE quote, and optionally produces a ZK proof.

#### Parameters

| Parameter           | Type       | Description                                                                        |
| ------------------- | ---------- | ---------------------------------------------------------------------------------- |
| `url`               | `&str`     | The Web2 API endpoint to fetch. Must be `https://` unless the host is `127.0.0.1`. |
| `transcript_hash`   | `[u8; 48]` | SHA-384 transcript hash of the current OpenHTTPA session, used as the QUDD input.  |
| `generate_zk_proof` | `bool`     | If `true`, a RISC Zero STARK proof is generated over the fetched data.             |

#### Processing Steps

1. **Scheme validation**: Parses `url` and rejects non-HTTPS schemes unless the host is `127.0.0.1`.
2. **HTTP fetch**: Sends a `GET` request via the hardened client; collects the full response body as bytes.
3. **QUDD construction**: Builds the 64-byte QUDD:
   ```
   report_data[0..19]  = b"openhttpa hs server"
   report_data[32..64] = transcript_hash[0..32]
   ```
4. **TEE quote generation**: Calls `tee_provider.generate_quote(&QuoteRequest { report_data })`.
5. **ZK proof** (if requested): Calls `ZkProver::prove` with `ZkMode::Oracle`, supplying the raw quote bytes, report data, and the fetched response body as `oracle_data`.
   - In mock mode, returns a dummy `[0xDE, 0xAD, 0xBE, 0xEF]` receipt with a warning log.
6. Returns `OracleResponse`.

#### Errors

- `Err(OracleError::TeeError(...))` for invalid URLs (non-HTTPS, non-local).
- `Err(OracleError::FetchFailed(...))` for HTTP errors.
- `Err(OracleError::TeeError(...))` if quote generation fails.
- `Err(OracleError::ZkError(...))` if ZK proof generation fails (unless mock prover).

---

## 4. Protocol: HTTP API

Source: [main.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-oracle/src/main.rs), [protocol.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-oracle/src/protocol.rs)

The oracle binary exposes a minimal HTTP server on a configurable address (default: `0.0.0.0:9090`).

### `POST /oracle/fetch`

**Request body** (JSON):

```json
{
  "url": "https://api.example.com/data",
  "transcript_hash": "<48-byte array as list of integers>",
  "generate_zk_proof": false
}
```

**Response body** (JSON, `200 OK`):

```json
{
  "data": [<bytes>],
  "quote": [<bytes>],
  "quote_type": "Mock",
  "transcript_hash": [<48 bytes>],
  "zk_receipt": null
}
```

**Error response** (JSON, `400 Bad Request` or `500 Internal Server Error`):

```json
{
  "error": "<error message>"
}
```

### Security Notes

- All non-`127.0.0.1` URLs **must** use `https://`. Requests to HTTP endpoints (except localhost) are rejected with `OracleError::TeeError("HTTPS required for non-local URLs")`.
- The oracle server should be deployed inside a TEE. The output `quote` field proves to callers that the fetch was performed inside a trusted environment.
- The `zk_receipt` field enables on-chain or off-chain verifiers to confirm the oracle response without trusting any specific TEE platform, using `ZkVerifier::verify(receipt, OPENHTTPA_GUEST_ID)`.

---

## Public API Surface

```rust
// From lib.rs (re-exported for library users)
pub use oracle::{OracleError, OracleNode, OracleResponse};
```

---

## Dependency Graph Position

```
openhttpa-oracle
├── openhttpa-tee     (TeeProvider, QuoteRequest)
├── openhttpa-zk      (ZkProver, ZkInput, ZkMode)
├── reqwest           (hardened HTTPS client)
├── serde + serde_json
├── serde-big-array   ([u8; 48] Serialize support)
├── bincode           (ZK receipt serialisation)
├── thiserror
└── tokio             (async runtime for main binary)
```
