# openhttpa-headers — API Specification

**Crate**: `openhttpa-headers`  
**License**: Apache-2.0 OR MIT  
**Edition**: Rust 2021  
**Repository**: [openhttpa-rs](file:///home/ub/tmp/openhttpa-rs)

---

## Overview

`openhttpa-headers` is the **typed HTTP header codec** for the OpenHTTPA protocol. It encodes and decodes every `Attest-*` header field defined by the OpenHTTPA specification, using **RFC 8941 Structured Field Values (SFV)** as the on-wire serialisation format.

Key responsibilities:

- Typed encode/decode for all `Attest-*` header fields
- Canonical AHL (Attest Header List) construction for MAC and QUDD binding
- Length-prefixed canonicalization to prevent header-injection attacks (C-AHL-1)
- Session-ticket and provenance encoding

---

## Table of Contents

1. [Header Name Constants](#1-header-name-constants)
2. [Header Error Type (`HeaderError`)](#2-header-error-type)
3. [AtHS Request Headers (`AtHsRequestHeaders`)](#3-aths-request-headers)
4. [AtHS Response Headers (`AtHsResponseHeaders`)](#4-aths-response-headers)
5. [Preflight Response Headers (`PreflightResponseHeaders`)](#5-preflight-response-headers)
6. [Termination Headers](#6-termination-headers)
7. [AHL Canonicalisation Functions](#7-ahl-canonicalisation-functions)
8. [SFV Encoding Helpers (Internal)](#8-sfv-encoding-helpers-internal)

---

## 1. Header Name Constants

All header names are defined as `LazyLock<HeaderName>` static constants so that they are interned once and reused without per-call allocation. All names are lowercase as required by RFC 7230 §3.2.

> **IANA Registration Note**: The `Attest-*` field names are pending registration in the IANA Hypertext Transfer Protocol (HTTP) Field Name Registry (RFC 9110 §16.3.1) once the OpenHTTPA specification is submitted to the IETF. Until that point, the `Attest-` prefix serves as an informal vendor namespace unlikely to conflict with standardised fields.

| Constant                             | Header Name Wire Value           |
| ------------------------------------ | -------------------------------- |
| `HDR_ATTEST_CIPHER_SUITES`           | `attest-cipher-suites`           |
| `HDR_ATTEST_SUPPORTED_CIPHER_SUITES` | `attest-supported-cipher-suites` |
| `HDR_ATTEST_CIPHER_SUITE`            | `attest-cipher-suite`            |
| `HDR_ATTEST_SUPPORTED_GROUPS`        | `attest-supported-groups`        |
| `HDR_ATTEST_KEY_SHARES`              | `attest-key-shares`              |
| `HDR_ATTEST_KEY_SHARE`               | `attest-key-share`               |
| `HDR_ATTEST_RANDOM`                  | `attest-random`                  |
| `HDR_ATTEST_POLICIES`                | `attest-policies`                |
| `HDR_ATTEST_BASE_CREATION`           | `attest-base-creation`           |
| `HDR_ATTEST_BLOCKLIST`               | `attest-blocklist`               |
| `HDR_ATTEST_VERSIONS`                | `attest-versions`                |
| `HDR_ATTEST_SUPPORTED_VERSIONS`      | `attest-supported-versions`      |
| `HDR_ATTEST_DATE`                    | `attest-date`                    |
| `HDR_ATTEST_SIGNATURES`              | `attest-signatures`              |
| `HDR_ATTEST_SERVER_SIGNATURES`       | `attest-server-signatures`       |
| `HDR_ATTEST_TRANSPORT`               | `attest-transport`               |
| `HDR_ATTEST_QUOTES`                  | `attest-quotes`                  |
| `HDR_ATTEST_BASE_ID`                 | `attest-base-id`                 |
| `HDR_ATTEST_VERSION`                 | `attest-version`                 |
| `HDR_ATTEST_EXPIRES`                 | `attest-expires`                 |
| `HDR_ATTEST_SECRETS`                 | `attest-secrets`                 |
| `HDR_ATTEST_CARGO`                   | `attest-cargo`                   |
| `HDR_ATTEST_TICKET`                  | `attest-ticket`                  |
| `HDR_ATTEST_BINDER`                  | `attest-binder`                  |
| `HDR_ATTEST_BASE_TERMINATION`        | `attest-base-termination`        |
| `HDR_ATTEST_CHALLENGE`               | `attest-challenge`               |
| `HDR_ATTEST_PROVENANCE`              | `attest-provenance`              |
| `HDR_ATTEST_TICKET_RESUMPTION`       | `attest-ticket-resumption`       |
| `HDR_ATTEST_ZK_PROOF`                | `attest-zk-proof`                |
| `HDR_ATTEST_AI_PROVENANCE_PROOF`     | `attest-ai-provenance-proof`     |

---

## 2. Header Error Type

Source: [attest_headers.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-headers/src/attest_headers.rs)

### `HeaderError` (Enum)

Errors returned by header encoding and decoding functions. `#[non_exhaustive]`.

| Variant                                    | Description                                                                              |
| ------------------------------------------ | ---------------------------------------------------------------------------------------- |
| `Missing { name: String }`                 | A required header was absent from the map.                                               |
| `Invalid { name: String, reason: String }` | A header was present but contained an unparseable or invalid value.                      |
| `Base64 { name: String, reason: String }`  | A binary header contained invalid base64url-encoded data.                                |
| `TooManyHeaders { max: usize }`            | The AHL contained more than `MAX_AHL_HEADERS` (64) distinct `Attest-*` fields.           |
| `ValueTooLong { name: String }`            | A header name (> 256 bytes) or value (> 4096 bytes) exceeded the maximum allowed length. |

---

## 3. AtHS Request Headers

### `AtHsRequestHeaders` (Struct)

The complete set of `Attest-*` headers sent by the client in the `AtHS` (Attestation Handshake) request. This struct accompanies the `ATTEST` HTTP method request that initiates the OpenHTTPA handshake.

#### Fields

| Field                      | Type                      | Required | Wire Header            | SFV Type                          | Description                                                                              |
| -------------------------- | ------------------------- | -------- | ---------------------- | --------------------------------- | ---------------------------------------------------------------------------------------- |
| `cipher_suites`            | `Vec<CipherSuite>`        | ✓        | `Attest-Cipher-Suites` | List of Token                     | Ordered preference list (most-preferred first). Must be non-empty.                       |
| `random`                   | `Vec<u8>`                 | ✓        | `Attest-Random`        | Byte Sequence                     | 32-byte cryptographically random nonce. Prevents replay of the handshake.                |
| `versions`                 | `Vec<ProtocolVersion>`    | ✓        | `Attest-Versions`      | List of Token                     | Protocol versions supported, most-preferred first. Must be non-empty.                    |
| `key_shares_json`          | `Vec<u8>`                 | ✓        | `Attest-Key-Shares`    | Byte Sequence                     | JSON-serialised `ClientKeyShare` (`{"ecdhe_public": "<b64>", "mlkem_public": "<b64>"}`). |
| `date`                     | `String`                  | ✓        | `Attest-Date`          | String                            | ISO 8601 UTC timestamp (e.g. `"2026-04-27T00:00:00Z"`).                                  |
| `base_creation`            | `AtbCreation`             | ✓        | `Attest-Base-Creation` | Token                             | Requested AtB allocation mode.                                                           |
| `direct_attestation`       | `bool`                    | ✓        | `Attest-Policies`      | Dictionary (`direct=?1`)          | If `true`, requires direct TEE attestation quotes from `TService`.                       |
| `allow_untrusted_requests` | `bool`                    | ✓        | `Attest-Policies`      | Dictionary (`allow-untrusted=?0`) | If `true`, permits `TService` without hardware attestation.                              |
| `client_quotes`            | `Vec<AttestQuote>`        | ✗        | `Attest-Quotes`        | List of Inner Lists               | Client-side TEE quotes for mutual attestation (mHTTPA).                                  |
| `challenge`                | `Option<Vec<u8>>`         | ✗        | `Attest-Challenge`     | Byte Sequence                     | Server-provided fresh challenge nonce (C-TEE-3). Present after preflight.                |
| `signatures`               | `Vec<Vec<u8>>`            | ✗        | `Attest-Signatures`    | List of Byte Sequences            | Client signatures over AHLs (for signature-bound policies).                              |
| `ticket`                   | `Option<SessionTicket>`   | ✗        | `Attest-Ticket`        | Byte Sequence (JSON)              | Session ticket for resumption.                                                           |
| `provenance`               | `Option<ProvenanceChain>` | ✗        | `Attest-Provenance`    | Byte Sequence (JSON)              | Multi-hop agent provenance chain.                                                        |

#### Methods

```rust
pub fn encode(&self) -> HeaderMap
```

Encodes all fields into an [`http::HeaderMap`] using RFC 8941 SFV.

- Binary fields (random, key shares, challenge, ticket, provenance): encoded as `Byte Sequence` SFV items (`:base64url:` format per RFC 8941 §4.1.8).
- List fields (cipher suites, versions): encoded as `List` of `Token` items.
- Policy flags: encoded as an SFV `Dictionary` (e.g. `direct=?1, allow-untrusted=?0`).
- `AtbCreation` variants: `New` → `"new"`, `Reuse` → `"reuse"`, `Shared` → `"shared"`.

**Never panics.** All internal token strings are statically validated SFV token literals.

```rust
pub fn decode(map: &HeaderMap) -> Result<Self, HeaderError>
```

Decodes an [`http::HeaderMap`] into a structured `AtHsRequestHeaders`.

- Returns `Err(HeaderError::Missing)` if `Attest-Random`, `Attest-Key-Shares`, `Attest-Cipher-Suites`, or `Attest-Versions` are absent.
- Returns `Err(HeaderError::Invalid)` if any present header contains invalid SFV.
- Tolerates missing optional fields (`challenge`, `ticket`, `provenance`, `client_quotes`).

---

## 4. AtHS Response Headers

### `AtHsResponseHeaders` (Struct)

The complete set of `Attest-*` headers returned by the `TService` in the `AtHS` (200 OK) response.

#### Fields

| Field               | Type                    | Wire Header                | SFV Type               | Description                                      |
| ------------------- | ----------------------- | -------------------------- | ---------------------- | ------------------------------------------------ |
| `cipher_suite`      | `CipherSuite`           | `Attest-Cipher-Suite`      | Token                  | Server-selected cipher suite.                    |
| `random`            | `Vec<u8>`               | `Attest-Random`            | Byte Sequence          | 32-byte server random nonce.                     |
| `key_share_json`    | `Vec<u8>`               | `Attest-Key-Share`         | Byte Sequence          | JSON-serialised `ServerKeyShare`.                |
| `base_id`           | `AtbId`                 | `Attest-Base-ID`           | String (UUID)          | Allocated AtB identifier (UUID v4, hyphenated).  |
| `version`           | `ProtocolVersion`       | `Attest-Version`           | Token                  | Selected protocol version.                       |
| `expires_secs`      | `u64`                   | `Attest-Expires`           | Integer                | AtB lifetime in seconds.                         |
| `quotes`            | `Vec<AttestQuote>`      | `Attest-Quotes`            | List of Inner Lists    | Server TEE attestation quotes.                   |
| `secrets`           | `Vec<AttestSecret>`     | `Attest-Secrets`           | Byte Sequence (JSON)   | Provisioned secrets (optional).                  |
| `cargo`             | `Option<TrustedCargo>`  | `Attest-Cargo`             | Byte Sequence (JSON)   | Trusted cargo metadata (optional).               |
| `ticket_resumption` | `Option<SessionTicket>` | `Attest-Ticket-Resumption` | Byte Sequence (JSON)   | Session ticket for future resumption (optional). |
| `server_signatures` | `Vec<Vec<u8>>`          | `Attest-Server-Signatures` | List of Byte Sequences | ML-DSA signatures over the transcript hash.      |
| `zk_proof`          | `Option<Vec<u8>>`       | `Attest-ZK-Proof`          | Byte Sequence          | Optional ZK-SNARK receipt (ZAA mode).            |

#### Methods

```rust
pub fn encode(&self) -> HeaderMap
pub fn decode(map: &HeaderMap) -> Result<Self, HeaderError>
```

Same conventions as `AtHsRequestHeaders`. Returns `Err(HeaderError::Missing)` if `Attest-Cipher-Suite`, `Attest-Random`, `Attest-Key-Share`, `Attest-Base-ID`, or `Attest-Version` are absent.

##### `AttestQuote` Inner List Wire Format

Each quote is encoded as an SFV Inner List: `(type_token :bytes: "collateral_uri_1" "collateral_uri_2")`.

- Position 0: `Token` — the quote type string (e.g. `sgx`, `tdx`).
- Position 1: `Byte Sequence` — raw quote bytes.
- Positions 2+: `String` items — optional collateral URI strings.

---

## 5. Preflight Response Headers

### `PreflightResponseHeaders` (Struct)

Headers returned by the server in response to a preflight `OPTIONS` request. Provides a fresh challenge to guarantee freshness of the subsequent `AtHS` quote (C-TEE-3).

| Field                     | Type                   | Wire Header                      | SFV Type      | Description                                |
| ------------------------- | ---------------------- | -------------------------------- | ------------- | ------------------------------------------ |
| `challenge`               | `Vec<u8>`              | `Attest-Challenge`               | Byte Sequence | 32-byte server-generated challenge nonce.  |
| `supported_cipher_suites` | `Vec<CipherSuite>`     | `Attest-Supported-Cipher-Suites` | List of Token | Cipher suites supported by the server.     |
| `supported_versions`      | `Vec<ProtocolVersion>` | `Attest-Supported-Versions`      | List of Token | Protocol versions supported by the server. |

#### Methods

```rust
pub fn encode(&self) -> HeaderMap
pub fn decode(map: &HeaderMap) -> Result<Self, HeaderError>
```

---

## 6. Termination Headers

### `AtTerminationHeaders` (Struct)

Headers sent by the client when terminating an Attest Base via the `TERMINATE_ATTEST` method.

| Field              | Type             | Wire Header               | SFV Type      | Description            |
| ------------------ | ---------------- | ------------------------- | ------------- | ---------------------- |
| `base_id`          | `AtbId`          | `Attest-Base-ID`          | String (UUID) | The AtB to terminate.  |
| `base_termination` | `AtbTermination` | `Attest-Base-Termination` | Token         | Termination semantics. |

```rust
pub fn encode(&self) -> HeaderMap
pub fn decode(map: &HeaderMap) -> Result<Self, HeaderError>
```

---

## 7. AHL Canonicalisation Functions

The Attest Header List (AHL) is a canonical byte representation of the HTTP request/response context, used as input to MAC calculation and QUDD quote binding. Binding the method and path prevents semantic re-routing attacks (C-AHL-1).

### `canonicalize_ahl`

```rust
pub fn canonicalize_ahl(
    method: &str,
    path: &str,
    query: Option<&str>,
    map: &HeaderMap,
) -> Result<Vec<u8>, HeaderError>
```

Constructs a canonical byte representation including the HTTP method, URI path, query string, and all `Attest-*` headers. Returns an allocated `Vec<u8>`.

**Canonicalisation algorithm** (length-prefixed encoding, C-AHL-1):

1. **Method**: `len(method_upper):method_upper` — always uppercased.
2. **Path**: `len(path):path`.
3. **Query**: `len(query):query` — empty string if absent.
4. For each `Attest-*` header (sorted by name ascending, case-insensitive; `Attest-Ticket` and `Attest-Binder` excluded):
   - `len(name_lower):name_lower`
   - `len(comma_joined_values):comma_joined_values`

Length prefixes use decimal ASCII representation followed by a colon separator (e.g. `"5:hello"`). This is a length-extension safe encoding.

**Limits**: Maximum 64 distinct `Attest-*` headers; maximum 256 bytes per header name; maximum 4096 bytes per header value. Exceeding these limits returns `Err(HeaderError::TooManyHeaders)` or `Err(HeaderError::ValueTooLong)`.

**Returns**: `Err(HeaderError::TooManyHeaders { max })` or `Err(HeaderError::ValueTooLong { name })`.

### `update_ahl`

```rust
pub fn update_ahl<F>(
    method: &str,
    path: &str,
    query: Option<&str>,
    map: &HeaderMap,
    update: F,
) -> Result<(), HeaderError>
where
    F: FnMut(&[u8]),
```

Streaming variant that avoids allocating an intermediate `Vec<u8>`. Calls `update` with each chunk of the AHL byte sequence. Preferred when feeding a running hash (e.g. SHA-384 digest state) to avoid intermediate buffer allocation.

---

## 8. Free-Standing Encoding Helpers

### `encode_attest_provenance`

```rust
pub fn encode_attest_provenance(json_bytes: &[u8]) -> HeaderValue
```

Encodes a raw provenance chain (JSON bytes) as an RFC 8941 `Byte Sequence` (`:base64url:`), suitable for insertion into the `Attest-Provenance` header.

---

## Wire Format Summary

| SFV Type                 | Wire Example                         | Used For                                     |
| ------------------------ | ------------------------------------ | -------------------------------------------- |
| `Item` – `Byte Sequence` | `:aGVsbG8=:`                         | Binary blobs (random, keys, quotes, tickets) |
| `List` of `Token`        | `X25519_ML_KEM768, openhttpa`        | Enumeration lists (cipher suites, versions)  |
| `Item` – `Token`         | `new`                                | Scalar enumerations (creation mode, version) |
| `Item` – `Integer`       | `3600`                               | Scalar integers (TTL)                        |
| `Dictionary`             | `direct=?1, allow-untrusted=?0`      | Policy flags                                 |
| `List` of `Inner List`   | `(sgx :rawbytes:), (tdx :rawbytes:)` | Attestation quotes                           |

---

## Dependency Graph Position

```
openhttpa-headers
├── openhttpa-proto      (types: AttestQuote, CipherSuite, ProtocolVersion, etc.)
├── http                 (HeaderMap, HeaderName, HeaderValue)
├── sfv                  (RFC 8941 structured field value codec)
└── serde + serde_json   (ticket/provenance JSON encoding)
```
