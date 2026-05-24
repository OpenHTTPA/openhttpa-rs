# openhttpa-grpc — API Specification

**Crate**: `openhttpa-grpc`  
**License**: Apache-2.0 OR MIT  
**Edition**: Rust 2024  
**Repository**: [openhttpa-rs](file:///home/ub/tmp/openhttpa-rs)

---

## Overview

`openhttpa-grpc` provides a **gRPC integration layer** for the OpenHTTPA protocol using `tonic`. It allows OpenHTTPA's Attestation Handshake and Trusted Request protocols to be transported over binary Protocol Buffers / gRPC rather than HTTP Structured Field Values.

Message types are defined as `prost`-derived structs that mirror the `proto/openhttpa.proto` schema. The tonic service implementations are provided in the `service` sub-module.

---

## Table of Contents

1. [Shared Message: `GrpcAttestQuote`](#1-shared-message-grpcattestquote)
2. [AtHS Messages](#2-aths-messages)
3. [TrR Messages](#3-trr-messages)
4. [Service Implementation](#4-service-implementation)

---

## 1. Shared Message: `GrpcAttestQuote`

```proto
message AttestQuote {
  string quote_type = 1;
  bytes  raw        = 2;
  bytes  qudd       = 3;
}
```

| Field        | Type     | Tag | Description                                          |
| ------------ | -------- | --- | ---------------------------------------------------- |
| `quote_type` | `String` | 1   | Quote type string (e.g. `"sgx"`, `"tdx"`, `"mock"`). |
| `raw`        | `Bytes`  | 2   | Raw attestation quote bytes.                         |
| `qudd`       | `Bytes`  | 3   | Quote User-Defined Data embedded in the quote.       |

---

## 2. AtHS Messages

### `AtHsRequest` (Struct)

The gRPC equivalent of the HTTP `ATTEST` request. Maps to `AtHsRequestHeaders`.

```proto
message AtHsRequest {
  bytes           key_share     = 1;  // JSON-encoded ClientKeyShare
  bytes           random        = 2;  // 32-byte client nonce
  repeated string cipher_suites = 3;  // e.g. ["X25519_ML_KEM768_AES256GCM_SHA384"]
  repeated string versions      = 4;  // e.g. ["openhttpa"]
  string          date          = 5;  // ISO 8601 UTC timestamp
  string          base_creation = 6;  // "new", "reuse", or "shared"
  AttestQuote     client_quote  = 7;  // Optional client TEE quote
  bytes           challenge     = 8;  // Optional server challenge
}
```

| Field           | gRPC Type                | Prost Type                | Description                            |
| --------------- | ------------------------ | ------------------------- | -------------------------------------- |
| `key_share`     | `bytes`                  | `Bytes`                   | JSON-encoded `ClientKeyShare`.         |
| `random`        | `bytes`                  | `Bytes`                   | 32-byte client random nonce.           |
| `cipher_suites` | `repeated string`        | `Vec<String>`             | Ordered cipher suite preferences.      |
| `versions`      | `repeated string`        | `Vec<String>`             | Ordered protocol version preferences.  |
| `date`          | `string`                 | `String`                  | ISO 8601 timestamp.                    |
| `base_creation` | `string`                 | `String`                  | AtB creation mode.                     |
| `client_quote`  | `AttestQuote` (optional) | `Option<GrpcAttestQuote>` | Client TEE quote (mHTTPA).             |
| `challenge`     | `bytes`                  | `Bytes`                   | Server challenge nonce from preflight. |

### `AtHsResponse` (Struct)

The gRPC equivalent of the HTTP `200 OK` AtHS response. Maps to `AtHsResponseHeaders`.

```proto
message AtHsResponse {
  string          cipher_suite  = 1;
  bytes           random        = 2;  // 32-byte server nonce
  bytes           key_share     = 3;  // JSON-encoded ServerKeyShare
  string          base_id       = 4;  // UUID v4, hyphenated
  string          version       = 5;
  uint64          expires_secs  = 6;
  repeated AttestQuote quotes   = 7;  // Server TEE quotes
}
```

| Field          | gRPC Type              | Prost Type             | Description                    |
| -------------- | ---------------------- | ---------------------- | ------------------------------ |
| `cipher_suite` | `string`               | `String`               | Selected cipher suite token.   |
| `random`       | `bytes`                | `Bytes`                | 32-byte server random nonce.   |
| `key_share`    | `bytes`                | `Bytes`                | JSON-encoded `ServerKeyShare`. |
| `base_id`      | `string`               | `String`               | Allocated AtB UUID.            |
| `version`      | `string`               | `String`               | Selected protocol version.     |
| `expires_secs` | `uint64`               | `u64`                  | AtB TTL in seconds.            |
| `quotes`       | `repeated AttestQuote` | `Vec<GrpcAttestQuote>` | Server attestation quotes.     |

---

## 3. TrR Messages

### `TrustedRequest` (Struct)

A single AEAD-encrypted trusted request carried over gRPC. Equivalent to the encrypted body of an HTTP `trusted_request`.

```proto
message TrustedRequest {
  string base_id     = 1;  // AtB identifier (UUID)
  bytes  ciphertext  = 2;  // AEAD-encrypted request body
  bytes  nonce       = 3;  // AEAD nonce used for this message
  string termination = 4;  // "cleanup", "destroy", or "keep"
}
```

| Field         | gRPC Type | Prost Type | Description                                              |
| ------------- | --------- | ---------- | -------------------------------------------------------- |
| `base_id`     | `string`  | `String`   | Identifies the AtB session context.                      |
| `ciphertext`  | `bytes`   | `Bytes`    | AEAD-encrypted body bytes.                               |
| `nonce`       | `bytes`   | `Bytes`    | 12-byte AEAD nonce.                                      |
| `termination` | `string`  | `String`   | Optional AtB termination instruction after this request. |

### `TrustedResponse` (Struct)

An AEAD-encrypted response to a `TrustedRequest`.

```proto
message TrustedResponse {
  bytes ciphertext = 1;  // AEAD-encrypted response body
  bytes nonce      = 2;  // AEAD nonce
}
```

| Field        | gRPC Type | Prost Type | Description                         |
| ------------ | --------- | ---------- | ----------------------------------- |
| `ciphertext` | `bytes`   | `Bytes`    | AEAD-encrypted response body bytes. |
| `nonce`      | `bytes`   | `Bytes`    | 12-byte AEAD nonce.                 |

---

## 4. Service Implementation

Source: [service.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-grpc/src/service.rs)

### `AttestHandshakeService` (Struct)

The tonic gRPC service that implements the OpenHTTPA handshake RPC. Re-exported at the crate root.

```rust
pub use service::AttestHandshakeService;
```

The service exposes:

- **`Handshake` RPC**: Accepts an `AtHsRequest`, performs the server-side `AtHS` handshake, and returns an `AtHsResponse`.
- **`TrustedCall` RPC**: Accepts a `TrustedRequest`, decrypts and routes the payload, encrypts the response, and returns a `TrustedResponse`.

---

## Encoding / Decoding Notes

- All binary fields (keys, nonces, quotes) are carried as raw bytes; base64 encoding is **not** used in gRPC (unlike SFV headers).
- Cipher suite and version strings use the same token values as the HTTP wire format.
- The JSON encoding of `ClientKeyShare` and `ServerKeyShare` is retained for compatibility with the HTTP client path.

---

## Public API Surface

```rust
// Prost-generated message types
pub use GrpcAttestQuote;
pub use AtHsRequest;
pub use AtHsResponse;
pub use TrustedRequest;
pub use TrustedResponse;

// Service
pub use service::AttestHandshakeService;
```

---

## Dependency Graph Position

```
openhttpa-grpc
├── openhttpa-core        (handshake executor, session management)
├── openhttpa-proto       (AttestQuote, etc. — type mapping)
├── prost                 (Protocol Buffers derive macros)
├── tonic                 (gRPC server/client runtime)
└── serde_json            (ClientKeyShare / ServerKeyShare JSON encoding)
```
