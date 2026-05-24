# openhttpa-transport — API Specification

**Crate**: `openhttpa-transport`  
**License**: Apache-2.0 OR MIT  
**Edition**: Rust 2024  
**Repository**: [openhttpa-rs](file:///home/ub/tmp/openhttpa-rs)

---

## Overview

`openhttpa-transport` provides **transport-agnostic abstractions** and concrete adapters that allow the higher-level `openhttpa-server` and `openhttpa-client` crates to remain independent of the underlying HTTP transport mechanism. It also implements the **Oblivious OpenHTTPA (O-HTTPA)** encapsulation layer based on RFC 9458.

**Available adapters**:

| Adapter            | Feature     | Description                                |
| ------------------ | ----------- | ------------------------------------------ |
| `ReqwestTransport` | _(default)_ | HTTP/1.1 and HTTP/2 via `reqwest`          |
| `H2Transport`      | `h2`        | HTTP/2 cleartext or TLS via `hyper` + `h2` |
| `H3Transport`      | `h3`        | HTTP/3 over QUIC via `quinn` + `h3`        |
| `ObliviousClient`  | _(default)_ | RFC 9458 HPKE-encapsulated O-HTTPA         |

---

## Table of Contents

1. [Core Abstraction (`connection`)](#1-core-abstraction)
2. [Reqwest Adapter (`reqwest_adapter`)](#2-reqwest-adapter)
3. [HTTP/2 Adapter (`h2_adapter`, feature: `h2`)](#3-http2-adapter)
4. [HTTP/3 Adapter (`h3_adapter`, feature: `h3`)](#4-http3-adapter)
5. [Oblivious Transport (`oblivious`)](#5-oblivious-transport)

---

## 1. Core Abstraction

Source: [connection.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-transport/src/connection.rs)

### `SendError` (Enum)

Transport-level errors. Returned by `AttestTransport::send`.

| Variant              | Description                                                 |
| -------------------- | ----------------------------------------------------------- |
| `Connection(String)` | TCP/QUIC connection failed (DNS, TLS, network unreachable). |
| `Io(String)`         | I/O read or write error.                                    |
| `Cancelled`          | The request was cancelled before completion.                |
| `Protocol(String)`   | HTTP framing, header, or protocol-level error.              |

### `TransportRequest` (Struct)

A transport-level HTTP request. All fields are consumed by `AttestTransport::send`.

| Field      | Type                      | Description                                                                              |
| ---------- | ------------------------- | ---------------------------------------------------------------------------------------- |
| `method`   | `http::Method`            | HTTP method. For OpenHTTPA, may be `ATTEST`, `TERMINATE_ATTEST`, or any standard method. |
| `uri`      | `http::Uri`               | Full request URI including scheme, host, port, and path.                                 |
| `headers`  | `http::HeaderMap`         | Request headers including all `Attest-*` fields.                                         |
| `body`     | `axum::body::Body`        | Request body, potentially a streaming body.                                              |
| `trailers` | `Option<http::HeaderMap>` | Trailing headers appended after the body (e.g. `Attest-Ticket`, `Attest-Binder`).        |

### `TransportResponse` (Struct)

A transport-level HTTP response.

| Field      | Type                      | Description                                                      |
| ---------- | ------------------------- | ---------------------------------------------------------------- |
| `status`   | `http::StatusCode`        | HTTP status code.                                                |
| `headers`  | `http::HeaderMap`         | Response headers.                                                |
| `body`     | `axum::body::Body`        | Response body, potentially streaming.                            |
| `trailers` | `Option<http::HeaderMap>` | Trailing headers received after the body (e.g. `Attest-Binder`). |

### `AttestTransport` (Trait)

The primary extension point for transport adapters. Implementations must be `Send + Sync` for use behind `Arc<dyn AttestTransport>`.

```rust
#[async_trait]
pub trait AttestTransport: Send + Sync {
    async fn send(&self, request: TransportRequest) -> Result<TransportResponse, SendError>;
}
```

#### `send`

Sends a single HTTP request and returns the full response. The transport may buffer the response body or return a streaming body; callers should not assume either.

**Contract**:

- The implementation is responsible for connection pooling, TLS handshake, and HTTP/x framing.
- Trailing headers must be propagated if the underlying protocol supports them (HTTP/2 `DATA` + `HEADERS` frame pair; HTTP/1.1 chunked trailer).
- The implementation must **not** modify or strip `Attest-*` headers.

---

## 2. Reqwest Adapter

Source: [reqwest_adapter.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-transport/src/reqwest_adapter.rs)

### `ReqwestTransport` (Struct)

A `reqwest`-based HTTP transport supporting HTTP/1.1 and HTTP/2. Provides connection pooling, keep-alive, and automatic TLS negotiation.

```rust
pub struct ReqwestTransport { /* private: reqwest::Client */ }
```

#### Methods

| Method        | Signature                                         | Description                                                                                                                     |
| ------------- | ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Constructor   | `fn new() -> Self`                                | Creates with a default `reqwest::Client` (connection pool: 100 idle connections per host; TLS min version: 1.2; timeout: 30 s). |
| Custom client | `fn with_client(client: reqwest::Client) -> Self` | Creates with a caller-configured `reqwest::Client`.                                                                             |

#### Notes

- The `ATTEST` method and other custom methods are sent via `reqwest::Method::from_bytes`. As `reqwest` does not natively support `ATTEST`, the method is sent verbatim in the HTTP request line.
- Trailing headers are not propagated by `reqwest`; use `H2Transport` or `H3Transport` if trailers are required.

---

## 3. HTTP/2 Adapter (feature: `h2`)

Source: [h2_adapter.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-transport/src/h2_adapter.rs)

### `H2Transport` (Struct)

A low-level `hyper` + `h2` HTTP/2 transport with full trailer support. Required when `Attest-Ticket` or `Attest-Binder` trailers must be sent or received over HTTP/2 `DATA` + `HEADERS` frame pairs.

```rust
#[cfg(feature = "h2")]
pub struct H2Transport { /* private */ }
```

#### Methods

| Method      | Signature                                     | Description                                                                                                                                 |
| ----------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Constructor | `fn new(uri: Uri) -> Result<Self, SendError>` | Establishes an HTTP/2 connection to `uri`. Requires `https://` URI for production use; `h2c` cleartext is available for local testing only. |

---

## 4. HTTP/3 Adapter (feature: `h3`)

Source: [h3_adapter.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-transport/src/h3_adapter.rs)

### `H3Transport` (Struct)

An HTTP/3 over QUIC transport using `quinn` and `h3`. Provides head-of-line blocking elimination and 0-RTT connection establishment.

```rust
#[cfg(feature = "h3")]
pub struct H3Transport { /* private */ }
```

#### Methods

| Method      | Signature                                                                                   | Description                                                        |
| ----------- | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Constructor | `fn new(server_addr: std::net::SocketAddr, server_name: String) -> Result<Self, SendError>` | Creates a QUIC endpoint connected to `server_addr` with ALPN `h3`. |

---

## 5. Oblivious Transport

Source: [oblivious.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-transport/src/oblivious.rs)

### Overview

Implements Oblivious OpenHTTPA (O-HTTPA), based on RFC 9458 (Oblivious HTTP). The oblivious transport hides the client's request from the relay (gateway) server by HPKE-encapsulating the request body. Only the target server (which holds the HPKE private key) can decrypt the request body.

**HPKE cipher suite** used by this implementation:

- KEM: X25519-HKDF-SHA-256
- KDF: HKDF-SHA-256
- AEAD: AES-256-GCM

### `ObliviousError` (Enum)

| Variant                | Description                                               |
| ---------------------- | --------------------------------------------------------- |
| `Hpke(String)`         | HPKE encapsulation/decapsulation failure.                 |
| `Malformed`            | Incoming oblivious message has insufficient length.       |
| `Transport(SendError)` | Inner transport error (propagated from the gateway send). |

### `ObliviousClient` (Struct)

A client-side oblivious transport that wraps an inner `AttestTransport`. When `ObliviousClient::send` is called, it:

1. Performs HPKE `setup_sender` to the server's X25519 public key.
2. Seals the request body with HPKE (using `b"openhttpa-oblivious"` as the info string).
3. Constructs the wire message: `[key_id (1 B)] ‖ [encapped_key (32 B)] ‖ [ciphertext]`.
4. Sets `Content-Type: message/oblivious-http`.
5. Sends via the inner transport.
6. Exports the response decryption key via HPKE key export with label `"openhttpa-oblivious-resp"`.
7. Decrypts the response body with AES-256-GCM using a fixed all-zero nonce.

```rust
pub struct ObliviousClient {
    inner: Arc<dyn AttestTransport>,
    server_public_key: Vec<u8>,  // X25519 public key bytes (32 bytes)
    key_id: u8,                  // Key identifier for key rotation
}
```

#### Methods

| Method      | Signature                                                                                 | Description                                          |
| ----------- | ----------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| Constructor | `fn new(inner: Arc<dyn AttestTransport>, server_public_key: Vec<u8>, key_id: u8) -> Self` | Wraps an inner transport with O-HTTPA encapsulation. |

Implements `AttestTransport`. Use via `OpenHttpaClientBuilder::oblivious_gateway(...)`.

### `ObliviousServer` (Struct)

A server-side helper for decapsulating O-HTTPA requests and encapsulating responses. Intended for use in the server request handler.

```rust
pub struct ObliviousServer {
    server_secret_key: <X25519HkdfSha256 as KemTrait>::PrivateKey,
}
```

#### Methods

```rust
pub const fn new(server_secret_key: <Kem as KemTrait>::PrivateKey) -> Self
```

Creates a server-side oblivious handler from the X25519 private key.

```rust
pub fn decapsulate(&self, enc_body: &[u8]) -> Result<(Vec<u8>, ReceiverCtx), ObliviousError>
```

Decapsulates an incoming oblivious HTTP body.

- Parses `[key_id (1 B)] ‖ [encapped_key (32 B)] ‖ [ciphertext]`.
- Performs HPKE `setup_receiver` with label `"openhttpa-oblivious"`.
- Returns `(plaintext_body_bytes, receiver_ctx)`. The `receiver_ctx` must be stored until `encapsulate_response` is called.
- **Errors**: `Err(ObliviousError::Malformed)` if `enc_body` is shorter than 33 bytes.

```rust
pub fn encapsulate_response(
    &self,
    receiver_ctx: &ReceiverCtx,
    body: &[u8],
) -> Result<Vec<u8>, ObliviousError>
```

Encapsulates the response body using an exported response encryption key derived from the receiver context (label: `"openhttpa-oblivious-resp"`). Returns ciphertext bytes.

---

## Public API Surface

```rust
// Core abstractions
pub use connection::{AttestTransport, SendError, TransportRequest, TransportResponse};

// Oblivious transport
pub use oblivious::ObliviousClient;

// Feature-gated adapters
pub mod reqwest_adapter;  // ReqwestTransport (default)

#[cfg(feature = "h2")]
pub mod h2_adapter;       // H2Transport

#[cfg(feature = "h3")]
pub mod h3_adapter;       // H3Transport

pub mod oblivious;        // ObliviousServer (for server-side use)
```

---

## Dependency Graph Position

```
openhttpa-transport
├── http            (Method, Uri, HeaderMap, StatusCode)
├── axum            (axum::body::Body for streaming support)
├── async-trait
├── reqwest         (ReqwestTransport)
├── hpke            (ObliviousClient / ObliviousServer HPKE)
├── aes-gcm         (ObliviousServer response encryption)
├── h2 (optional, feature: h2)
├── hyper (optional, feature: h2)
├── quinn (optional, feature: h3)
└── h3 (optional, feature: h3)
```
