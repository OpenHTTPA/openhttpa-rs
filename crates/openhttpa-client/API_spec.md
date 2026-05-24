# openhttpa-client — API Specification

**Crate**: `openhttpa-client`  
**License**: Apache-2.0 OR MIT  
**Edition**: Rust 2024  
**Repository**: [openhttpa-rs](file:///home/ub/tmp/openhttpa-rs)

---

## Overview

`openhttpa-client` is the **async client SDK** for the OpenHTTPA protocol. It provides a high-level API for performing the Attestation Handshake (`AtHS`) and subsequently sending AEAD-encrypted trusted requests (`TrR`) over an established `AttestSession`.

The client is transport-agnostic (backed by `openhttpa-transport`) and TEE-agnostic (backed by `openhttpa-tee`). It supports:

- Hybrid KEM key exchange (X25519 + ML-KEM-768)
- Optional preflight challenge retrieval (C-TEE-3 hardening)
- Mutual attestation (mHTTPA) — client generates TEE quotes
- ML-DSA post-quantum server signature verification (pinned identity key)
- Binary-framed streaming trusted requests
- 0-RTT trusted requests via session tickets
- Oblivious transport integration (O-HTTPA)

---

## Table of Contents

1. [Builder: `OpenHttpaClientBuilder`](#1-builder-openhttpaclientbuilder)
2. [Client: `OpenHttpaClient`](#2-client-openhttpaclient)
3. [Error Type: `ClientError`](#3-error-type-clienterror)

---

## 1. Builder: `OpenHttpaClientBuilder`

Source: [builder.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-client/src/builder.rs)

The builder follows the consuming-builder pattern (each setter method takes and returns `Self`). All fields are optional; sensible defaults apply.

```rust
let client = OpenHttpaClient::builder()
    .server_uri("https://service.example.com".parse().unwrap())
    .tee_provider(Arc::new(MockTeeProvider::default()))
    .verifier(Arc::new(MockVerifier::default()))
    .strict_attestation(true)
    .build();
```

### `OpenHttpaClientBuilder` (Struct)

```rust
#[derive(Default)]
pub struct OpenHttpaClientBuilder { /* private */ }
```

#### Setter Methods

| Method                | Signature                                                                                      | Description                                                                                                                                                                   |
| --------------------- | ---------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `server_uri`          | `fn server_uri(self, uri: Uri) -> Self`                                                        | **(Required)** Sets the base URI of the `TService`. Panics in `build()` if absent.                                                                                            |
| `tee_provider`        | `fn tee_provider(self, p: Arc<dyn TeeProvider>) -> Self`                                       | Sets a single TEE provider, replacing any previously set providers.                                                                                                           |
| `add_tee_provider`    | `fn add_tee_provider(self, p: Arc<dyn TeeProvider>) -> Self`                                   | Appends an additional TEE provider. If multiple providers are set, a `CompositeTeeProvider` is constructed automatically.                                                     |
| `tee_config`          | `fn tee_config(self, config: TeeConfig) -> Self`                                               | Sets a `TeeConfig` used with `detect_best_provider` when no explicit provider is given.                                                                                       |
| `verifier`            | `fn verifier(self, v: Arc<dyn QuoteVerifier>) -> Self`                                         | Sets the server-quote verifier. **Default**: `MockVerifier`. Override with a production-grade verifier in deployed environments.                                              |
| `transport`           | `fn transport(self, t: Arc<dyn AttestTransport>) -> Self`                                      | Sets the transport adapter. **Default**: `ReqwestTransport`.                                                                                                                  |
| `strict_attestation`  | `const fn strict_attestation(self, s: bool) -> Self`                                           | If `true`, the handshake fails when the server provides no quotes or if client TEE quote generation fails. **Default**: `false`.                                              |
| `require_preflight`   | `const fn require_preflight(self, r: bool) -> Self`                                            | If `true`, performs a preflight `OPTIONS` request to fetch a fresh server challenge before `AtHS`. Implements C-TEE-3. **Default**: `false`.                                  |
| `oblivious_gateway`   | `fn oblivious_gateway(self, gateway_uri: Uri, server_public_key: Vec<u8>, key_id: u8) -> Self` | Enables Oblivious OpenHTTPA (O-HTTPA). All requests are HPKE-encapsulated and sent to `gateway_uri`. See `ObliviousConfig`.                                                   |
| `server_identity_pub` | `fn server_identity_pub(self, pk: Vec<u8>) -> Self`                                            | Pins the server's ML-DSA public key. If set, the server **must** provide an ML-DSA signature over the transcript hash in `Attest-Server-Signatures`; failure is a hard error. |

#### `build()`

```rust
pub fn build(self) -> OpenHttpaClient
```

Constructs the `OpenHttpaClient`.

- **Panics** if `server_uri` was not set.
- If no TEE provider was set, calls `detect_best_provider(&self.tee_config.unwrap_or_default())`. If detection fails (no hardware TEE and mock disabled), this panics.
- If no verifier was set, defaults to `MockVerifier`.
- If no transport was set, defaults to `ReqwestTransport::new()`.
- If `oblivious_gateway` was configured, wraps the transport in `ObliviousClient`.

### `ObliviousConfig` (Struct)

```rust
pub struct ObliviousConfig {
    pub gateway_uri: Uri,          // URI of the oblivious relay/gateway
    pub server_public_key: Vec<u8>, // X25519 HPKE public key of the target server
    pub key_id: u8,                // Key identifier for server-side key rotation
}
```

---

## 2. Client: `OpenHttpaClient`

Source: [client.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-client/src/client.rs)

```rust
pub struct OpenHttpaClient { /* private fields */ }
```

### Construction

```rust
pub fn builder() -> OpenHttpaClientBuilder
```

Returns a new builder. This is the canonical entry point for client construction.

### `strict_attestation`

```rust
pub const fn strict_attestation(mut self, s: bool) -> Self
```

Adjusts strictness after construction (consuming). Returns a new client.

---

### `attest_handshake`

```rust
#[instrument(skip_all, name = "client.attest_handshake")]
pub async fn attest_handshake(&self) -> Result<AttestSession, ClientError>
```

Performs the complete OpenHTTPA Attestation Handshake (`AtHS`) and returns a live `AttestSession`.

#### Handshake Steps

1. **Preflight** (if `require_preflight` is set): Sends an `OPTIONS` request to the server and decodes the `Attest-Challenge` from `PreflightResponseHeaders`.
2. **Key generation**: Generates a hybrid `HybridKemPair` (X25519 + ML-KEM-768) and a 32-byte `SystemRandom` client nonce.
3. **Client quote** (mHTTPA): Generates TEE quotes binding `client_random || challenge || client_ecdhe_pk || client_mlkem_pk`. Uses `"openhttpa hs client"` as the report-data prefix (T-10). If TEE generation fails and `strict_attestation` is `false`, an empty quote list is sent.
4. **ATTEST request**: Sends `ATTEST <server_uri>` with all `Attest-*` headers encoded via `AtHsRequestHeaders::encode`.
5. **Transcript hash**: Computes SHA-384 over all 10 canonical fields (client random, challenge, ECDHE/ML-KEM shares from both sides, cipher suite, version) using length-prefixed encoding.
6. **ML-DSA verification** (if `server_identity_pub` is pinned): Verifies `Attest-Server-Signatures[0]` over the transcript hash. Returns `Err(ClientError::Attestation(...))` if the signature is missing or invalid.
7. **Server quote verification**: Verifies each quote in `Attest-Quotes` against `report_data = "openhttpa hs server" ‖ transcript[..32]`. Fails if `strict_attestation` and no quotes are provided.
8. **KEM combination**: Calls `HybridKemPair::client_combine` with the server's ECDHE public key and ML-KEM ciphertext.
9. **Key derivation**: Calls `SessionKeys::derive(hybrid_shared_secret, transcript_hash)`.
10. Returns `AttestSession` with all session state.

**Errors**: See `ClientError`.

**Panics**: If internal cryptographic state is corrupted (should not occur under normal operation).

---

### `trusted_request`

```rust
#[instrument(skip(self, session, body))]
pub async fn trusted_request(
    &self,
    session: &AttestSession,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<Vec<u8>, ClientError>
```

Sends a single AEAD-encrypted trusted request on an established session.

A convenience wrapper over `trusted_request_ext` with no extra headers. Returns the decrypted response body.

**Errors**:

- `ClientError::NotAttested` — session has expired.
- `ClientError::Transport` — network error.
- `ClientError::Handshake` — encryption or decryption failure.

---

### `trusted_request_ext`

```rust
#[instrument(skip(self, session, body, extra_headers))]
pub async fn trusted_request_ext(
    &self,
    session: &AttestSession,
    method: &str,
    path: &str,
    body: &[u8],
    extra_headers: Option<http::HeaderMap>,
) -> Result<Vec<u8>, ClientError>
```

Extended version of `trusted_request` that accepts additional request headers (e.g. `Attest-Provenance`).

#### Request Protocol

1. Verifies `session.is_alive()`.
2. Constructs full request URI by joining `server_uri` with `path`.
3. Constructs AAD: `b"openhttpa:" ‖ base_id_string_bytes`.
4. Seals `body` with the session's `client_write_key` and a monotonic nonce (TLS 1.3 §5.3 IV-XOR construction).
5. Sends the request with `Content-Type: application/json` and body `{"ciphertext": "<hex>"}`.
6. Collects the response body (up to 100 MB) and decrypts with `server_write_key`.
7. Returns decrypted plaintext.

---

### `trusted_request_streaming`

```rust
#[instrument(skip(self, session, body_stream))]
pub async fn trusted_request_streaming(
    &self,
    session: &AttestSession,
    method: &str,
    path: &str,
    body_stream: axum::body::Body,
) -> Result<axum::body::Body, ClientError>
```

Sends a trusted request with a streaming encrypted body and returns a streaming decrypted response. Implements binary framing: `[Length (4 B)] ‖ [Counter (8 B)] ‖ [Ciphertext]`.

- Each request chunk is encrypted with a unique random nonce; the cumulative SHA-384 hash of all previous ciphertext frames is mixed into the AAD to provide chain authentication.
- Response is decrypted chunk-by-chunk using the same binary framing protocol.
- Uses `Content-Type: application/x-openhttpa-stream`.

**Returns**: A streaming `axum::body::Body` of decrypted plaintext bytes.

---

### `trusted_request_0rtt`

```rust
#[instrument(skip(self, ticket, body))]
pub async fn trusted_request_0rtt(
    &self,
    ticket: &SessionTicket,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<Vec<u8>, ClientError>
```

Sends a 0-RTT trusted request using a session resumption ticket. Derives fresh session keys from `ticket.master_secret` and a new random 16-byte salt (SA-05 hardening for forward secrecy).

> **Note**: Full 0-RTT implementation is gated on session ticket provisioning from the server.

---

## 3. Error Type: `ClientError`

Source: [client.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-client/src/client.rs)

`#[non_exhaustive]`.

| Variant                 | Description                                                                              |
| ----------------------- | ---------------------------------------------------------------------------------------- |
| `Handshake(String)`     | Handshake protocol failure (key generation, transcript mismatch, server error response). |
| `Transport(String)`     | Transport-layer error from the underlying `AttestTransport`.                             |
| `Attestation(String)`   | Server quote verification failure, or ML-DSA signature failure.                          |
| `NotAttested`           | A trusted request was attempted on a session that has expired or was never established.  |
| `Serialisation(String)` | JSON serialisation or deserialisation error.                                             |
| `KeyExchange(String)`   | Hybrid KEM combination failure.                                                          |

---

## Public API Surface

```rust
pub use builder::OpenHttpaClientBuilder;
pub use client::{ClientError, OpenHttpaClient};
```

---

## Usage Example

```rust
use openhttpa_client::OpenHttpaClient;
use openhttpa_tee::mock::MockTeeProvider;
use openhttpa_attestation::MockVerifier;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Build a client (using mock TEE and verifier for development)
    let client = OpenHttpaClient::builder()
        .server_uri("https://service.example.com".parse().unwrap())
        .tee_provider(Arc::new(MockTeeProvider::default()))
        .verifier(Arc::new(MockVerifier::default()))
        .require_preflight(true)          // Enforce fresh challenge (C-TEE-3)
        .strict_attestation(true)         // Fail if server provides no quotes
        .build();

    // Perform the attestation handshake
    let session = client.attest_handshake().await.unwrap();

    // Send an AEAD-encrypted trusted request
    let response_bytes = client
        .trusted_request(&session, "GET", "/api/secret", b"")
        .await
        .unwrap();

    println!("{}", String::from_utf8_lossy(&response_bytes));
}
```

---

## Dependency Graph Position

```
openhttpa-client
├── openhttpa-core        (AttestSession, ClientKeyShare, SessionKeys, handshake types)
├── openhttpa-crypto      (HybridKemPair, AeadAlgorithm, BoundAeadKey)
├── openhttpa-headers     (AtHsRequestHeaders, AtHsResponseHeaders, HDR_ATTEST_*)
├── openhttpa-proto       (CipherSuite, ProtocolVersion)
├── openhttpa-attestation (QuoteVerifier)
├── openhttpa-tee         (TeeProvider, QuoteRequest)
├── openhttpa-transport   (AttestTransport, TransportRequest, TransportResponse)
├── axum                  (body streaming)
├── sha2                  (transcript hash)
├── hmac                  (HMAC-SHA-384 for ticket MAC)
└── tracing               (instrumentation)
```
