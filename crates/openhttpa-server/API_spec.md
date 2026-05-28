# openhttpa-server API Documentation

This document provides a comprehensive API reference for the [openhttpa-server](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-server/src/lib.rs) crate. This crate provides the Axum-based server-side SDK for **OpenHTTPA**, enabling seamless integration of attestation handshakes, Tower request verification, automatic body decryption, and attested WebSocket channels.

---

## Table of Contents

1. [Session Registry (`atb_registry`)](#1-session-registry-atb_registry)
2. [Axum Extractors (`extractors`)](#2-axum-extractors-extractors)
3. [Preflight & Handshake Handlers (`handlers`)](#3-preflight--handshake-handlers-handlers)
4. [Middleware & Resumption (`middleware`)](#4-middleware--resumption-middleware)
5. [Rate Limiting (`rate_limit`)](#5-rate-limiting-rate_limit)
6. [Persistent Storage Wrappers (`replay_guard_fs`, `replay_guard_redis`, `ticket_engine_fs`)](#6-persistent-storage-wrappers-replay_guard_fs-replay_guard_redis-ticket_engine_fs)
7. [Attested WebSockets (`ws`)](#7-attested-websockets-ws)

---

## 1. Session Registry (`atb_registry`)

Source file: [atb_registry.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-server/src/atb_registry.rs)

The `AtbRegistry` serves as an in-memory database of live `AttestSession`s established during handshakes.

### `AtbRegistry` (Struct)

Thread-safe session container backed by a concurrent `DashMap` and an atomic counter.

- **`new() -> Self`**: Creates a registry with a default capacity of 10,000 active sessions.
- **`with_capacity(max_sessions: usize) -> Self`**: Creates a registry with a custom maximum session limit (protects against memory exhaustion).
- **`insert(&self, session: AttestSession) -> Result<(), &'static str>`**: Atomically inserts a session. Rejects with an error if the registry is at capacity (uses a CAS loop to prevent concurrent overflows).
- **`get(&self, id: &AtbId) -> Option<AttestSession>`**: Returns the session. Eagerly evicts and returns `None` if the session has expired.
- **`evict_expired(&self)`**: Traverses and deletes all expired sessions from the registry, reclaiming active slots.
- **`len(&self) -> usize`**: Returns the count of registered sessions (expired sessions not yet evicted are included).
- **`is_empty(&self) -> bool`**: Returns `true` if empty.
- **`start_eviction_task(&self, interval: Duration) -> tokio::task::JoinHandle<()>`**: Spawns a background task that calls `evict_expired` periodically. Cleans up automatically once all registry instances are dropped.

---

## 2. Axum Extractors (`extractors`)

Source file: [extractors.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-server/src/extractors.rs)

Implements Axum extractors for seamless extraction and inline decryption of request payloads.

### `OpenHttpaSession` (Struct)

Axum extractor that retrieves the session from the state's `AtbRegistry` using the `Attest-Base-ID` header.

- **`id(&self) -> AtbId`**: Returns the session UUID.
- **`inner(&self) -> &AttestSession`**: Accesses the underlying `AttestSession`.
- **`transcript_hash(&self) -> Result<[u8; 48], StatusCode>`**: Fetches the handshake transcript hash.
- **`seal<T: serde::Serialize>(&self, value: &T) -> Result<Response, Response>`**: Encrypts and serializes a value into a hex-encoded JSON body response (`{"ciphertext": "..."}`) bound to the session.
- **`seal_stream<St, T>(self, stream: St) -> Response`**: Wraps a stream of serializable data into an authenticated, chunk-encrypted stream (`application/x-openhttpa-stream`).

### `EncryptedJson<T>` (Struct)

Axum extractor that decrypts and parses JSON request bodies.

- Validates the `Attest-Ticket` header.
- Verifies the AHL signature against the header MAC key.
- Decrypts the body payload using AES-256-GCM and deserializes into type `T`.
- Rolls back strict-monotonic nonces if decryption or validation fails.

### `EncryptedStream` (Struct)

Axum extractor that yields decrypted chunks from a streaming request.

Unfolds and decrypts framed streaming payloads sequentially using AES-256-GCM.

#### Binary Frame Format

Each frame in a streaming request or response uses the following wire layout:

```
+------------------+------------------+-------------------------------+
| Length (4 bytes) | Counter (8 bytes) | Ciphertext (Length bytes)    |
| big-endian u32   | big-endian u64    | AES-256-GCM output + 16B tag |
+------------------+------------------+-------------------------------+
```

- **Length**: Number of bytes in `Ciphertext` (includes the 16-byte GCM authentication tag).
- **Counter**: Monotonic counter value used for nonce construction via `write_iv XOR counter`.
- **Ciphertext**: AEAD-encrypted plaintext including the authentication tag.
- **AAD**: `SHA-384(prev_ciphertext_frame)` chained with the session base AAD (`"openhttpa:" + base_id`). Provides chain authentication: modifying any prior frame invalidates all subsequent frames.
- **Content-Type**: `application/x-openhttpa-stream`

The frame format is identical for `EncryptedStream` (server-side decode) and
`trusted_request_streaming` (client-side encode).

---

## 3. Preflight & Handshake Handlers (`handlers`)

Source file: [handlers.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-server/src/handlers.rs)

Contains Axum handler entry points for negotiating preflight parameters and finalizing handshakes.

### `ChallengeKey` (Struct)

A thread-safe container for the preflight challenge HMAC key.

- **`new(key: [u8; 32]) -> Self`**: Wraps a 32-byte secret.
- **`rotate(&self, new_key: [u8; 32])`**: Atomically rotates the active signing key.
- **`read(&self) -> [u8; 32]`**: Reads the active key.

### `AtHsHandlerState` (Struct)

Shared state passed to `aths_handler`.

- Fields: `executor`, `registry`, `tee_provider`, `verifier`, `atb_ttl`, `challenge_key`, and `identity_key`.

### Core Handlers

- **`async fn preflight_handler(State(state): State<Arc<PreflightHandlerState>>) -> Response`**:
  Handles preflight `OPTIONS` requests. Computes and returns supported suites, versions, and a fresh challenge (signed by the `ChallengeKey`).
- **`async fn aths_handler(State(state): State<Arc<AtHsHandlerState>>, req: Request) -> Response`**:
  Handles `ATTEST` handshake requests. Verifies the freshness challenge, executes KEM negotiation via the `AtHsExecutor`, registers the session, and encodes response headers.

---

## 4. Middleware & Resumption (`middleware`)

Source file: [middleware.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-server/src/middleware.rs)

Implements Tower layers for session filtering, Bloom filter replay protection, and 0-RTT session resumption.

### `TrRequestLayer` & `TrRequestMiddleware` (Structs)

A Tower middleware layer that inspects every request's `Attest-Base-ID` header and ensures it maps to a valid session. Inserts `AttestSession` and `AtbId` into request extensions.

### `LocalReplayGuard` (Struct)

An in-memory Bloom filter replay guard for 0-RTT nonces.

- **`new(items: usize, fp_rate: f64) -> Self`**: Sizes a Bloom filter.
- **`with_auto_rotate(items: usize, fp_rate: f64, interval: Duration) -> Arc<Self>`**: Spawns a background task to rotate filters (implements a double-buffer overlap filter to prevent false replays during rotation).
- **`is_near_capacity(&self) -> bool`**: Returns `true` if the active filter is $\ge 80\%$ full.
- **`rotate(&self)`**: Swaps in a fresh Bloom filter, moving the current one to `prev_bloom`.

### `Rtt0ResumptionLayer` & `Rtt0ResumptionMiddleware` (Structs)

Intercepts `Attest-Ticket-Resumption` headers, unseals the session state via the `TicketEngine`, validates the 0-RTT nonce against the `DistributedReplayGuard` atomically, and registers the session.

---

## 5. Rate Limiting (`rate_limit`)

Source file: [rate_limit.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-server/src/rate_limit.rs)

Implements per-IP sliding-window rate limiting.

### `RateLimitLayer` (Struct)

- **`new(max_requests: usize, window: Duration) -> Self`**: Limits requests per IP within the rolling window.
- Spawns a background task to clean up old IP mappings.
- **IPv6 Protection**: Automatically collapses IPv6 addresses to their `/64` prefix to prevent attackers from bypassing limits by cycling through addresses in their allocation.

---

## 6. Persistent Storage Wrappers (`replay_guard_fs`, `replay_guard_redis`, `ticket_engine_fs`)

### `FileReplayGuard<const W: usize = 64>` (Struct)

Source file: [replay_guard_fs.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-server/src/replay_guard_fs.rs)
A persistent, file-backed wrapper around the sliding-window `ReplayGuard`.

- **`new(path: PathBuf) -> Self`**: Restores state if the file exists.
- **`check(&self, nonce: u64) -> Result<(), ReplayError>`**: Performs a validation check.
- **`accept(&self, nonce: u64) -> io::Result<()>`**: Commits a nonce and writes state atomically (`write` to `.tmp` followed by `rename`) with Unix mode `0600`.

### `RedisReplayGuard` (Struct)

Source file: [replay_guard_redis.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-server/src/replay_guard_redis.rs)
Redis-backed implementation of `DistributedReplayGuard`.

- **`new(url: &str, ttl: Duration) -> RedisResult<Self>`**: Connects to Redis.
- **`check_and_accept(...)`**: Performs a single atomic `SET NX PX` command to eliminate TOCTOU windows, and introduces a constant-time timing delay to prevent side-channel timing analysis.

### `FileTicketEngine` (Struct)

Source file: [ticket_engine_fs.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-server/src/ticket_engine_fs.rs)
A key-persisted ticket sealer/unsealer wrapper.

- **`new(path: PathBuf) -> Result<Self, TicketEngineError>`**: Restores ticket keys from disk. Parse failures return `TicketEngineError::Corrupt` instead of silently rekeying (securing tickets against silent invalidation).
- **`rotate(&mut self) -> io::Result<()>`**: Rotates current keys to historical fallbacks and persists.
- **`persist(&self) -> io::Result<()>`**: Atomic write with Unix mode `0600`.

---

## 7. Attested WebSockets (`ws`)

Source file: [ws.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-server/src/ws.rs)

Provides attested, encrypted WebSocket upgrading.

### `AttestWsHandler` (Trait)

Defines the callback handler for accepted WebSockets.

```rust
pub trait AttestWsHandler: Send + Sync + 'static {
    async fn handle(&self, ws: AttestWsSession);
}
```

### Core Functions

- **`async fn attested_ws_upgrade<H: AttestWsHandler>(...) -> Response`**:
  Axum handler that validates the `Attest-Base-ID` header, extracts the session, derives per-channel keys, and upgrades the HTTP socket.

### `AttestWsSession` (Struct)

Encapsulates an active, encrypted WebSocket stream.

- **`async fn send_text(&mut self, text: &str) -> Result<(), WsError>`**: Seals and sends a text frame.
- **`async fn send_binary(&mut self, data: &[u8]) -> Result<(), WsError>`**: Seals and sends a binary frame.
- **`async fn recv(&mut self) -> Option<Result<WsPayload, WsError>>`**: Decrypts and validates incoming frames. Enforces strict monotonic counters on incoming nonces to prevent replay/reordering.
- **`async fn send_ping(&mut self, payload: Vec<u8>) -> Result<(), WsError>`**: Sends unencrypted ping.
- **`async fn close(&mut self) -> Result<(), WsError>`**: Closes the socket gracefully.
- **`const fn algorithm(&self) -> AeadAlgorithm`**: AEAD algorithm in use.
- **`const fn atb_id_bytes(&self) -> &[u8; 16]`**: AAD UUID bytes bound to the channel.
