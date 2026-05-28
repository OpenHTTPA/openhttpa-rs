# openhttpa-core API Documentation

This document provides a comprehensive API reference for the [openhttpa-core](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-core/src/lib.rs) crate. This crate implements the core protocol state machine, handshake executor, and session management logic for **OpenHTTPA** (Attested Hypertext Transfer Protocol version 2).

---

## Table of Contents

1. [State Module (`state`)](#1-state-module-state)
2. [Handshake Module (`handshake`)](#2-handshake-module-handshake)
3. [Session Module (`session`)](#3-session-module-session)
4. [Session Tickets Module (`session::ticket`)](#4-session-tickets-module-sessionticket)
5. [Replay Guard Module (`replay_guard`)](#5-replay-guard-module-replay_guard)

---

## 1. State Module (`state`)

Source file: [state.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-core/src/state.rs)

The `state` module defines the core protocol phase state machine and session resumption stores.

### `ProtocolPhase` (Enum)

Represents the sequential phases of an `OpenHTTPA` session.

```rust
pub enum ProtocolPhase {
    Init,
    Preflight,
    AtHsInProgress,
    Attested,
    AtSpInProgress,
    SecretProvisioned,
    Rtt0,
    Terminated,
}
```

- **`allows_trusted_request(self) -> bool`**: Returns `true` if trusted requests (`TrR`) are permitted in this phase (`Attested`, `SecretProvisioned`, or `Rtt0`).

### `TransitionError` (Enum)

Represents state-transition errors.

- `InvalidTransition { from: ProtocolPhase, to: ProtocolPhase }`
- `NotPermitted { phase: ProtocolPhase }`

### Core Functions

- **`transition(current: ProtocolPhase, next: ProtocolPhase) -> Result<ProtocolPhase, TransitionError>`**: Validates and executes a state transition.

### `PskStore` (Struct)

Thread-safe store for Pre-Shared Keys (PSKs) used for session resumption.

- **`new() -> Self`**: Creates a new, empty `PskStore`.
- **`async fn store_psk(&self, ticket_id: Vec<u8>, psk: Vec<u8>)`**: Stores a PSK associated with a ticket ID.
- **`async fn take_psk(&self, ticket_id: &[u8]) -> Option<Vec<u8>>`**: Retrieves and removes a PSK associated with a ticket ID (enforcing single-use tickets).

---

## 2. Handshake Module (`handshake`)

Source file: [handshake.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-core/src/handshake.rs)

Manages the server-side execution of the Attest Handshake (`AtHS`) under the SIGMA-I protocol model.

### `AtHsExecutor` (Struct)

Orchestrates client verification, key generation, transcript binding, and session key derivation.

#### Constructors

- **`new(supported_suites: Vec<CipherSuite>, supported_versions: Vec<ProtocolVersion>) -> Self`**: Creates an executor with default config (warning: if suites are empty, all preferred suites are accepted).
- **`with_strict_mode(supported_suites: Vec<CipherSuite>, supported_versions: Vec<ProtocolVersion>, strict_attestation: bool) -> Self`**: Creates an executor with explicit control over whether TEE attestation is strictly required.
- **`with_config(supported_suites: Vec<CipherSuite>, supported_versions: Vec<ProtocolVersion>, strict_attestation: bool, allow_debug: bool) -> Self`**: Creates an executor with debug-build permission controls.
- **`with_all(supported_suites: Vec<CipherSuite>, supported_versions: Vec<ProtocolVersion>, strict_attestation: bool, allow_debug: bool, policy_engine: Option<Arc<dyn PolicyEngine>>, revocation_provider: Option<Arc<dyn RevocationProvider>>) -> Self`**: Full constructor with custom verification policies and revocation checkers.
- **`with_zk(self, config: openhttpa_zk::ZkConfig) -> Self`**: (Feature `zk` required) Configures zero-knowledge proof generation parameters.

#### Server Execution Method

```rust
pub async fn execute_server(
    &self,
    req: &AtHsRequest<'_>,
    tee_provider: Option<&dyn TeeProvider>,
    verifier: Option<&dyn QuoteVerifier>,
    identity_key: Option<&openhttpa_crypto::pqc::MlDsaKeyPair>,
) -> Result<(CipherSuite, ProtocolVersion, ServerKeyShare, AtHsResult), HandshakeError>
```

Executes the server-side handshake steps: negotiates parameters, encapsulates hybrid keys, computes transcript hashes, verifies client quotes, signs transcripts, and optionally generates server attestation quotes or ZK proofs.

### `AtHsRequest<'a>` (Struct)

Parameters passed by the caller to execute a handshake:
| Field | Type | Description |
|---|---|---|
| `client_suites` | `&'a [CipherSuite]` | Negotiable cipher suites proposed by the client. |
| `client_versions` | `&'a [ProtocolVersion]` | Protocol versions proposed by the client. |
| `client_random` | `&'a [u8; 32]` | 32-byte fresh client nonce. |
| `client_challenge` | `&'a [u8; 48]` | 48-byte preflight challenge. |
| `client_share` | `&'a ClientKeyShare` | Client public key shares. |
| `client_quotes` | `&'a [AttestQuote]` | TEE attestation reports submitted by the client. |
| `atb_ttl_secs` | `u64` | Time-to-live for the derived session in seconds. |
| `provenance` | `Option<&'a ProvenanceChain>` | Multi-hop agent metadata tracing. |

### `AtHsResult` (Struct)

Key material and metadata generated by a successful handshake:
| Field | Type | Description |
|---|---|---|
| `atb_id` | `AtbId` | Unique 16-byte UUID for the session. |
| `session_keys` | `SessionKeys` | Derived classical and post-quantum keys/IVs. |
| `expires_at` | `Instant` | Monotonic expiry timestamp. |
| `server_quotes` | `Vec<AttestQuote>` | Generated server TEE quotes. |
| `server_random` | `[u8; 32]` | Server-side randomness. |
| `transcript_hash` | `[u8; 48]` | SHA-384 transcript binding hash. |
| `server_signatures` | `Vec<Vec<u8>>` | Identity signatures (ML-DSA). |
| `client_attestation_result` | `Option<VerificationResult>` | Claims parsed and verified from client quote(s). |
| `server_zk_proof` | `Option<Vec<u8>>` | Optional serialized RISC Zero receipt. |

### `HandshakeError` (Enum)

Possible failure cases during the handshake:

- `NoCipherSuiteOverlap`
- `NoVersionOverlap`
- `KeyExchange(String)`
- `KeyDerivation(String)`
- `Serialisation(String)`
- `AttestationRequired`
- `Attestation(String)` (including expiration checks or formatting errors)
- `Revoked(String)` (revocation checking failures)
- `Policy(String)` (policy engine violations)
- `Internal(String)`

---

## 3. Session Module (`session`)

Source files: [mod.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-core/src/session/mod.rs) | [sealed.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-core/src/session/sealed.rs)

Encapsulates active session state (`AtB`) and enforces replay protection and key isolation.

### `AttestSession` (Struct)

Thread-safe session container wrapped in an `Arc<Mutex<SessionInner>>`. Can be cloned cheaply.

#### Core Methods

- **`new(...) -> Self`**: Creates a session from handshake results.
  ```rust
  pub fn new(
      id: AtbId,
      cipher_suite: CipherSuite,
      version: ProtocolVersion,
      keys: SessionKeys,
      expires_at: Instant,
      strategy: ReplayStrategy,
      attestation_result: Option<VerificationResult>,
  ) -> Self
  ```
- **`id(&self) -> AtbId`**: Retrieves the session UUID.
- **`state(&self) -> SessionState`**: Returns a safe, secret-free snapshot of metadata.
- **`is_alive(&self) -> bool`**: Returns `true` if the session hasn't expired.
- **`advance_phase(&self, next: ProtocolPhase) -> Result<(), SessionError>`**: Transitions the internal phase.
- **`peek_keys<F, R>(&self, f: F) -> Result<R, SessionError>`**: Accesses session keys in read-only mode without modifying replay counters. Useful for long-lived sockets that handle their own replay guard.
- **`with_keys_for_trr<F, T, E>(&self, nonce: u64, f: F) -> Result<Result<T, E>, SessionError>`**:
  Wraps request processing with replay protection:
  1. Checks the incoming `nonce` using the chosen `ReplayStrategy`.
  2. Runs the closure `f` with decrypted keys and the current counter.
  3. If `f` succeeds, commits the nonce and increments the client counter.
  4. If `f` fails, rolls back strict-monotonic counters.
- **`with_keys_for_trs<F, R>(&self, f: F) -> Result<R, SessionError>`**: Accesses keys to encrypt a response, incrementing the server-to-client message counter.
- **`export_durable(&self) -> DurableSessionState`**: Snapshots session metadata, secrets, and replay windows for persistent storage.
- **`from_durable(state: DurableSessionState) -> Self`**: Reconstructs a session from a durable snapshot.

### `ReplayStrategy` (Enum)

Specifies how incoming nonces are validated:

- **`StrictMonotonic`**: Requires nonces in strictly ascending order. Best for ordered transports (TCP/HTTP). Minimal overhead.
- **`SlidingWindow(usize)`**: Accepts out-of-order nonces within a sliding bitmask window. Best for unordered transports (UDP/QUIC).
- _Default_: `SlidingWindow(64)` (covers a window of 4096 nonces).

### `SealedSessionKeys` (Struct)

Prevents accidental logging or leaks of raw session keys.

- Implements `Zeroize` and `ZeroizeOnDrop`.
- Implements `Debug` by returning `"[REDACTED]"` for all keys/IVs.
- **`unseal(&self) -> &SessionKeys`**: Safely returns the inner session keys.

---

## 4. Session Tickets Module (`session::ticket`)

Source file: [ticket.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-core/src/session/ticket.rs)

Provides secure encryption and rotation for session resumption tickets (`AtST`).

### `TicketKey` (Struct)

An encryption key structure implementing monotonic nonce counter serialization.

- **`generate() -> Self`**: Generates a cryptographically random 32-byte key starting with counter 1.
- **`from_parts(key: [u8; 32], counter: u64) -> Self`**: Restores a key state.
- **`to_parts(&self) -> ([u8; 32], u64)`**: Exports key parameters.
- **`next_nonce(&self) -> u64`**: Safely increments and returns the next nonce counter.

### `TicketEngine` (Struct)

Manages encryption/decryption keys and rotatable fallbacks.

- **`new(key: TicketKey) -> Self`**: Creates an engine with a current key.
- **`rotate(&mut self)`**: Promotes the current key to `previous_key` and initializes a new active key.
- **`save_to_file<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()>`**: Atomically writes serialized keys to a file with strict Unix permissions (`0600`).
- **`load_from_file<P: AsRef<Path>>(path: P) -> std::io::Result<Self>`**: Restores engine state from a file.
- **`seal_session(&self, state: &DurableSessionState, lifetime: Duration) -> Result<SessionTicket, AeadError>`**: Encrypts durable session states using AES-256-GCM.
- **`unseal_session(&self, ticket: &[u8]) -> Result<DurableSessionState, AeadError>`**: Decrypts tickets, falling back to `previous_key` if necessary, and enforces absolute expiration bounds.

---

## 5. Replay Guard Module (`replay_guard`)

Source file: [replay_guard.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-core/src/replay_guard.rs)

Implements the low-level bitmask-based anti-replay window logic.

### `ReplayGuard<const WINDOW: usize = 64>` (Struct)

Maintains a bit-packed array mapping to seen nonces. A default window size of 64 arrays allows tracking $64 \times 64 = 4096$ concurrent nonces.

- **`new() -> Self`**: Instantiates an empty guard.
- **`check(&self, nonce: u64) -> Result<(), ReplayError>`**: Read-only check for replay or age boundaries.
- **`accept(&self, nonce: u64)`**: Commits a nonce and slides the window forward.
- **`check_and_accept(&self, nonce: u64) -> Result<(), ReplayError>`**: Combined atomic execution check and commit.
- **`export_state(&self) -> (u64, [u64; WINDOW])`**: Exports highest sequence and window bitmask.
- **`import_state(&self, highest: u64, window: [u64; WINDOW])`**: Restores guard state.

### `DistributedReplayGuard` (Trait)

Defines the interface for multi-node deployments requiring atomic, TOCTOU-safe checks (e.g., via Redis).

```rust
pub trait DistributedReplayGuard: Send + Sync {
    async fn check_and_accept(&self, key: &str, nonce: u64) -> Result<(), ReplayError>;

    #[deprecated]
    async fn check(&self, key: &str, nonce: u64) -> Result<(), ReplayError>;

    #[deprecated]
    async fn accept(&self, key: &str, nonce: u64) -> Result<(), ReplayError>;
}
```
