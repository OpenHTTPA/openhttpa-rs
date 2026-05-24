# openhttpa-a2a — API Specification

**Crate**: `openhttpa-a2a`  
**License**: Apache-2.0 OR MIT  
**Edition**: Rust 2021  
**Repository**: [openhttpa-rs](file:///home/ub/tmp/openhttpa-rs)

---

## Overview

`openhttpa-a2a` implements the **Agent-to-Agent (A2A) protocol** over OpenHTTPA. It provides the foundational building blocks for secure, attested communication between autonomous agents running inside TEEs. Each agent can perform mutual attestation with its peers before exchanging messages.

> **Note**: Full mutual attestation (mHTTPA) for agent handshakes is pending full implementation. The current release stubs the A2A handshake and uses the standard server-side attestation flow. This is tracked as `A2A-STUB-01`.

---

## Table of Contents

1. [Message Types (`types`)](#1-message-types)
2. [Agent (`A2AAgent`)](#2-agent-a2aagent)
3. [Router (`AgentRouter`)](#3-router-agentrouter)
4. [Handshake (`handshake`)](#4-handshake)

---

## 1. Message Types

Source: [types.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-a2a/src/types.rs)

### `A2AMessage` (Struct)

A structured message sent between agents over an encrypted A2A channel.

```rust
pub struct A2AMessage {
    pub from: String,              // Sender agent ID
    pub to: String,                // Target agent ID
    pub payload: serde_json::Value, // Arbitrary JSON payload
    pub message_id: String,        // UUID v4 for correlation and deduplication
    pub timestamp: u64,            // Unix timestamp of creation
}
```

| Field        | Type                | Description                                  |
| ------------ | ------------------- | -------------------------------------------- |
| `from`       | `String`            | Sender agent identifier.                     |
| `to`         | `String`            | Target agent identifier.                     |
| `payload`    | `serde_json::Value` | Application-defined message content.         |
| `message_id` | `String`            | UUID v4 message correlation identifier.      |
| `timestamp`  | `u64`               | Message creation time as Unix epoch seconds. |

---

## 2. Agent

Source: [agent.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-a2a/src/agent.rs)

### `A2AAgent` (Struct)

An autonomous agent capable of secure A2A communication.

```rust
pub struct A2AAgent {
    pub agent_id: String,
    client: OpenHttpaClient,  // private
}
```

#### Construction

```rust
pub fn new(agent_id: &str) -> Result<Self, String>
```

Creates a new agent with a default `OpenHttpaClient` configured for:

- `server_uri = "http://127.0.0.1:8080"`
- `MockTeeProvider` (for development)
- `require_preflight = true`

**Errors**: Returns `Err(String)` if the underlying client construction fails.

```rust
pub fn new_with_client(agent_id: &str, client: OpenHttpaClient) -> Self
```

Creates an agent with an explicitly configured `OpenHttpaClient`. Use this in production environments to set a production `TeeProvider` and `QuoteVerifier`.

```rust
pub const fn client(&self) -> &OpenHttpaClient
```

Returns an immutable reference to the underlying `OpenHttpaClient`.

---

#### `connect_to_agent`

```rust
pub async fn connect_to_agent(&self, target_url: &str) -> Result<(), String>
```

Performs the `AtHS` handshake with the target agent at `target_url` and sends a single `POST /api/a2a` message with body `{"agent_id": ..., "action": "handshake"}`.

This is the high-level connection entry point. It:

1. Calls `self.client.attest_handshake()`.
2. Sends the handshake JSON via `trusted_request`.

**Note** (`A2A-STUB-01`): Full mutual attestation is not yet implemented. The client sends a TEE quote only if the underlying `OpenHttpaClient` has a real `TeeProvider`; the target agent does not currently send its quote back for client-side verification.

**Errors**: Returns `Err(String)` if the handshake or the request fails.

---

#### `send_message`

```rust
pub async fn send_message(&self, _target_url: &str, msg: A2AMessage) -> Result<(), String>
```

Sends a confidential `A2AMessage` to the target agent.

1. Performs a fresh `AtHS` handshake.
2. Serialises `msg` as JSON.
3. Sends via `trusted_request` to `POST /api/a2a`.

> **Note**: In a production implementation, sessions should be cached and reused until expiry. The current implementation performs a full handshake per message for simplicity.

**Errors**: Returns `Err(String)` if serialisation, handshake, or transmission fails.

---

## 3. Router

Source: [router.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-a2a/src/router.rs)

### `AgentRouter` (Struct)

Routes incoming `A2AMessage` objects to registered handler functions by message type.

```rust
pub use router::AgentRouter;
```

#### Methods

```rust
pub fn new() -> Self
```

Creates an empty router.

```rust
pub fn register<F, Fut>(&mut self, action: &str, handler: F)
where
    F: Fn(A2AMessage) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), String>> + Send + 'static,
```

Registers an async handler for a given action string. The action is matched against the `payload["action"]` field of incoming messages.

```rust
pub async fn dispatch(&self, msg: A2AMessage) -> Result<(), String>
```

Dispatches a message to its registered handler.

**Errors**:

- `Err(String)` containing `"No handler for action: {action}"` if no handler is registered.
- `Err(String)` from the handler itself.

---

## 4. Handshake

Source: [handshake.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-a2a/src/handshake.rs)

### `execute_client_handshake`

```rust
pub fn execute_client_handshake() -> Result<(), String>
```

> **Stub** (`A2A-STUB-01`): Returns `Err("A2A mHTTPA handshake not yet implemented")`.

The mutual HTTPA (mHTTPA) handshake — where both the client agent and the server agent exchange and verify each other's TEE quotes — is not yet implemented. Once implemented, this function will:

1. Generate a client TEE quote.
2. Send the quote to the peer.
3. Receive and verify the peer's TEE quote.
4. Derive symmetric session keys.

---

## Public API Surface

```rust
pub use agent::A2AAgent;
pub use router::AgentRouter;
pub use types::*;  // A2AMessage
```

---

## Dependency Graph Position

```
openhttpa-a2a
├── openhttpa-client  (OpenHttpaClient — AtHS, trusted_request)
├── openhttpa-tee     (MockTeeProvider — default in new())
├── serde + serde_json
└── tracing
```
