# openhttpa-mesh — API Specification

**Crate**: `openhttpa-mesh`  
**License**: Apache-2.0 OR MIT  
**Edition**: Rust 2021  
**Repository**: [openhttpa-rs](file:///home/ub/tmp/openhttpa-rs)

---

## Overview

`openhttpa-mesh` implements the **Attested Agent Mesh (AAM)** — a network of AI agents where each agent's identity and runtime environment are hardware-verified by TEE attestation before any communication is permitted. It provides:

- `AgentNode`: A TEE-attested node that can connect to peers, enforce admission policy, and invoke peer tools via MCP.
- `AgentRegistry`: A service-discovery registry for locating peers by capability.
- `PolicyEngine`: A pluggable admission-control policy layer, with a built-in Open Policy Agent (OPA) Rego engine.
- Provenance tracking: each request chain carries an `Attest-Provenance` header logging every hop.

---

## Table of Contents

1. [Session Types](#1-session-types)
2. [Error Type: `MeshError`](#2-error-type-mesherror)
3. [Agent Node: `AgentNode`](#3-agent-node-agentnode)
4. [Policy Engine](#4-policy-engine)
5. [Agent Registry](#5-agent-registry)

---

## 1. Session Types

Source: [lib.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-mesh/src/lib.rs)

### `AgentSession` (Struct)

Represents a live, attested session between two mesh agents.

```rust
pub struct AgentSession {
    pub peer_metadata: AgentMetadata,   // Verified metadata of the remote peer
    pub session: Arc<AttestSession>,    // The underlying OpenHTTPA session
}
```

| Field           | Type                 | Description                                                       |
| --------------- | -------------------- | ----------------------------------------------------------------- |
| `peer_metadata` | `AgentMetadata`      | Name, capabilities, endpoint, and last quote of the remote agent. |
| `session`       | `Arc<AttestSession>` | The established `AttestSession` (keys, AtB ID, expiry).           |

---

## 2. Error Type: `MeshError`

`#[non_exhaustive]`.

| Variant                | Description                                             |
| ---------------------- | ------------------------------------------------------- |
| `Handshake(String)`    | AtHS or reconnection failure.                           |
| `Attestation(String)`  | Server quote verification failure or policy rejection.  |
| `PeerNotFound(String)` | The requested agent UUID was not found in the registry. |
| `Mcp(String)`          | MCP JSON-RPC serialisation or dispatch failure.         |
| `Registry(String)`     | Registry lookup, heartbeat, or registration failure.    |

---

## 3. Agent Node: `AgentNode`

Source: [node.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-mesh/src/node.rs)

The central entity in the mesh. Each `AgentNode` holds an identity (`AgentMetadata`), an embedded `OpenHttpaMcpServer` for hosting tools, a session cache, and references to the TEE provider, verifier, transport, and policy engine.

### Construction

```rust
pub fn new(
    name: String,
    capabilities: Vec<String>,
    endpoint: String,
    registry: Arc<dyn AgentRegistry>,
    tee_provider: Arc<dyn TeeProvider>,
    verifier: Arc<dyn QuoteVerifier>,
    transport: Arc<dyn AttestTransport>,
    policy_engine: Arc<dyn PolicyEngine>,
) -> Self
```

Creates a new `AgentNode` with a freshly generated UUID v4 identity.

| Parameter       | Description                                                                                      |
| --------------- | ------------------------------------------------------------------------------------------------ |
| `name`          | Human-readable agent name.                                                                       |
| `capabilities`  | List of capability tokens (e.g. MCP tool names this node provides).                              |
| `endpoint`      | Full URI of this node's server (e.g. `"http://agent-a:8080"`). Used by peers to reach this node. |
| `registry`      | Agent discovery registry.                                                                        |
| `tee_provider`  | TEE hardware provider for quote generation.                                                      |
| `verifier`      | Quote verifier for peer attestation.                                                             |
| `transport`     | Transport adapter for outgoing connections.                                                      |
| `policy_engine` | Admission policy engine.                                                                         |

### Accessors

```rust
pub const fn metadata(&self) -> &AgentMetadata
```

Returns this node's `AgentMetadata` (ID, name, capabilities, endpoint).

```rust
pub fn mcp_server(&self) -> Arc<OpenHttpaMcpServer>
```

Returns the embedded `OpenHttpaMcpServer`. Call `mcp_server().add_tool(...)` to register tools.

---

### `connect_to_peer`

```rust
#[instrument(skip(self), fields(agent_id = %peer_id))]
pub async fn connect_to_peer(&self, peer_id: Uuid) -> Result<Arc<AgentSession>, MeshError>
```

Establishes a mutually-attested session with a peer agent, enforcing the configured admission policy.

#### Steps

1. **Session cache check**: Returns an existing live session from `self.sessions` if present.
2. **Peer discovery**: Calls `self.registry.get_agent(peer_id)`. Returns `Err(MeshError::PeerNotFound)` if not found.
3. **AtHS handshake**: Builds an `OpenHttpaClient` with `strict_attestation = true` and calls `attest_handshake()`.
4. **Policy enforcement**: If the session includes an attestation result, evaluates the result against the configured policy engine using a structured JSON input:
   ```json
   {
     "src_id": "<this node's UUID>",
     "dst_id": "<peer UUID>",
     "claims": { ... },
     "tcb_status": "UpToDate",
     "pqc_bound": true,
     "timestamp": 1716000000
   }
   ```
   Returns `Err(MeshError::Attestation(...))` if the policy denies the connection.
5. **Session storage**: Inserts the `AgentSession` into the session cache under `peer_id`.
6. Returns `Arc<AgentSession>`.

---

### `call_peer_tool`

```rust
pub async fn call_peer_tool(
    &self,
    peer_id: Uuid,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, MeshError>
```

Calls a tool on a peer agent using MCP over the encrypted OpenHTTPA session, with a default empty provenance chain.

A convenience wrapper over `call_peer_tool_with_provenance`.

---

### `call_peer_tool_with_provenance`

```rust
#[instrument(skip(self, params, provenance), fields(peer_id = %peer_id, method = %method))]
pub async fn call_peer_tool_with_provenance(
    &self,
    peer_id: Uuid,
    method: &str,
    params: serde_json::Value,
    mut provenance: ProvenanceChain,
) -> Result<serde_json::Value, MeshError>
```

Calls a tool on a peer agent, attaching a provenance chain to the request.

#### Steps

1. Calls `connect_to_peer(peer_id)` to get or establish a session.
2. Appends this node's `AgentMetadata` to `provenance` (P-01 provenance tracking).
3. Constructs a JSON-RPC 2.0 MCP request.
4. Serialises the provenance chain as JSON and encodes it as an RFC 8941 Byte Sequence in the `Attest-Provenance` header.
5. Calls `OpenHttpaClient::trusted_request_ext(session, "POST", "/api/mcp", req_bytes, extra_headers)`.
6. Parses the decrypted response as `serde_json::Value` and returns it.

---

### `start_heartbeat`

```rust
pub fn start_heartbeat(&mut self, interval: std::time::Duration)
```

Starts a background Tokio task that calls `self.registry.heartbeat(self.metadata.id)` on the configured interval. The heartbeat task is aborted when `AgentNode` is dropped (via `Drop` impl).

---

### `Drop` Implementation

```rust
impl Drop for AgentNode {
    fn drop(&mut self) {
        if let Some(handle) = self.heartbeat_handle.take() {
            handle.abort();
        }
    }
}
```

Ensures the heartbeat task is cancelled when the node is dropped, preventing resource leaks.

---

## 4. Policy Engine

Source: [policy.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-mesh/src/policy.rs)

### `PolicyEngine` (Trait)

The extension point for mesh admission-control policies.

```rust
#[async_trait]
pub trait PolicyEngine: Send + Sync {
    async fn evaluate_ext(
        &self,
        policy_id: &str,
        input: serde_json::Value,
    ) -> Result<PolicyResult, MeshError>;
}
```

| Method                           | Description                                                                  |
| -------------------------------- | ---------------------------------------------------------------------------- |
| `evaluate_ext(policy_id, input)` | Evaluates the JSON `input` against the named policy. Returns `PolicyResult`. |

### `PolicyResult` (Struct)

```rust
pub struct PolicyResult {
    pub allow: bool,       // Whether the policy permits the action
    pub policy_id: String, // Name of the policy that was evaluated
    pub reason: Option<String>, // Optional reason for denial
}
```

### `RegoPolicyEngine` (Struct)

An OPA Rego-based policy engine backed by the `regorus` crate.

```rust
pub use policy::RegoPolicyEngine;
```

#### Constructors

```rust
pub fn new(policy_id: String, rego_source: String) -> Result<Self, MeshError>
```

Creates an engine with a named Rego policy source.

```rust
pub fn permissive() -> Self
```

Creates an engine with the default permissive policy:

```rego
package openhttpa.mesh
default allow = true
```

Useful for development and testing environments where attestation policy should not block connections.

---

## 5. Agent Registry

Source: [registry.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-mesh/src/registry.rs)

### `AgentRegistry` (Trait)

Abstracts agent discovery and registration.

```rust
#[async_trait]
pub trait AgentRegistry: Send + Sync {
    async fn register(&self, metadata: AgentMetadata) -> Result<(), String>;
    async fn get_agent(&self, id: Uuid) -> Result<Option<AgentMetadata>, String>;
    async fn search(&self, capability: &str) -> Result<Vec<AgentMetadata>, String>;
    async fn heartbeat(&self, id: Uuid) -> Result<(), String>;
}
```

| Method      | Description                                             |
| ----------- | ------------------------------------------------------- |
| `register`  | Registers an agent's metadata in the registry.          |
| `get_agent` | Looks up an agent by UUID. Returns `None` if not found. |
| `search`    | Searches for agents that expose a given capability.     |
| `heartbeat` | Updates the last-seen timestamp for an agent.           |

### `MockRegistry` (Struct)

An in-memory implementation of `AgentRegistry` for testing.

```rust
pub use registry::MockRegistry;
```

| Method             | Description                                      |
| ------------------ | ------------------------------------------------ |
| `fn new() -> Self` | Creates an empty registry backed by a `DashMap`. |

---

## Public API Surface

```rust
pub use node::AgentNode;
pub use openhttpa_proto::{AgentMetadata, ProvenanceChain};
pub use policy::{PolicyEngine, RegoPolicyEngine};
pub use registry::AgentRegistry;

// Types
pub struct AgentSession { pub peer_metadata: AgentMetadata; pub session: Arc<AttestSession>; }
pub enum MeshError { ... }
```

---

## Dependency Graph Position

```
openhttpa-mesh
├── openhttpa-client      (OpenHttpaClient)
├── openhttpa-core        (AttestSession)
├── openhttpa-proto       (AgentMetadata, ProvenanceChain, AttestQuote)
├── openhttpa-headers     (HDR_ATTEST_PROVENANCE, encode_attest_provenance)
├── openhttpa-mcp         (OpenHttpaMcpServer)
├── openhttpa-attestation (QuoteVerifier)
├── openhttpa-tee         (TeeProvider)
├── openhttpa-transport   (AttestTransport)
├── regorus               (OPA Rego policy evaluation)
├── dashmap               (concurrent session/registry maps)
├── uuid                  (agent identity)
└── tracing
```
