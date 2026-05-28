# SPDX-License-Identifier: Apache-2.0 OR MIT

# Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

# `OpenHTTPA` Technical Specification

This document defines the Layer 7 (Application Layer) protocol for **OpenHTTPA** (Attested Hypertext Transfer Protocol version 2).

## Overview

`OpenHTTPA` provides end-to-end confidential and authenticated communication between a Client and a Trusted Execution Environment (TEE) over standard HTTP/S. Unlike TLS, which terminates at the network edge, `OpenHTTPA` terminates inside the TEE enclave.

## 1. Protocol Phases

The protocol consists of four distinct phases:

### Phase 1: Preflight (`OPTIONS`)

Standard HTTP `OPTIONS` request to negotiate capabilities.

- **Header**: `Attest-Versions: openhttpa`
- **Header**: `Attest-Cipher-Suites: X25519_ML_KEM768_AES256GCM_SHA384, ...`

### Phase 2: Attestation Handshake (AtHS)

The AtHS establishes a session between a client and a TEE-based server.

#### AtHS Methods

`OpenHTTPA` supports two methods for performing the attestation handshake:

1.  **Canonical (Header-based)**: Uses the custom `ATTEST` HTTP method. Parameters are transmitted in `Attest-*` headers (RFC 8941). This is the recommended method for L7 `OpenHTTPA`.
2.  **Web-friendly (JSON-based)**: Uses `POST /api/attest` with a JSON body. This is often easier to implement in browser environments where custom methods may be restricted.

#### Canonical Request Headers

- `Attest-Versions`: List of supported HTTPA versions (e.g., `openhttpa`).
- `Attest-Cipher-Suites`: Ordered list of preferred cipher suites.
- `Attest-Random`: 32-byte fresh client nonce.
- `Attest-Key-Shares`: JSON-encoded public keys (ECDH + ML-KEM).
- `Attest-Base-Creation`: `new` or `resume`.

#### Canonical Response Headers

- `Attest-Version`: Selected protocol version.
- `Attest-Cipher-Suite`: Selected cipher suite.
- `Attest-Random`: 32-byte fresh server nonce.
- `Attest-Key-Share`: JSON-encoded server public keys, ML-KEM ciphertext, and optional server identity key.
- `Attest-Base-ID`: 16-byte session identifier (UUID).
- `Attest-Quotes`: One or more TEE attestation quotes.
- `Attest-Server-Signatures`: Post-quantum and hardware-backed digital signatures (ML-DSA, TEE-ECDSA).
- `Attest-ZK-Proof`: (Optional) Succinct Zero-Knowledge proof (RISC Zero Receipt) verifying the hardware attestation and transcript binding.
- `Attest-Expires`: Session TTL in seconds.
- `Attest-Ticket-Resumption`: Opaque encrypted ticket for session resumption (Phase 5).

### Phase 3: Attest Secret Provisioning (`AtSP`)

Optional phase to deliver long-term secrets to the client inside the established session.

### Phase 4: Trusted Request (`TrR`)

Confidential payload delivery using AEAD.

The request body is encrypted using AES-256-GCM (or negotiated AEAD) using the derived `client_write_key` and a nonce derived from `client_write_iv ^ counter`.

- **AHL (Attested Header List)**: A canonical representation of the request's semantic context used to bind the hardware attestation to the specific intent of the operation. The HMAC input is constructed by concatenating length-prefixed values: `len:METHOD` ‖ `len:PATH` ‖ `len:QUERY` ‖ `len:HEADER1_NAME` ‖ `len:HEADER1_VALUE` ...

  The `len:QUERY` field is mandatory; if no query string is present, a 0-length prefix is used. Sorting of `Attest-*` headers (excluding `Attest-Ticket` and `Attest-Binder`) ensures a deterministic transcript across heterogeneous proxies (Nginx/Caddy).

- **Response**: Encrypted responses are returned as a JSON object: `{"ciphertext": "hex_encoded_data"}` or as raw binary in supported transports.

### Phase 5: Session Resumption

Clients can skip the hybrid KEM handshake using a PSK from a previous session ticket.

- **Header**: `Attest-Ticket: <opaque_ticket_data>`

### Phase 6: Oblivious `OpenHTTPA` (O-HTTPA)

Privacy-preserving transport using HPKE encapsulation.

- **Transports**: `message/oblivious-http`
- **Encapsulation**: HPKE(X25519, HKDF-SHA256, AES-GCM-256)

### Phase 7: ZK-HTTPA (Succinct Proofs)

Optional, high-privacy extension using Zero-Knowledge proofs to wrap TEE attestation.

- **Mechanism**: The server generates a ZK-SNARK (using RISC Zero) that proves the validity of the TEE quote and its binding to the handshake transcript.
- **Benefit**: Eliminates the need to share raw hardware metadata with the client.
- **Header**: `Attest-ZK-Proof` (Receipt bytes).
- **Status**: Disabled by default. Requires explicit opt-in.

## 2. Cryptography

### Hybrid KEM

`OpenHTTPA` mandates hybrid post-quantum resilience:

- **Classical**: X25519 or P-384
- **Post-Quantum**: ML-KEM-768 or ML-KEM-1024 (FIPS 203)
- **Signatures**: ML-DSA-65 or higher (FIPS 204) for post-quantum identity.

### AEAD

Payloads are encrypted using:

- **AES-256-GCM** (default)
- **ChaCha20-Poly1305**

### Nonce Derivation

Nonces for AEAD are 96-bit (12 bytes), derived as:
`nonce = static_iv ^ counter`
Where `counter` is an 8-byte big-endian integer, starting at 1.

### §2.4 Session Key Schedule

The `OpenHTTPA` session key schedule follows **RFC 5869** and is structurally aligned with
**TLS 1.3 §7.1** (RFC 8446). Implementations MUST use the following construction:

#### Step 1 — HKDF-Extract

```
PRK = HKDF-Extract(
    Hash   = SHA-384,
    salt   = [0x00; 48],              // 48 zero bytes (SHA-384 output length)
    IKM    = combined_hybrid_secret   // X25519 ⊕ ML-KEM-768 combined secret
)
```

The salt is the zero-value byte string of hash-output length, per RFC 5869 §2.2. The
combined hybrid secret provides all entropy. A session-specific salt MAY be provided in
future PSK-resumption cipher suites; the zero-salt case is the baseline for full
handshake sessions.

#### Step 2 — HKDF-Expand (per key slot)

```
OKM = HKDF-Expand(
    Hash   = SHA-384,
    PRK    = PRK from step 1,
    info   = b"openhttpa v2 " ‖ label ‖ transcript_hash,
    L      = <slot-specific length>
)
```

The `info` string components:

| Component       | Value                           | Length                            |
| --------------- | ------------------------------- | --------------------------------- |
| Version prefix  | `b"openhttpa v2 "`              | 10 bytes (ASCII, fixed)           |
| Key-slot label  | See table below                 | Variable (ASCII, unique per slot) |
| Transcript hash | `SHA-384(handshake transcript)` | 48 bytes (fixed)                  |

Because `transcript_hash` is always exactly 48 bytes, there is no length ambiguity at
the `label ‖ transcript_hash` boundary.

#### Key Slots

| Slot               | Label                 | Output length | Purpose                           |
| ------------------ | --------------------- | ------------- | --------------------------------- |
| `master_secret`    | `b"master secret"`    | 48 bytes      | Root of the session key hierarchy |
| `client_write_key` | `b"client write key"` | 32 bytes      | AES-256-GCM key for client→server |
| `server_write_key` | `b"server write key"` | 32 bytes      | AES-256-GCM key for server→client |
| `client_write_iv`  | `b"client write iv"`  | 12 bytes      | Base IV for client→server nonces  |
| `server_write_iv`  | `b"server write iv"`  | 12 bytes      | Base IV for server→client nonces  |
| `client_mac_key`   | `b"client mac key"`   | 32 bytes      | HMAC-SHA-384 key for AHL binding  |
| `server_mac_key`   | `b"server mac key"`   | 32 bytes      | HMAC-SHA-384 key for AHL binding  |

#### Domain Separation Properties

The info string enforces three independent domain-separation properties:

1. **Protocol-version separation** — `b"openhttpa v2 "` ensures that keys derived under
   `OpenHTTPA` v2 cannot be confused with keys from any other protocol version, even if the
   same combined secret is used.

2. **Key-slot separation** — each label is unique, guaranteeing computational independence
   between all seven derived keys within a single session.

3. **Session binding** — the transcript hash is collision-resistant (SHA-384) and unique
   per session, tying every key to the exact handshake that established it.

> [!IMPORTANT]
> **Breaking change from pre-ADR-001 builds**: Any implementation derived from
> `openhttpa-rs` prior to the SA-02 fix (where `b"openhttpa handshake v2"` was used as the
> HKDF-Extract salt) will derive **different** keys and will be incompatible with
> updated implementations. See [ADR-001](docs/adr/ADR-001-key-schedule-wire-break.md)
> for the full analysis and migration procedure.

## 3. Headers & SFV

All `OpenHTTPA` headers follow **RFC 8941** (Structured Field Values for HTTP).

| Header                 | Type                | Description                                                                                |
| ---------------------- | ------------------- | ------------------------------------------------------------------------------------------ |
| `Attest-Base-ID`       | String              | Unique session identifier (UUID v4).                                                       |
| `Attest-Versions`      | List                | Negotiated protocol versions.                                                              |
| `Attest-Cipher-Suites` | List                | Negotiated cipher suites.                                                                  |
| `Attest-Quotes`        | List of Inner Lists | One or more TEE quotes, encoded as `(type_token bytes_sequence)`.                          |
| `Attest-Ticket`        | Byte Sequence       | Binary trailer: `BE_u64(counter)` ‖ `HMAC_SHA384(AHL)`.                                    |
| `Attest-Binder`        | Byte Sequence       | Binary trailer: `BE_u64(req_counter)` ‖ `HMAC_SHA384(resp_AHL)`.                           |
| `Attest-Provenance`    | List                | JSON-encoded list of `AgentMetadata` for multi-hop tracking.                               |
| `Attest-EAT`           | Byte Sequence       | CBOR-encoded Entity Attestation Token (RFC 9334).                                          |
| `Attest-Policies`      | Dictionary          | Policy flags: `namespace="mcp"`, `debug=?0`, `keyword-intent="execute"`, `sig-binding=?1`. |

### Attested Provenance (P-01)

Multi-hop agent communication uses the `Attest-Provenance` header to maintain a cryptographic chain of custody. Each agent appends its `AgentMetadata` to the list before delegating to the next hop.

```json
[
  {
    "id": "uuid-agent-origin",
    "name": "Decision Engine",
    "capabilities": ["orchestration"],
    "endpoint": "http://engine.local:8080",
    "public_key": "...",
    "last_quote": { ... }
  },
  {
    "id": "uuid-agent-hop-1",
    "name": "SQL Executor",
    "capabilities": ["read_db"],
    "endpoint": "http://db-tool.local:8080",
    "public_key": "...",
    "last_quote": { ... }
  }
]
```

## 4. Security Recommendations

1. **Zeroize Secrets**: All implementations MUST zeroize key material in memory after use.
2. **Replay Protection**: Servers MUST implement a sliding window or monotonic counter replay guard.
3. **Semantic Binding**: The AHL MUST bind the HTTP method, URI path, and **query string** to prevent request re-routing and parameter manipulation attacks.
4. **AAD Binding**: AEAD AAD MUST include the `Attest-Base-ID` to prevent session-mixup attacks.
5. **Canonical Transcript**: Handshake transcripts MUST use length-prefixed binary fields to ensure consistent cross-platform hashing. Transcripts MUST bind the full **48-byte** preflight challenge to ensure high entropy and transcript integrity.
6. **EAT Alignment**: Attestation verification MUST validate EAT-standard claims (RFC 9334) and platform extensions:
   - `ueid`: Unique Entity ID (Hardware-bound).
   - `hwmodel`: Hardware Model (e.g., "NVIDIA Hopper H100").
   - `dbgstat`: Debug Status (MUST be 0 for production).
   - `iat`: Issued At (MUST be less than 24 hours old to mitigate ARL Rollback T-09).
   - `boot_progress`: Verified boot measurements.
   - `security_version`: Platform-specific TCB versioning (e.g. SVN) to reject unpatched hardware.
7. **Durable Replay Protection**: To prevent replay across server restarts, implementations SHOULD use persistent `NonceSequence` storage (e.g. `FileNonceSequence`) to ensure counter monotonicity is preserved across process lifecycles.
8. **Resource Protection**: Implementations MUST enforce upper limits on active sessions (e.g., 10,000 per registry) and background cleanup tasks for rate-limiting state to mitigate memory exhaustion DoS.

## 5. Agentic AI Integration

`OpenHTTPA` provides a secure transport for autonomous agents and Model Context Protocol (MCP) tool execution.

### Confidential Tool Execution (MCP)

Tools are invoked via the `TrR` phase (Phase 4). The JSON-RPC 2.0 request is encrypted as the body of a `POST /api/mcp` request.

- **Request**: `{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "...", "arguments": {...}}, "id": 1}`
- **Response**: Encrypted JSON-RPC result or error.

### Agent-to-Agent (A2A) Messaging

M-HTTPA (Mutual `OpenHTTPA`) allows two agents to mutually attest to each other.

- **Handshake**: Both parties exchange `Attest-Quotes` during AtHS.
- **Messaging**: Messages are exchanged as `TrR` payloads over the established mutual session.

## 6. Heterogeneous Hardware Synchronization (H-01)

`OpenHTTPA` supports the simultaneous attestation of multiple hardware providers (e.g., Host CPU + Accelerator GPU) in a single unified handshake.

### Canonical Encoding

Multiple quotes are encoded in the `Attest-Quotes` header as an RFC 8941 **List of Inner Lists**. Each inner list contains:

1. A **Token** identifying the TEE type (e.g., `intel_tdx`, `nvidia_gpu`).
2. A **Byte Sequence** containing the raw attestation report/quote.

### Transcript Binding

To prevent "Hardware Splitting" and "Cross-Role Reuse" attacks (T-10), the protocol MUST bind the session transcript hash to the `ReportData` or `Nonce` field of every hardware provider's report using a domain-separated prefix.

- **Format**: `report_data = [16-byte prefix] || [48-byte SHA-384 transcript hash]`
- **Prefixes**:
  - `openhttpa hs client`: Used for quotes generated by the client during AtHS.
  - `openhttpa hs server`: Used for quotes generated by the server during AtHS.

Verification succeeds ONLY if all provided quotes are valid, all quotes are bound to the identical transcript hash, and all prefixes match the expected role.

## 7. Attested Agent Mesh (AAM) & Transitive Trust (A-01)

AAM extends `OpenHTTPA` to a graph of agents where trust is transitive across hardware-verified hops.

### Transitive Trust Property

AAM ensures that if Agent A trusts Agent B (via `OpenHTTPA`) and Agent B trusts Agent C (via `OpenHTTPA`), Agent A can verify the provenance of Agent C's contributions to a shared task.

### Intent Binding via AHL

In multi-hop delegation, the **AHL (Attest Header List)** mechanism is used to bind the "Intent" of the original user to the final execution.

1. User A sends a signed request for `POST /tools/execute { "tool": "search" }`.
2. Agent B (Coordinator) delegates this to Agent C (Specialist).
3. Agent B MUST include User A's original `Attest-Ticket` (MAC of User A's AHL) in its delegation to Agent C.
4. Agent C verifies that the delegated tool call matches the semantic intent bound in User A's original AHL.

This prevents Agent B from using its attested session with Agent C to execute unauthorized tools on behalf of User A.

### Provenance Chain Data Structure

The `Attest-Provenance` header maintains an immutable log of the delegation path. Each node appends an entry:
`ProvEntry = { NodeID, Capability, TranscriptHash, Signature(NodeSecret, TranscriptHash ‖ PrevEntryHash) }`

## 8. Configurable Policy Engine (P-02)

`OpenHTTPA` provides a strict, configurable policy engine to enforce domain-specific rules during the attestation handshake. Policies are transmitted in the `Attest-Policies` dictionary.

- **Namespace Enforcement**: Isolates requests to explicit authorized boundaries (e.g., `namespace="mcp"`).
- **Debug Prevention**: Explicitly rejects attestation from hardware running in debug or developer mode (`debug=?0`), mitigating vulnerability surfaces.
- **Keyword Intent**: Enforces application-layer operations (e.g., `keyword-intent="execute"`), ensuring the agent's intent is cryptographically bound to the session.

## 9. ZAA Compression & Optimization

To reduce the bandwidth overhead of large hardware attestation quotes (e.g. AMD SEV-SNP or composite quotes), `OpenHTTPA` supports optional ZAA (Zstandard Attestation Archival) compression over the attestation payload. This drastically reduces the size of the `Attest-Quotes` header during the Preflight and Handshake phases.
