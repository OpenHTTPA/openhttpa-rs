# `OpenHTTPA`

<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org) -->

> The authoritative reference implementation of the **OpenHTTPA** protocol — a post-quantum,
> hardware-attested application transport standard engineered for Zero-Trust confidential
> computing across HTTP/2, HTTP/3, and gRPC architectures.

[![CI](https://github.com/openhttpa/openhttpa-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/openhttpa/openhttpa-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Table of contents

- [Features](#features)
- [Repository layout](#repository-layout)
- [Technical Specification (API.md)](API.md)
- [Contributing](#contributing)
- [Prerequisites](#prerequisites)
- [Quick start](#quick-start)
- [Build](#build)
- [Test](#test)
- [Language bindings](#language-bindings)
- [Examples](#examples)
- [Running the demo](#running-the-demo)
- [Standards & Compliance](#standards--compliance)
- [Security](#security)
- [License](#license)

## Why `OpenHTTPA`?

Traditional Transport Layer Security (TLS) terminates at the network edge (e.g., load balancers or ingress controllers), exposing plaintext data-in-transit to internal network topographies, privileged administrators, and host operating system vulnerabilities.

**OpenHTTPA** establishes a novel paradigm for high-assurance confidential computing by enforcing cryptographic termination directly within a hardware-isolated **Trusted Execution Environment (TEE)** (e.g., Intel TDX, AMD SEV-SNP, AWS Nitro Enclaves, ARM TrustZone). This architectural shift provides formal cryptographic assurance that data is exclusively decrypted by an explicitly authorized, cryptographically measured enclave—effectively removing the cloud service provider and host infrastructure from the Trusted Computing Base (TCB).

### Core Architecture

- **Hardware-Rooted Trust (SIGMA-I)**: Integrates hardware attestation quotes (Entity Attestation Tokens) directly into the key exchange, enabling mutual, hardware-verified authentication.
- **Semantic Context Binding**: Introduces the Attested Header List (AHL) to cryptographically bind Application Layer (L7) semantics (HTTP Method, Request-URI) to the session MAC, mitigating Confused Deputy and semantic re-routing vectors.
- **Post-Quantum Cryptographic Agility**: Implements a hybrid key exchange and signature scheme utilizing NIST-standardized ML-KEM-768 and ML-DSA-65 to ensure resilience against "Harvest Now, Decrypt Later" (HNDL) quantum threats.

## Use Cases

`OpenHTTPA` serves as the foundational transport protocol for Zero-Trust, high-assurance distributed systems:

- **Confidential AI & LLM Inference**: Facilitates the secure transmission of regulated datasets (e.g., PHI, PII) to cloud-hosted Large Language Models. Ensures strict privacy preservation, preventing infrastructure providers from observing prompts, responses, or model weights.
- **Secure Multi-Party Computation (MPC)**: Enables cross-organizational data pooling for joint cryptographic analysis. Ensures mathematical non-disclosure of raw constituent data to participating nodes or the central aggregator.
- **Attested Agentic Swarms**: Empowers autonomous AI agents to perform mutually authenticated handshakes (M-HTTPA). Agents cryptographically verify peer execution environments and operational prompts prior to executing high-value transactions or sharing sensitive context.
- **High-Assurance Web3 Oracles**: Establishes trustless bridges for off-chain Web2 API data ingress. Utilizes TEE-attested provenance chains coupled with ZK-STARK zero-knowledge proofs to eliminate reliance on trusted intermediary oracle nodes.

## Protocol Capabilities & Feature Specifications

- **Cryptographic Protocol Adherence**: Strictly implements the Preflight, Attested Handshake (AtHS utilizing SIGMA-I), Attested Session Protocol (AtSP), and Ticket-based Resumption (TrR) state machines defined in the foundational specifications.
- **Post-Quantum Cryptographic Readiness (FIPS 203/204)**: Integrates hybrid X25519/ML-KEM-768 Key Encapsulation Mechanisms (KEM) and ML-DSA-65 post-quantum digital signatures, complemented by SLH-DSA fallback vectors.
- **FIPS 140-3 Compliant Cryptography**: Employs the `aws-lc-rs` cryptographic provider (AWS Libcrypto for Rust), leveraging FIPS-validated cryptographic boundaries when compiled with compliance flags.
- **Agnostic Hardware Root of Trust**: Provides seamless, vendor-agnostic abstractions over prominent Trusted Execution Environments, including Intel SGX, Intel TDX, AMD SEV-SNP, AWS Nitro Enclaves, and ARM TrustZone.
- **Composite Attestation Modalities**: Facilitates simultaneous, unified session attestation spanning heterogeneous compute architectures (e.g., verifying Intel TDX CPU integrity alongside NVIDIA Hopper GPU secure execution states).
- **Transport Layer Independence**: Designed for agnostic multiplexing over HTTP/2 (`hyper`/`h2`), HTTP/3 (`quinn`/`h3`), and Remote Procedure Calls via gRPC (`tonic`).
- **Comprehensive FFI Binding Surface**: Exposes memory-safe Foreign Function Interfaces for Python (`PyO3`/`maturin`), Node.js (`napi-rs`), ANSI C (`cbindgen`), and Go (`cgo`).
- **Autonomous Agentic Architectures**: Natively provisions the Attested Agent Mesh (AAM) and Model Context Protocol (MCP) enabling secure, confidential multi-hop tool delegation among decentralized AI agents.
- **Production-Grade Resilience**: Implements durable cryptographic nonce persistence, real-time Attestation Revocation List (ARL) evaluations, and strict monotonic counter synchronization to preclude replay vectors.
- **Cryptographic Semantic Context**: Integrates the Attest Header List (AHL) to mathematically bind Application Layer (L7) semantics (HTTP Method, Request-URI) to the session MAC, definitively neutralizing semantic re-routing and confused deputy attacks.
- **Trustless Blockchain Oracles**: Bridges deterministic Web2 API responses to EVM/Bitcoin networks utilizing TEE-attested provenance derivations coupled with Zero-Knowledge (ZK-STARK) succinct execution proofs.
- **Canonical Handshake Transcripts**: Enforces length-prefixed, deterministically serialized binary fields for all handshake transcripts, guaranteeing exact cross-platform cryptographic hash derivation.
- **Rigorous Software Quality Assurance**: Enforces strict `#![deny(warnings)]` workspace compiler configurations and employs continuous static analysis to guarantee memory safety and deterministic operational behavior.

## Formal Cryptographic Verification

The `OpenHTTPA` protocol architecture has been subjected to exhaustive, machine-checked formal security audits utilizing industry-standard cryptographic verification frameworks.

- **ProVerif Symbolic Modeling (`formal/handshake.pv`)**:
  - **Cryptographic Secrecy**: Formally proved that all established session keys remain computationally confidential, even in the presence of an active, network-controlling Dolev-Yao adversary.
  - **Injective Authentication**: Verified perfect injective agreement between the initiator and responder, cryptographically anchored by TEE hardware measurements and quotes.
- **Tamarin Prover Temporal Analysis (`formal/handshake.spthy`)**:
  - **Perfect Forward Secrecy (PFS)**: Mathematically validated that the catastrophic compromise of long-term enclave identity keys (e.g., Device Identity Keys) unequivocally does not result in the retroactive compromise of historical session traffic.

Based on these formal models, the protocol is mathematically guaranteed to withstand sophisticated replay attacks, active transcript-mismatch manipulation, and cross-session mix-up vectors.

## Repository layout

```
Makefile                          Monorepo management (build, test, demo)
CONTRIBUTING.md                   Contribution guidelines
Cargo.toml                        Workspace root
crates/
  openhttpa-proto/                   Protocol types and error codes
  openhttpa-crypto/                  Key exchange, PQC, AEAD, HKDF, signatures
  openhttpa-headers/                 Attest-* HTTP header encode/decode (RFC 9651 SFV)
  openhttpa-core/                    Protocol state machine (AtHS / AtSP / TrR)
  openhttpa-tee/                     TEE providers (Mock / SGX / TDX / SEV-SNP / TrustZone)
  openhttpa-attestation/             Quote verification (Mock / MAA / DCAP / AMD SNP)
  openhttpa-transport/               HTTP/2 + HTTP/3 transport adapters
  openhttpa-grpc/                    tonic gRPC service + .proto definition
  openhttpa-server/                  Axum server SDK (AtHS handler + TrR middleware)
  openhttpa-client/                  Async Rust client SDK
  openhttpa-llm/                     Confidential LLM inference client
  openhttpa-mcp/                     Model Context Protocol (MCP) over `OpenHTTPA`
  openhttpa-mesh/                    Attested Agent Mesh (AAM) & Swarm orchestration
  openhttpa-oracle/                  Confidential Web2-to-Web3 Oracle Bridge
  openhttpa-contract/                On-chain verifiers (Solidity, Bitcoin Taproot)
  openhttpa-a2a/                      High-level Agent-to-Agent secure messaging
bindings/
  ...
modules/
  caddy/                          Caddy proxy module            →  modules/caddy/README.md
  nginx/                          Nginx proxy module (Rust FFI) →  modules/nginx/README.md
  browser-extension/              Chrome/Edge extension         →  modules/browser-extension/README.md
demo/
  multiparty-webapp/
    backend/                      Axum demo server
    frontend/                     Plain HTML/JS frontend
    docker-compose.yml            One-command demo launch
    Dockerfile.backend
.github/
  workflows/
    ci.yml                        Lint + test + bindings CI
    release.yml                   PyPI + npm + GitHub Release
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on coding standards, monorepo structure, and the pull request process.

## Prerequisites

| Tool                        | Min version                                                                | Purpose                                                                          |
| --------------------------- | -------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| Rust + Cargo                | **≥ 1.88** (pinned via `rust-toolchain.toml` — `rustup` will auto-install) | All Rust crates and bindings                                                     |
| Docker + Compose            | any                                                                        | Demo (`docker compose up`)                                                       |
| pnpm                        | 10+                                                                        | JS/TS package management (mandatory)                                             |
| System Tools                | -                                                                          | `cmake`, `clang`, `nasm`, `perl`, `go`, `pkg-config`, `python3-dev`, `wasm-pack` |
| Python 3.9 + maturin 1.7    | optional                                                                   | Python binding                                                                   |
| Node.js 18 + @napi-rs/cli 3 | optional                                                                   | Node.js binding                                                                  |
| Go 1.22 + C compiler        | optional                                                                   | Go binding                                                                       |
| wasm-pack                   | latest                                                                     | Browser Wasm bindings (`cargo install wasm-pack`)                                |
| ProVerif / Tamarin          | latest                                                                     | Formal verification tools (see [Security](#security))                            |

Install Rust (`rustup` will automatically switch to the pinned toolchain on first build):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Quick start

```bash
# Clone
git clone https://github.com/openhttpa/openhttpa-rs
cd openhttpa-rs

# Initialise dependencies (installs system libs on Linux + Node.js libs + Playwright)
make setup

# Build everything (all Rust crates + C / Node.js bindings)
make build

# Run all tests (mock TEE — no hardware required)
make test

# Start the demo
docker compose -f demo/multiparty-webapp/docker-compose.yml up
# Then open http://127.0.0.1:3001

# Formal Verification (ProVerif + Tamarin)
make formal-verify
```

## Formal Verification

The `OpenHTTPA` protocol is formally verified for secrecy, authentication, and forward secrecy. We use **ProVerif** for symbolic analysis and **Tamarin Prover** for temporal properties.

To reproduce the security proofs, ensure you have the provers installed and run:

```bash
# Run all formal proofs (requires ProVerif and Tamarin Prover on PATH)
# Note: If ProVerif is installed via opam, run: eval $(opam env)
make formal-verify
```

Detailed reports and proofs are available in the [Formal Security Suite](#formal-security-suite).

## Standards & Compliance

`OpenHTTPA` is designed for official standardization and federal compliance. The following high-assurance documents provide the technical foundation for submission to the **IETF** and **NIST**.

### IETF Standardization

- **[IETF Internet-Draft (Protocol Wire)](docs/ietf/draft-openhttpa-protocol-00.md)**: The authoritative protocol specification and wire format definition.

### NIST Technical Reports & Guidelines

- **[NIST Technical Report (Security Analysis)](docs/nist/OPENHTTPA-NIST-Technical-Report.md)**: Foundational security analysis and Post-Quantum alignment.
- **[NIST Security Guidelines (Operational SP)](docs/nist/OPENHTTPA-NIST-SP-Security-Guidelines.md)**: Operational best practices and TEE configuration.
- **[FIPS 140-3 Compliance Capability Report](docs/nist/OPENHTTPA-FIPS-Compliance-Capability.md)**: Roadmap for federal cryptographic certification.

### Formal Security Suite

- **[Formal Threat Model](docs/security/OPENHTTPA-Formal-Threat-Model.md)**: Detailed adversary modeling and attack tree analysis.
- **[Formal Verification Report](docs/security/OPENHTTPA-Formal-Verification-Report.md)**: Mathematical proof results from ProVerif and Tamarin Prover.
- **[Privacy Impact Assessment (PIA)](docs/security/OPENHTTPA-Privacy-Impact-Assessment.md)**: Privacy risk analysis following the NIST Privacy Framework.

### Protocol Extensions & Architectural Evaluations

- **[HTTPA/3 & 0-RTT Confidentiality Integration](docs/strategic/HTTPA3-QUIC-0RTT-Evaluation.md)**: Formal evaluation and architectural design for the now-implemented QUIC transport and mathematically verified 0-RTT session resumption capabilities.

### Future Strategic Roadmap

- **FIPS 140-3 Certification Validation**: Completing formal NIST CMVP validation for the underlying `aws-lc-rs` cryptographic boundary.
- **IETF RFC Publication**: Advancing `draft-openhttpa-protocol-00` through the HTTPBIS and SECDISPATCH working groups toward an official Request for Comments (RFC).
- **Expanded Hardware Support**: Extending native attestation providers to include upcoming confidential compute architectures (e.g., RISC-V Keystone).
- **ZK-Oracle Mainnet Deployment**: Transitioning the Confidential Oracle Bridge from evaluation to full production deployment on EVM/Bitcoin mainnets.

## Build

### All Rust crates + C / Node.js bindings

```bash
cargo build --workspace            # debug
cargo build --workspace --release  # optimised
```

> The Python binding (`bindings/python`) is excluded from `cargo build --workspace`
> because it must be linked by Python's interpreter. See
> [bindings/python/README.md](bindings/python/README.md) for its separate build
> command (`maturin develop`).

### Individual crates

```bash
cargo build -p openhttpa-client       # Rust client SDK
cargo build -p openhttpa-server       # Rust server SDK
cargo build -p openhttpa-c            # C shared library (libopenhttpa_c.{a,dylib,so})
cargo build -p openhttpa-node         # Node.js native addon (Rust only; use `pnpm run build` for the .node file)
```

### Language binding artifacts

| Binding     | Build command                                      | Output                                       |
| ----------- | -------------------------------------------------- | -------------------------------------------- |
| **C**       | `cargo build --release -p openhttpa-c`             | `target/release/libopenhttpa_c.{a,dylib,so}` |
| **Node.js** | `cd bindings/nodejs && pnpm run build`             | `openhttpa.<platform>.node`                  |
| **Python**  | `cd bindings/python && maturin develop`            | installed into active venv                   |
| **Go**      | see [bindings/go/README.md](bindings/go/README.md) | links against C library                      |

## Test

### All Rust tests (recommended)

```bash
cargo test --workspace
```

### Formal Validation & Verification

For a complete, exhaustive check of the entire project stack (formatting, clippy, building, all tests, examples, and e2e browser tests), use the following command:

```bash
OPENHTTPA_SKIP_ZK_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 make verify-all
```

> **Python 3.14+**: PyO3 requires a forward-compatibility flag on Python 3.14:
>
> ```bash
> PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 cargo test --workspace
> ```

### Per-binding tests

| Binding            | Command                                                                | Tests           |
| ------------------ | ---------------------------------------------------------------------- | --------------- |
| Core crates        | `cargo test --workspace`                                               | 157 tests       |
| **C**              | `cargo test -p openhttpa-c`                                            | 15              |
| **Node.js (Rust)** | `cargo test -p openhttpa-node`                                         | 14              |
| **Node.js (JS)**   | `cd bindings/nodejs && node test/index.js`                             | smoke           |
| **Python**         | `PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 cargo test -p openhttpa-python` | 14              |
| **Go**             | `cd bindings/go && go test ./... -v`                                   | 9 pass + 2 skip |

### Integration tests (requires a running server)

```bash
# Start the server
docker compose -f demo/multiparty-webapp/docker-compose.yml up -d

# Node.js integration tests
OpenHTTPA_SERVER=http://127.0.0.1:8080 node bindings/nodejs/test/index.js

# Go smoke tests
OpenHTTPA_SERVER=http://127.0.0.1:8080 go test ./bindings/go/... -v -run Smoke
```

## Language bindings

### Python

```python
import openhttpa

llm = openhttpa.PyConfidentialLlm("http://127.0.0.1:8080", "llama3")
reply = llm.chat([("user", "Hello!")])
print(reply)
```

→ Full docs: [bindings/python/README.md](bindings/python/README.md)

#### Agentic AI (MCP)

```python
import json
client = openhttpa.PyMcpClient("http://127.0.0.1:8080")
# JSON-RPC style call
result = client.call("tools/call", json.dumps({"name": "secure_sum", "arguments": {"a": 1, "b": 2}}))
print(result)
```

### Node.js

```js
const { confidentialChat } = require('./bindings/nodejs/index');

const reply = await confidentialChat('http://127.0.0.1:8080', 'llama3', [['user', 'Hello!']]);
console.log(reply);
```

→ Full docs: [bindings/nodejs/README.md](bindings/nodejs/README.md)

#### Agentic AI (A2A)

```js
const { a2aSendMessage } = require('./bindings/nodejs/index');
await a2aSendMessage('http://127.0.0.1:8080', {
  type: 'greeting',
  payload: { text: 'Hello from NodeAgent' },
});
```

### C

```c
#include "openhttpa.h"
char *reply = openhttpa_confidential_chat(
    "http://127.0.0.1:8080", "llama3",
    "[[\"user\",\"Hello!\"]]");
printf("%s\n", reply);
openhttpa_free_string(reply);
```

→ Full docs: [bindings/c/README.md](bindings/c/README.md)

### Go

```go
reply, err := openhttpa.ConfidentialChat(
    "http://127.0.0.1:8080", "llama3",
    [][2]string{{"user", "Hello!"}},
)
fmt.Println(reply)
```

→ Full docs: [bindings/go/README.md](bindings/go/README.md)

## Agentic AI & Swarm

`OpenHTTPA` is uniquely designed for the **Agentic Mesh**. It enables AI agents to form ad-hoc, hardware-verified swarms where every tool execution and message is end-to-end encrypted and attested.

### Running a Swarm Simulation

We provide a comprehensive swarm simulation that launches 100 agents, performs mutual attestation, and executes a "distributed prime search" using MCP tool delegation.

```bash
# Run the basic 2-agent swarm
make swarm-basic

# Run the complex 12-agent Monte Carlo swarm (Coordinator + Workers + Aggregator)
make swarm-complex

# Run the massive 100-agent swarm simulation (concurrent registration + discovery)
make swarm-massive
```

Key features demonstrated:

- **Mutual Attestation**: Peer agents verify each other's TEE hardware quotes.
- **Transcript Binding**: Session keys are cryptographically bound to the handshake history.
- **MCP Delegation**: Agents delegate tasks to specialists over attested tunnels.

## Examples

Each language binding includes a comprehensive, well-commented example demonstrating both the high-level LLM API and the low-level attestation logic.

To run an example, ensure the backend is running first:

```bash
docker compose -f demo/multiparty-webapp/docker-compose.yml up -d
```

Then use the bindings Makefile:

```bash
cd bindings
make python   # Run Python example
make node     # Run Node.js example
make go       # Run Go example
make c        # Run C example
make wasm     # Build and serve Wasm browser example
```

### Running with Docker (Recommended)

If you don't have all the language runtimes (Go, Node, Python) installed locally, you can run all examples in a single command using the provided Docker environment:

```bash
# Start the backend first
make up -C demo/multiparty-webapp

# Run all binding examples
./bindings/run_examples.sh
```

Each example script (e.g., `bindings/python/examples/chat_example.py`) is designed to be readable and serves as a reference for integrating `OpenHTTPA` into your own applications.

## Running the demo

The demo shows multi-party attested computation: a browser talks to an Axum
backend that performs an `OpenHTTPA` handshake and routes requests through a
confidential LLM.

````bash
# Build images and start services (first run takes ~2 min)
docker compose -f demo/multiparty-webapp/docker-compose.yml up --build

# Open in browser
open http://127.0.0.1:3001

### Running the Native Proxy Demo (Caddy)

This demo shows how to proxy a legacy backend through a hardware-attested Caddy instance.

```bash
# Start the native proxy stack
make demo-native-up

# Open the test page
open http://127.0.0.1:8082
````

For detailed deployment instructions, see [DEPLOYMENT.md](DEPLOYMENT.md).

````

To run the backend locally without Docker:

```bash
cargo run -p multiparty-webapp-backend
# Listens on http://127.0.0.1:8080
````

## Operational Security Posture & Deployment Caveats

While the `OpenHTTPA` protocol architecture has undergone exhaustive formal cryptographic verification, this reference SDK is provided for high-assurance integration and evaluation. Strict adherence to operational security guidelines is mandatory prior to production deployment:

- **Cryptographic Transport Dependencies**: The `OpenHTTPA` application layer is agnostic to the underlying transport encryption. Implementers **MUST** provision and wire a secure Transport Layer Security (TLS 1.3+) connector for all HTTP/2 and HTTP/3 adapters to ensure defense-in-depth against Dolev-Yao adversaries.
- **Hardware Enclave Provisioning**: The Arm TrustZone and Intel SGX modules are currently provided as architectural interface stubs. They require binding to a cryptographically signed Trusted Application (TA) or Enclave binary for production execution.
- **Attestation Governance**: The `MockTeeProvider` exists strictly for local development and CI/CD deterministic testing. It **MUST NEVER** be provisioned in a production state; doing so trivially bypasses all hardware-rooted trust guarantees.

## Licensing & Defensive Patent Strategy

The `OpenHTTPA` protocol reference implementation is dual-licensed under the following permissive, OSI-approved licenses:

- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- **MIT License** ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

_at the user's discretion._

### Open-Source Patent Safe Harbor

This repository encompasses foundational technologies critical to the integrity of the confidential computing ecosystem—including Semantic Context Binding (AHL), Heterogeneous TEE Synchronization, and Attested Agent Mesh architectures.

These intellectual properties are explicitly granted to the open-source community under the comprehensive terms of **Section 3 of the Apache License 2.0**.

**Defensive Termination Clause**: To protect the open-source ecosystem, the `OpenHTTPA` Foundation strictly enforces the Apache 2.0 "Patent Retaliation" provision. If any corporate entity institutes patent litigation alleging that this software, or its underlying protocols, constitutes patent infringement, their license rights to utilize `OpenHTTPA` technologies are irrevocably and immediately terminated. This defensive posture mathematically guarantees that `OpenHTTPA` remains an unencumbered, protected Safe Harbor for all high-assurance enterprise adoptions.

Refer to the formal [PATENTS.md](PATENTS.md) declaration for comprehensive legal details.

---

## References

- [arXiv:2205.01052](https://arxiv.org/abs/2205.01052): Original `OpenHTTPA` academic pre-print.

**The `OpenHTTPA` Foundation (openhttpa.org)**
