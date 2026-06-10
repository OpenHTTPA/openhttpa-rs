# ADR 003: Transport Layer Abstraction and ZK Isolation

## Status

Accepted

## Context

As the `OpenHTTPA` protocol and its reference implementations (`openhttpa-rs`) evolved, two architectural coupling issues became apparent that negatively impacted security footprints, compilation times, and adoption:

1. **Transport Layer Coupling:** The `openhttpa-client` and `openhttpa-transport` crates directly depended on `axum::body::Body`. While `axum` is an excellent framework for building the server (`openhttpa-server`), dragging it into pure client and low-level transport boundaries bloated the dependency tree and unnecessarily tied our wire-format abstractions to a specific web framework.
2. **ZK Prover Coupling:** The `openhttpa-attestation` crate previously included the `DcapZkVerifier`, pulling in heavy Zero-Knowledge proof generation dependencies (`risc0-zkvm`). Since many consumers only need to _verify_ standard hardware attestation quotes (or just ZK receipts, which are lightweight to verify), bundling the prover side inside the core attestation logic expanded the security attack surface and build times.

## Decision

### 1. Transport Abstraction via `http-body-util`

We have completely removed the `axum` dependency from `openhttpa-client` and `openhttpa-transport`. Instead, we now rely on the standard `http-body` and `http-body-util` traits.

- We introduced `openhttpa_transport::connection::TransportBody` as a generic abstraction.
- We utilize `http_body_util::combinators::BoxBody` for dynamic body types.
- The server crate (`openhttpa-server`) continues to use `axum` but bridges the gap to `TransportBody` at its boundary.

### 2. Isolation of `risc0` into `openhttpa-zk`

We have extracted the `DcapZkVerifier` and all heavy `risc0-zkvm` dependencies out of `openhttpa-attestation` and into a dedicated, standalone crate: `openhttpa-zk`.

- `openhttpa-attestation` is now strictly focused on traditional hardware TEE quote verification (SGX, TDX, SEV-SNP) and is significantly lighter.
- `openhttpa-zk` encapsulates the complex logic of converting hardware quotes into succinct SNARK receipts (ZAA compression).

## Consequences

- **Positive:** Massive reduction in compile times and dependency bloat for client applications.
- **Positive:** Reduced security attack surface in the core attestation verifier.
- **Positive:** Clearer semantic boundaries between the "wire transport", the "server framework", and the "zero-knowledge prover".
- **Negative:** Slightly more complex setup for advanced deployments that wish to _generate_ ZK receipts, as they must explicitly depend on the new `openhttpa-zk` crate.
