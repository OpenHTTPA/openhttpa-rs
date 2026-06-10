# ADR 002: ML-DSA Migration and FIPS Conflict

## Status

Proposed / Blocked

## Context

The `OpenHTTPA` protocol mandates a migration to NIST-standardized Post-Quantum Cryptography algorithms, specifically moving from the experimental Dilithium implementation in `oqs` to the standardized ML-DSA implementation. Our primary cryptographic provider is `aws-lc-rs`.

However, the workspace enforces a global `fips` feature to guarantee that all deployments strictly utilize FIPS 140-3 compliant cryptographic modules.

Currently, `aws-lc-rs` (and the underlying `aws-lc-fips-sys`) does not yet include ML-DSA within its FIPS boundary, nor does it provide a stable API for ML-DSA when the `fips` feature is enabled. Enabling ML-DSA in `aws-lc-rs` while compiling with `fips` results in compilation errors and violates the FIPS boundary constraints.

## Decision

We will **delay** the migration of the ML-DSA signature scheme from `oqs` to `aws-lc-rs` until AWS LC officially includes ML-DSA within its FIPS module and stabilizes the API.

In the interim:

1. We will continue to use `oqs` for ML-DSA (Dilithium) where explicitly required by experimental cipher suites.
2. The core handshake will default to hybrid key exchange (e.g. `X25519MlKem768Aes256GcmSha384`) which _is_ supported within the FIPS boundary (ML-KEM).
3. We will monitor the `aws-lc-rs` release notes for ML-DSA FIPS certification and stable API availability.

## Consequences

- **Positive:** We maintain strict FIPS 140-3 compliance for the core operations without introducing unstable or non-compliant cryptography into the TCB.
- **Negative:** We must temporarily maintain the `oqs` dependency for legacy or experimental ML-DSA endpoints, slightly increasing the binary size and dependency complexity.
- **Negative:** The full migration to a unified cryptographic provider (`aws-lc-rs`) is delayed.
