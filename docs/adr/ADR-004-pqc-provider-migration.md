# ADR-004: ML-DSA Migration from `oqs` to `aws-lc-rs`

| Field      | Value                                     |
| ---------- | ----------------------------------------- |
| Status     | **Proposed**                              |
| Date       | 2026-06-21                                |
| Supersedes | —                                         |
| Related    | ADR-002 (ML-DSA FIPS conflict)            |
| Tracking   | PQC-01, PQC-02 (Formal Review 2026-06-21) |

## Context

The `openhttpa-crypto` crate currently uses the `oqs` crate (wrapping liboqs from
Open Quantum Safe) for both ML-KEM-768 and ML-DSA-65. liboqs is explicitly
documented by OQS as **"intended for prototyping and evaluation"** — not
production deployment.

This has the following consequences:

1. **No FIPS 140-3 validation path** — liboqs has no CMVP module. `aws-lc-rs`
   has an active FIPS 140-3 certification through the AWS-LC cryptographic
   module (certificate pending).
2. **Side-channel exposure** — liboqs ML-KEM/ML-DSA implementations have not
   undergone the same level of constant-time auditing as the AWS-LC implementations.
3. **API stability** — liboqs can change APIs between minor releases, creating
   maintenance burden.

The hybrid design (X25519 via `aws-lc-rs` + ML-KEM via `oqs`) means classical
ECDHE provides a FIPS-validated fallback, limiting the blast radius. However,
the ML-DSA identity signature has no classical fallback — if the PQC signature
is compromised, identity assurance is lost.

## Decision

Migrate both ML-KEM and ML-DSA from `oqs` to `aws-lc-rs` once `aws-lc-rs`
ships stable ML-KEM and ML-DSA support.

### Migration Plan

| Phase | Milestone                                    | Target   |
| :---: | -------------------------------------------- | -------- |
|   1   | `aws-lc-rs` ML-KEM API stabilizes            | Upstream |
|   2   | Migrate `MlKemPair` to `aws-lc-rs` ML-KEM    | v0.3.0   |
|   3   | `aws-lc-rs` ML-DSA API stabilizes            | Upstream |
|   4   | Migrate `MlDsaKeyPair` to `aws-lc-rs` ML-DSA | v0.4.0   |
|   5   | Remove `oqs` dependency entirely             | v0.5.0   |
|   6   | Complete FIPS 140-3 module boundary audit    | v1.0.0   |

### API Compatibility

The `MlKemPair` and `MlDsaKeyPair` public APIs will remain unchanged. The
migration is an internal implementation swap behind the same trait interface.
Wire-format compatibility will be preserved: ML-KEM-768 ciphertext sizes and
ML-DSA-65 signature sizes are FIPS 204/203 standardized and identical across
implementations.

### Interim Mitigations

Until the migration is complete:

1. The hybrid KEM combiner ensures classical X25519 via FIPS-validated `aws-lc-rs`
   provides a safety net even if the `oqs` ML-KEM implementation has issues.
2. The `MlKemPair::Drop` and `MlDsaKeyPair::Drop` implementations manually
   zeroize `oqs::SecretKey` internals (RUST-03, SEC-DSA-01) since `oqs` does
   not implement `ZeroizeOnDrop`.
3. Documentation explicitly states that FIPS compliance claims are aspirational
   for the PQC components until Phase 6 is complete.

## Consequences

- **Positive**: Single cryptographic provider (`aws-lc-rs`) simplifies auditing,
  FIPS boundary analysis, and dependency management.
- **Positive**: Constant-time guarantees from AWS-LC's audited implementations.
- **Negative**: Migration is blocked on upstream `aws-lc-rs` milestones outside
  our control.
- **Risk**: `aws-lc-rs` ML-DSA API may differ from `oqs` API, requiring
  adaptation in the `MlDsaKeyPair` implementation.

## References

- [aws-lc-rs ML-KEM tracking](https://github.com/aws/aws-lc-rs/issues/350)
- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [OQS liboqs status](https://openquantumsafe.org/liboqs/)
- [ADR-002: ML-DSA FIPS conflict](ADR-002-mldsa-fips-conflict.md)
