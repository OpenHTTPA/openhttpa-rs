# CHANGELOG

All notable changes to `openhttpa-rs` are documented here.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and
[Conventional Commits](https://www.conventionalcommits.org/).

---

## [Unreleased]

### Security — P0 Audit Remediation (SA-01, SA-02, SA-03)

> See [Security Audit Report](docs/security_audit_report.md) for full findings.  
> See [ADR-001](docs/adr/ADR-001-key-schedule-wire-break.md) for the key-schedule design decision.

---

#### Security — Metadata Protection & Memory Safety

**Feature:**  
`OpenHTTPA` now features ML-KEM HPKE Encrypted Client Hello for cover-traffic metadata protection, Strict Post-Quantum Cryptographic Memory Safety using `zeroize`, and E2E tested Replay Attack Prevention.

**Changes:**

- Added `EncryptedHelloPayload` for hiding cipher suites and protocol versions during `AtHS`.
- Refactored `HpkeClient::seal` and `HpkeServer::open` to use strongly-typed `HpkeCiphertext` with `ZeroizeOnDrop` bound to it.
- Enforced `ZeroizeOnDrop` across the `openhttpa-crypto` crate on highly sensitive structures like `SessionKeys` and `ClientWriteKey`.
- Built an extensive E2E Replay Attack test (`test_replay_attack_prevention_e2e`) using a custom `RecordingTransport`.

---

#### Post-Quantum Identity — ML-DSA-65 Integration (FIPS 204)

**Affected files:** `crates/openhttpa-crypto/src/pqc.rs`, `crates/openhttpa-core/src/handshake.rs`, `openhttpa-server/src/handlers.rs`

**Feature:**  
`OpenHTTPA` now incorporates post-quantum digital signatures using **ML-DSA-65** to ensure identity assurance against quantum adversaries. The server-side identity is now bound to the handshake transcript via an ML-DSA signature, complementing the hybrid KEM (ML-KEM) and hardware attestation.

**Changes:**

- Added `MlDsaKeyPair` and `MlDsaSignature` to `openhttpa-crypto`.
- Updated `AtHsExecutor` and `execute_server` to require an optional `identity_key`.
- Updated `AtHsResult` and `AtHsResponseHeaders` to carry `server_signatures`.
- Updated all language bindings to support ML-DSA public key verification.

---

#### High-Assurance — Composite TEE Attestation (TDX + GPU)

**Affected files:** `demo/multiparty-webapp/backend/src/main.rs`, `crates/openhttpa-tee/src/provider.rs`

**Feature:**  
Enhanced the multiparty demonstration stack to support **Composite TEE Attestation**, allowing for the simultaneous verification of multiple hardware roots-of-trust (e.g., Intel TDX CPU + NVIDIA Hopper GPU) in a single unified session.

**Changes:**

- Updated `DemoState` to default to a composite `tdx + nvidia_gpu` view in mock mode.
- Improved `aths_json` handler to correctly utilize the TEE provider registry and identity keys.
- Verified transcript-binding (T-10) across heterogeneous providers.

---

#### SA-02 — ⚠️ BREAKING: Session Key Schedule Corrected (RFC 5869)

**Affected files:** `crates/openhttpa-crypto/src/hkdf.rs`  
**Breaking:** YES — all endpoints must be updated simultaneously (see migration guide below)

**Problem:**  
`SessionKeys::derive` placed the ASCII version label `b"openhttpa handshake v2"` in the
HKDF-Extract **salt** position instead of the HKDF-Expand **info** parameter. RFC 5869
§2.2 defines the salt as a random or zero-value input for whitening the IKM, not a
channel for application-level domain separation. The info parameter is the correct
location for labels and context binding.

**Fix:**  
The key schedule now follows RFC 5869 §2.2 and mirrors the TLS 1.3 §7.1 structure:

```
# Old (INCORRECT — do not use)
PRK = HKDF-Extract(salt=b"openhttpa handshake v2", IKM=combined_secret)
OKM = HKDF-Expand(PRK, info=transcript_hash ‖ b"<slot>", len)

# New (CORRECT — RFC 5869 §2.2 compliant)
PRK = HKDF-Extract(salt=[0x00; 48], IKM=combined_secret)
OKM = HKDF-Expand(PRK, info=b"openhttpa_v2" ‖ b"<slot>" ‖ 0x00 ‖ transcript_hash, len)
```

The zero-byte salt of hash-output length (48 bytes for SHA-384) is the RFC-mandated
default when no external salt is available. The `b"openhttpa v2 "` version prefix in each
Expand info string provides protocol-version domain separation, equivalent to the
`"tls13 "` prefix in TLS 1.3.

**Impact:**  
Derived session keys (`client_write_key`, `server_write_key`, `client_write_iv`,
`server_write_iv`, `client_mac_key`, `server_mac_key`, `master_secret`) are
cryptographically different from keys produced by the old code for the same inputs.
This is by design and confirmed by the regression test
`hkdf::tests::new_schedule_differs_from_old_label_as_salt`.

**Migration:**

1. **Invalidate all active sessions** before deploying updated server binaries.
2. **Update all language bindings** to the matching version that includes this fix.
3. **Force-expire all session resumption tickets** (PSK tickets embed old schedule keys).
4. **Deploy server-side first**, then clients. Mixed-version pairs will fail at the first
   `TrR` AEAD decryption (a AEAD tag mismatch error) — this is detectable and non-silent.

Full rollout procedure: [ADR-001 §3.4](docs/adr/ADR-001-key-schedule-wire-break.md#34-rollout-procedure).

---

#### SA-01 — Session Key Combiner: Length-Prefix Encoding Added

**Affected files:** `crates/openhttpa-crypto/src/key_exchange.rs`  
**Breaking:** NO — the combined hybrid secret is an internal intermediate value.
The wire format of `Attest-Key-Share` headers is unchanged.

**Problem:**  
`HybridSharedSecret::combine` concatenated variable-length public-key material
(ECDHE public keys, ML-KEM encapsulation key, ML-KEM ciphertext) without length prefixes.
This violates the injective encoding requirement of `draft-ietf-tls-hybrid-design §3.2`:
two sessions with distinct public keys that straddle field boundaries differently could
produce identical IKMs, breaking the IND-CCA2 combiner proof.

**Fix:**  
A private `encode_lengthed(buf, data)` helper now prefixes each variable-length field
with its 2-byte big-endian `u16` length before appending the data bytes. Applied to the
domain-separation label and all four public-key material fields.

**New regression tests:**

- `key_exchange::tests::encode_lengthed_format` — verifies byte-level prefix format
- `key_exchange::tests::hybrid_combiner_field_swap_changes_secret` — verifies IKM injection safety

---

#### SA-03 — Client Quote Verification: Silent Bypass Eliminated

**Affected files:** `crates/openhttpa-core/src/handshake.rs`  
**Breaking:** Configuration-level — deployments that pass client quotes but no
`QuoteVerifier` now receive `HandshakeError::AttestationRequired` instead of silently
succeeding.

**Problem:**  
`verify_client_quotes` used `if let Some(v) = verifier { … }` to gate all verification
logic. When `verifier` was `None` but the client submitted one or more quotes, the loop
body was empty and every quote passed unconditionally — a silent mutual-attestation bypass.

**Fix:**  
The function now returns `HandshakeError::AttestationRequired` immediately when quotes
are submitted but no `QuoteVerifier` is provided. Submitting zero quotes with no verifier
is still allowed (for unauthenticated modes).

**New regression test:**

- `handshake::tests::client_quotes_without_verifier_rejected`

---

### Added

- `openhttpa-fabric` crate for distributed memory synchronization and integration with mesh node via MCP tools.
- Auto-attestation with hardware TEE federation and optional ZAA compression support.
- Configurable policy engine with namespace, debug, and keyword intent enforcement.
- AMD SEV-SNP verifier and federated verification support.
- Comprehensive unit and integration test suites for ZK verification, gRPC attestation, and LLM error handling.
- Provenance signing to `AgentMetadata` and expanded `EatClaims` with expiry.
- Interactive version bumping and package publication wizards in Makefile.
- `docs/adr/ADR-001-key-schedule-wire-break.md` — Architecture Decision Record
  documenting the SA-02 wire-format break, security analysis, RFC alignment, formal proof
  sketches, and rollout procedure.
- `CHANGELOG.md` — this file.

### Changed

- Implemented A2A handshake logic and migrated trait definitions to use native async functions.
- Replaced `innerHTML` with DOM API elements in session list rendering to improve security and performance.
- Improved security for PSK storage and added comprehensive unit tests across transportation, attestation, and middleware modules.
- Updated `nsm-api` dependency and refined ephemeral key generation warning in backend.
- Removed `async-trait` dependency in favor of manual pinning and added `non_exhaustive` to `TicketEngineError`.
- Modularized verification targets in Makefile and excluded additional WASM artifacts from Prettier.
- Enhanced devcontainer and setup scripts with browser extension support, Trivy, Foundry, and cargo tools.
- Hardened WebSocket AAD with response size configuration.
- Added TMPDIR export to Makefile for CI environment consistency.
- `crates/openhttpa-crypto/src/hkdf.rs` — Module documentation updated to describe the
  corrected key schedule with full RFC 5869 alignment rationale.
- `crates/openhttpa-crypto/src/key_exchange.rs` — Module documentation updated to describe
  length-prefix encoding semantics per draft-ietf-tls-hybrid-design §3.2.
- `API.md` §2.4 — Key Schedule section updated to reflect the new HKDF construction.
- `CONTRIBUTING.md` — Added Wire-Format Versioning policy.

---

## [0.1.0] — 2026-05-05 (Pre-release baseline)

Initial pre-release of the `openhttpa-rs` reference implementation:

- Hybrid KEM handshake (X25519 + ML-KEM-768) with transcript binding
- TEE attestation framework supporting TDX, SGX, SEV-SNP, TPM, TrustZone, NVIDIA GPU
- AEAD session encryption (AES-256-GCM / ChaCha20-Poly1305) with nonce reuse protection
- Replay guard (sliding-window bit-map, configurable window size)
- ProVerif and Tamarin formal models with zero-warning baseline
- Language bindings: Node.js (NAPI), Python (PyO3/maturin), Go (CGO), Wasm (wasm-pack)
- CI/CD: cargo-deny, cargo-audit, Trivy image scanning, Playwright E2E tests
- Demo: `multiparty-webapp` with hardened Docker Compose stack

[Unreleased]: https://github.com/openhttpa/openhttpa-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/openhttpa/openhttpa-rs/releases/tag/v0.1.0
