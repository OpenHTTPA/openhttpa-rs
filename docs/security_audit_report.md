# Security Audit Report — OpenHTTPA v0.1.x

> **Status**: Ongoing  
> **Last Updated**: 2026-06-22  
> **Scope**: Full codebase, formal verification models, cryptographic primitives, protocol design

## Overview

This document tracks all security findings from internal and external audits of the
`openhttpa-rs` reference implementation. Each finding is assigned a unique ID and
severity level per the project's security taxonomy.

## Finding Classification

| Severity | Definition                                                       |
| :------- | :--------------------------------------------------------------- |
| **P0**   | Critical — immediate exploitation risk; blocks release           |
| **P1**   | High — exploitable under specific conditions; must fix before GA |
| **P2**   | Medium — defense-in-depth improvement; should fix before GA      |
| **P3**   | Low — informational; fix when convenient                         |

## Remediated Findings

### SA-01 — Hybrid Combiner IKM Injection Vulnerability (P1)

**Component**: `crates/openhttpa-crypto/src/key_exchange.rs`  
**Status**: ✅ FIXED  
**Description**: Variable-length public key fields concatenated without length prefixes,
violating the injective encoding requirement of `draft-ietf-tls-hybrid-design §3.2`.  
**Fix**: Added `encode_lengthed()` helper with 2-byte big-endian u16 length prefix for all
variable-length fields.  
**Regression Tests**: `encode_lengthed_format`, `hybrid_combiner_field_swap_changes_secret`

### SA-02 — HKDF Key Schedule RFC 5869 Violation (P0)

**Component**: `crates/openhttpa-crypto/src/hkdf.rs`  
**Status**: ✅ FIXED  
**Description**: The version label was placed in the HKDF-Extract salt position instead of
HKDF-Expand info, violating RFC 5869 §2.2.  
**Fix**: Moved to zero-byte salt with protocol-version-prefixed info strings. See
[ADR-001](adr/ADR-001-key-schedule-wire-break.md) for the full analysis.  
**Regression Tests**: `session_keys_known_answer_vector_v2_prefix`,
`new_schedule_differs_from_old_label_as_salt`

### SA-03 — Silent Client Quote Verification Bypass (P0)

**Component**: `crates/openhttpa-core/src/handshake.rs`  
**Status**: ✅ FIXED  
**Description**: When a `QuoteVerifier` was not configured but client quotes were submitted,
all quotes passed unconditionally — a silent mutual-attestation bypass.  
**Fix**: Returns `HandshakeError::AttestationRequired` when quotes are submitted but no
verifier is available.  
**Regression Test**: `client_quotes_without_verifier_rejected`

## Open Findings

> [!NOTE]
> Additional findings from the 2026-06-22 formal audit are tracked in the
> implementation plan artifact and are being addressed in the v0.1.2 release cycle.

### CRYPTO-C03 — FIPS 140-3 Certification Status (P2)

**Component**: Documentation  
**Status**: 🔶 IN PROGRESS  
**Description**: FIPS compliance claims reference `aws-lc-rs` FIPS features but no CMVP
certificate number is cited. ML-KEM-768 and ML-DSA-65 are NIST-standardized (FIPS 203/204)
but `liboqs` has no CMVP certificate.  
**Action**: Distinguish between "NIST-standardized algorithms" and "FIPS-validated module"
in all documentation.

### PROTO-H01 — Cipher Suite Negotiation Order (P1)

**Component**: `crates/openhttpa-core/src/handshake.rs`  
**Status**: ✅ FIXED  
**Description**: Cipher suite negotiation used client-preference ordering instead of
server-preference ordering as documented in the formal model.  
**Fix**: Changed to server-preference iteration.

---

_For the complete audit methodology and findings, see the formal audit artifact in the
project's issue tracker._
