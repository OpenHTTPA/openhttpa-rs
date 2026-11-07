# ADR-005: FIPS 204 Context Strings for ML-DSA-65 Identity Signatures

**Status:** Accepted
**Date:** 2026-11-07
**Authors:** Gordon King
**Replaces:** N/A
**Affects:** `openhttpa-crypto`, `openhttpa-core` (server transcript signature), `openhttpa-client`
(pinned-identity verification), and the `openhttpa-az-cvm` epoch binding in `openhttpa-proxy-rs`.

---

## 1. Context

An external audit of a live SEV-SNP session (`openhttpa-proxy-rs` `docs/AUDIT_REPORT.md` §12)
found that the server's sealed ML-DSA-65 identity key signs two kinds of message with the **empty**
FIPS 204 context:

| Role                  | Message                                                                        | Context (before) |
| --------------------- | ------------------------------------------------------------------------------ | ---------------- |
| Handshake transcript  | `T` = SHA-384 transcript hash (48 bytes)                                       | `""`             |
| Epoch session binding | `"openhttpa-az-cvm/v1/epoch-session-sig" ‖ epoch_rd ‖ report_data` (165 bytes) | `""`             |

The two messages cannot collide today, because their lengths differ and one carries an ASCII
domain. But the separation depends on message shape, not on the signature scheme, and every
future use of the same key would have to preserve it by hand. FIPS 204 §5.2 provides the context
string for exactly this purpose.

## 2. Decision

Every ML-DSA-65 signature made by an OpenHTTPA identity key uses pure ML-DSA (FIPS 204
Algorithm 2, not HashML-DSA) with a non-empty, role-specific context:

| Role                  | Message `M` (unchanged)                                            | Context `ctx`                                     |
| --------------------- | ------------------------------------------------------------------ | ------------------------------------------------- |
| Handshake transcript  | `T`                                                                | `"openhttpa/v1/hs-server-transcript"` (33 bytes)  |
| Epoch session binding | `"openhttpa-az-cvm/v1/epoch-session-sig" ‖ epoch_rd ‖ report_data` | `"openhttpa/v1/epoch-session-binding"` (34 bytes) |

The signed message becomes `M' = 0x00 ‖ u8(len(ctx)) ‖ ctx ‖ M`, which differs from the
legacy `M' = 0x00 ‖ 0x00 ‖ M` for every `M`. Distinct contexts make cross-role substitution
impossible by construction.

`Attest-Key-Share.signature_alg` stays `ml-dsa-65`: the algorithm is unchanged and the context
is one of its parameters.

APIs: `MlDsaKeyPair::{sign_with_context, verify_with_context}` (1..=255-byte context, enforced);
`openhttpa_core::handshake::{HS_SERVER_SIG_CONTEXT, verify_server_transcript_signature,
TranscriptSigContext}`.

## 3. Compatibility (dual-accept)

Signers always use the context. Verifiers accept the context form and, failing that, the
legacy empty-context form, and report which one verified (`TranscriptSigContext::LegacyEmpty`,
logged at `warn`, shown by `audit-verify`). The reasons:

- Recorded sessions keep verifying deterministically. One is the live SEV-SNP capture
  `crates/openhttpa-proxy/tests/fixtures/audit-real-snp.jsonl` in `openhttpa-proxy-rs`.
- Sealed appliances cannot be updated in place. Rejecting legacy signatures would break every
  deployed server until it is recreated.

Accepting both forms adds no attack. A cross-role substitution needs the same key to have
produced an empty-context signature over the other role's message. A key used by post-ADR-005
software never signs with the empty context, and a pre-ADR-005 key gains nothing it did not
already have. Legacy acceptance will be removed once deployed servers have been recreated. That
removal is a separate, announced change.

## 4. Consequences

- **⚠️ BREAKING for pinned-identity clients built before this change** (`--server-identity-pubkey`
  or `OpenHttpaClientBuilder` with a pinned key): they verify with the empty context and reject a
  new server's transcript signature. Upgrade clients before servers.
- Unpinned clients are unaffected for the transcript signature. Hardware evidence binds `T`
  through `report_data` regardless.
- The epoch binding is verified by every Azure CVM client, pinned or not. A client built before
  this change rejects a new server's reused epoch quotes; fresh per-session quotes
  (`--attestation-cache-ttl-secs 0`) still work.

## 5. Verification

- `openhttpa-crypto`: `mldsa_context_separates_signatures`. A context signature does not verify
  under another context or the empty one, a plain signature does not verify under a context, and
  empty or over-long contexts are refused.
- `openhttpa-core`: `transcript_signature_uses_the_fips204_context`. The executor's real output
  verifies only under the context and never as an empty-context signature (new output differs
  from old). A legacy signature reports `LegacyEmpty`, and another context or transcript is
  refused.
- Tamarin (`formal/handshake.spthy`): signatures carry their role tag. The model was updated but
  not re-run in this change, because no prover was available.
- Independently: `openhttpa-proxy-rs/scripts/audit_verify_independent.py` verifies with
  `dilithium-py` (pure-Python FIPS 204) and reports the context each signature used.
