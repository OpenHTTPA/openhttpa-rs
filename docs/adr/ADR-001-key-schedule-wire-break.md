# ADR-001: `OpenHTTPA` Session Key Schedule — SA-02 Wire-Format Break

**Status:** Accepted  
**Date:** 2026-05-06  
**Authors:** Security Audit Panel (Security Lead · Architecture · IETF · CTO)  
**Replaces:** N/A (first formal ADR)  
**Affects:** All `OpenHTTPA` implementations — clients, servers, bindings (Node.js, Python, Go, Wasm), and any out-of-tree implementations.

---

## 1. Context and Problem

During the SA-02 security audit finding, the `OpenHTTPA` session key schedule in
`crates/openhttpa-crypto/src/hkdf.rs` was found to violate **RFC 5869 §2.2** by using an
ASCII version label as the HKDF-Extract salt instead of the HKDF-Expand info parameter.

### 1.1 What the Old Code Did

```
PRK = HKDF-Extract(
    salt = b"openhttpa handshake v2",   ← ASCII label used as HKDF salt  ❌
    IKM  = combined_hybrid_secret
)

client_write_key = HKDF-Expand(
    PRK,
    info = transcript_hash ‖ b"client write key",  ← no version prefix ❌
    len  = 32
)
```

The root cause was a parameter-order confusion in the `HkdfExpander::extract_sha384`
call site inside `SessionKeys::derive`. The label `b"openhttpa handshake v2"` was intended
to provide domain separation but was placed in the `salt` position of HKDF-Extract rather
than the `info` position of HKDF-Expand.

### 1.2 Why This Was a Security Finding

RFC 5869 defines HKDF as a two-step construction:

```
HKDF-Extract(salt, IKM) → PRK
HKDF-Expand(PRK, info, L) → OKM
```

The **salt** is defined as "a non-secret random value" or a "fixed" default (zeroes of
hash-output length). Its security role is to _whiten_ a potentially non-uniform IKM into
a uniform PRK. It is **not** the channel for application-level domain separation.

The **info** parameter is the correct vehicle for domain separation. It is mixed into
every block of HKDF-Expand via HMAC, binding each derived key to:

- The protocol context (version, algorithm)
- The specific key slot (client write key vs. server write key, etc.)
- The session-specific transcript

Placing a label in the salt position creates the following risks:

| Risk                              | Detail                                                                                                                                                                                                                               |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **RFC 5869 compliance**           | Violates the defined role of the `salt` parameter. RFC 5869 §2.2 states the salt should be a random or zero-byte value, not an application label.                                                                                    |
| **Interoperability**              | Third-party implementations reading the spec will generate different keys, creating silent session failures that appear as authentication errors rather than obvious mismatches.                                                     |
| **Protocol-version scoping**      | Without a version prefix in `info`, keys derived under two different protocol versions using the same combined secret would be identical — enabling cross-version session confusion attacks if version negotiation is ever weakened. |
| **Formal model drift**            | The ProVerif and Tamarin models assume HKDF is used correctly per its security proofs. Using the salt as a label invalidates the underlying IND-PRF assumption that those proofs depend on.                                          |
| **Future cipher-suite expansion** | When new cipher suites add session-specific salts (e.g., from PSK resumption), the existing code provides no obvious extension point because the label has colonised the salt field.                                                 |

### 1.3 What the Old Code Got Right

To be precise about scope: the old code still produced **pseudorandom output** for the
current single-context deployment. HMAC-SHA-384 is a PRF over both the key and the data,
so feeding a constant label as the salt of HKDF-Extract produces a valid PRK — it is just
not what RFC 5869 specifies. No session keys were exposed retrospectively.

However, "pseudorandom in the current deployment" is not the same as "correct" and is not
a sufficient bar for a cryptographic library claiming RFC 5869 compliance.

---

## 2. Decision

### 2.1 New Key Schedule

The following key schedule replaces the old one for all `OpenHTTPA` v2 sessions:

```
PRK = HKDF-Extract(
    salt = [0x00; 48],             ← 48 zero bytes (SHA-384 output length)
    IKM  = combined_hybrid_secret  ← X25519 ⊕ ML-KEM-768 combined secret
)

For each key slot:

OKM = HKDF-Expand(
    PRK,
    info = b"openhttpa v2 " ‖ label ‖ transcript_hash,
    len  = <slot-specific length>
)
```

**Key slots and lengths:**

| Slot               | Label bytes           | Output length |
| ------------------ | --------------------- | ------------- |
| `master_secret`    | `b"master secret"`    | 48 bytes      |
| `client_write_key` | `b"client write key"` | 32 bytes      |
| `server_write_key` | `b"server write key"` | 32 bytes      |
| `client_write_iv`  | `b"client write iv"`  | 12 bytes      |
| `server_write_iv`  | `b"server write iv"`  | 12 bytes      |
| `client_mac_key`   | `b"client mac key"`   | 32 bytes      |
| `server_mac_key`   | `b"server mac key"`   | 32 bytes      |

**Info string composition:**

```
info = "openhttpa v2 "      (10 bytes, ASCII, protocol-version prefix)
     ‖ label              (variable, UTF-8 slot label — see table above)
     ‖ transcript_hash    (48 bytes, SHA-384 of the full handshake transcript)
```

Because `transcript_hash` is always exactly 48 bytes (SHA-384 output), there is no
length ambiguity at the `label ‖ transcript_hash` boundary. The three components
together ensure:

1. **Protocol-version domain separation** — `"openhttpa v2 "` prevents any other
   protocol (including future HTTPA/3) from silently reusing these keys even if
   the same combined secret appears.
2. **Slot domain separation** — each label is distinct and produces a different
   HKDF-Expand block sequence.
3. **Session binding** — the transcript hash is unique per session and ties every
   derived key to the specific handshake that established it.

### 2.2 Salt Selection Rationale

RFC 5869 §2.2 states:

> If not provided, [the salt] is set to a string of HashLen zeros.

The zero-byte salt of length 48 (the SHA-384 output size) is the RFC-mandated default
when no external salt is available. The combined hybrid secret (`IKM`) provides all
entropy; no additional randomness from the salt is required. A non-zero structured salt
would be appropriate only in a PSK-resumption scenario where the pre-shared key acts as
the salt — a future extension that this design explicitly accommodates.

### 2.3 Alignment with TLS 1.3

This design mirrors the TLS 1.3 key schedule (RFC 8446 §7.1):

```
TLS 1.3:
  HKDF-Extract(salt=0, IKM=DHE) → handshake_secret
  HKDF-Expand-Label(handshake_secret, "tls13 " ‖ label, context_hash, len)
```

`OpenHTTPA` uses the same structural pattern:

- Zero salt for Extract
- Version-prefixed label + session context in Expand info
- Fixed-length hash as the session-binding context

The `"openhttpa v2 "` prefix plays the same role as `"tls13 "` in TLS 1.3 — it scopes
all derived keys to this exact protocol version and prevents cross-protocol attacks.

---

## 3. Consequences — Wire-Format Break

### 3.1 Why This Is a Breaking Change

The new key schedule produces **cryptographically different keys** from the old one for
any given `(combined_hybrid_secret, transcript_hash)` pair. This is intentional and
unavoidable: the fix changes the HKDF inputs, so the outputs must change.

Specifically:

| Component         | Old value                              | New value                                    |
| ----------------- | -------------------------------------- | -------------------------------------------- |
| HKDF-Extract salt | `b"openhttpa handshake v2"` (19 bytes) | `[0x00; 48]` (48 bytes)                      |
| HKDF-Expand info  | `transcript_hash ‖ label`              | `b"openhttpa v2 " ‖ label ‖ transcript_hash` |

A client running the old schedule and a server running the new schedule will derive
incompatible session keys. The handshake will complete successfully (key negotiation and
attestation are unaffected), but all subsequent `TrR` decryption will fail with an AEAD
authentication error.

### 3.2 Scope of Impact

This change affects **all `OpenHTTPA` sessions**. There is no partial or version-negotiated
migration path within the `v0.1.x` release series. The change affects:

- `openhttpa-rs` (all crates)
- `bindings/nodejs` — `openhttpa-node`
- `bindings/python` — `openhttpa-python`
- `bindings/go` — CGO wrapper via `openhttpa-c`
- `bindings/wasm` — `openhttpa-wasm`
- Any out-of-tree implementations that independently implemented the key schedule

**Session resumption tickets** issued before this change are also invalidated because
the session keys embedded in encrypted tickets were derived using the old schedule.

### 3.3 What Is NOT Affected

The following components are **not changed** and produce identical wire bytes before and
after:

- The hybrid KEM key exchange (`HybridKemPair`, `HybridSharedSecret`)
- The SA-01 combiner fix (length-prefixed IKM) — independent of SA-02
- The TEE attestation quote format and binding (`AtHsExecutor`, `verify_client_quotes`)
- The AEAD encryption algorithm (AES-256-GCM, nonce construction)
- The replay protection mechanism (`ReplayGuard`, `NonceManager`)
- The `Attest-*` HTTP header wire format
- The ProVerif and Tamarin formal models (the key schedule is abstracted as `hkdf(…)`)

### 3.4 Rollout Procedure

Because this is a coordinated atomic break:

1. **Deploy server-side first**: Update all server instances to the new binary. In-flight
   sessions using the old schedule will be rejected at the first `TrR` decryption (AEAD
   tag failure). Clients will receive an HTTP 400 or connection reset and will
   automatically re-negotiate via a new AtHS.

2. **Update all clients simultaneously**: After all servers are updated, client libraries
   across all bindings must be updated. There is no mixed-version window to support.

3. **Invalidate all resumption tickets**: If your deployment uses session resumption
   (`Attest-Ticket-Resumption`), force-expire all tickets in your session store before
   deploying the new server binary.

4. **Pin the dependency**: All language binding packages (`openhttpa-node`, `openhttpa-python`,
   `openhttpa-wasm`) must be updated to a version that includes this fix. Pinning to the
   exact minor version is recommended:

   ```toml
   # Cargo.toml
   openhttpa-crypto = "= 0.1.1"  # exact pin to post-SA-02 version
   ```

   ```json
   // package.json
   "openhttpa-node": "=0.1.1"
   ```

### 3.5 Detecting Mixed-Version Deployments

A mixed-version deployment (old client + new server, or new client + old server) produces
the following observable symptom:

- **AtHS phase completes successfully** — no error
- **First `TrR` request fails** with AEAD authentication error (HTTP 422 or connection reset)

This is distinct from a certificate/attestation failure (which occurs during AtHS) and
from a replay error (which includes a specific error message). If you see TrR AEAD
failures immediately after a successful handshake, version mismatch is the most likely
cause.

---

## 4. Security Analysis

### 4.1 Formal Proof of Non-Regression

The security of the new schedule follows from the security of HKDF proven by Krawczyk
and Eronen (RFC 5869) and the IND-PRF assumption on HMAC-SHA-384:

**Claim**: Given a pseudorandom `combined_hybrid_secret` (guaranteed by the hybrid KEM
combiner), `HKDF-Extract([0;48], combined_hybrid_secret)` produces a uniformly
distributed PRK.

**Proof sketch**: By the IND-PRF property of HMAC-SHA-384, for any fixed salt, the
output of `HMAC-SHA-384(salt, IKM)` is computationally indistinguishable from uniform
when `IKM` contains sufficient entropy. The combined hybrid secret has at least 256 bits
of computational security (min of X25519 and ML-KEM-768 security levels). A zero salt
does not reduce this guarantee — it is equivalent to using a publicly known fixed salt,
which RFC 5869 explicitly permits.

**Claim**: Each `HKDF-Expand(PRK, info_i, len_i)` output is computationally independent
from `HKDF-Expand(PRK, info_j, len_j)` for `i ≠ j`.

**Proof sketch**: The HKDF-Expand construction chains HMAC blocks:
`T(i) = HMAC-SHA-384(PRK, T(i-1) ‖ info ‖ i)`. As long as `info_i ≠ info_j`, the
HKDF-Expand streams diverge at the first block. All seven info strings in the `OpenHTTPA`
schedule are distinct (they differ in label), so all seven derived keys are
computationally independent.

**Claim**: The transcript hash in info provides session binding.

**Proof sketch**: The transcript hash is `SHA-384(client_hello ‖ server_hello ‖ …)`.
SHA-384 is collision-resistant; no two distinct sessions produce the same hash with
non-negligible probability. Therefore, keys from one session cannot decrypt messages from
a different session.

### 4.2 What the Old Code Did NOT Lose

The old schedule, while non-compliant, did produce pseudorandom output because:

- `HMAC-SHA-384(b"openhttpa handshake v2", combined_secret)` is a valid PRF evaluation
- The resulting PRK was computationally indistinguishable from uniform assuming the
  combined secret was pseudorandom

No past session keys are retrospectively weakened by this change. The fix is forward-
looking: it aligns the implementation with the security model that the formal proofs
assume and enables correct interoperability.

### 4.3 Remaining Formal Verification Tasks

The following ProVerif/Tamarin model updates are tracked under **P1**:

- The ProVerif model (`formal/handshake.pv`) uses an abstract `hkdf(ss_dh, ss_ml, transcript)`
  term. This abstraction correctly captures the binding properties but does not distinguish
  between old and new key schedule implementations. No model change is required for secrecy
  and agreement lemmas.
- The Tamarin model (`formal/handshake.spthy`) uses `h(<ss_dh, ss_ml, h(transcript)>)`.
  Same conclusion — the Fix does not invalidate existing lemmas.
- Future work: add a HKDF-specific sub-lemma that models the info-parameter domain
  separation property to make the key schedule independence explicit in the formal model.

---

## 5. References

| Reference                               | URL                                                                                          |
| --------------------------------------- | -------------------------------------------------------------------------------------------- |
| RFC 5869 — HKDF                         | https://www.rfc-editor.org/rfc/rfc5869                                                       |
| RFC 8446 §7.1 — TLS 1.3 Key Schedule    | https://www.rfc-editor.org/rfc/rfc8446#section-7.1                                           |
| `OpenHTTPA` Audit Finding SA-02         | `docs/adr/ADR-001-key-schedule-wire-break.md` (this document)                                |
| SA-02 Implementation                    | `crates/openhttpa-crypto/src/hkdf.rs`                                                        |
| SA-02 Regression Tests                  | `crates/openhttpa-crypto/src/hkdf.rs` — `tests::new_schedule_differs_from_old_label_as_salt` |
| Krawczyk, Eronen (2010) — HKDF Analysis | https://eprint.iacr.org/2010/264                                                             |
| NIST SP 800-56C Rev 2 — Key Derivation  | https://doi.org/10.6028/NIST.SP.800-56Cr2                                                    |

---

## 6. Decision Log

| Date       | Author               | Decision                                                                                                      |
| ---------- | -------------------- | ------------------------------------------------------------------------------------------------------------- |
| 2026-05-06 | Security Audit Panel | Accepted: fix HKDF salt/info semantics; accept wire break; mandate coordinated rollout                        |
| 2026-05-06 | Architecture         | Confirmed: zero-salt Extract + version-prefixed Expand info is consistent with TLS 1.3 §7.1 and RFC 5869 §2.2 |
| 2026-05-06 | CTO                  | Approved: document as ADR-001; add to CHANGELOG; no partial migration path                                    |
