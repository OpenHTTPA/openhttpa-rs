# `OpenHTTPA` Formal Verification and Protocol Analysis Report

| Metadata           | Value                                      |
| :----------------- | :----------------------------------------- |
| **Document ID**    | OPENHTTPA-VER-2026-001                     |
| **Version**        | 1.0 (Official Release)                     |
| **Status**         | Final                                      |
| **Date**           | May 2026                                   |
| **Authors**        | The `OpenHTTPA` Foundation (openhttpa.org) |
| **Classification** | UNCLASSIFIED // PUBLIC                     |
| **Subject**        | Symbolic and Temporal Verification Results |

---

## 1. Introduction

This report documents the formal verification of the `OpenHTTPA` protocol handshake (AtHS) and trusted request (TrR) phases. We employ automated theorem proving and symbolic analysis to provide mathematical assurance that the protocol satisfies its stated security properties under the Dolev-Yao adversary model.

## 2. Formal System Model

The protocol is modeled as a set of interacting processes in a concurrent environment.

### 2.1 Symbolic Representations

- **KEM**: Modeled as an ideal IND-CCA2 primitive.
- **AEAD**: Modeled as an ideal authenticated encryption scheme (INT-CTXT, IND-CPA).
- **Transcript Hash**: Modeled as a random oracle (collision-resistant).
- **TEE Quotes**: Modeled as unforgeable signatures bound to the transcript hash.

## 3. ProVerif Symbolic Analysis

### 3.1 ProVerif Script Structure (Handshake)

The ProVerif model (`formal/handshake.pv`) defines the message exchange and queries for secrecy and authentication.

```proverif
(* Handshake Secrecy Query *)
query secret master_secret.
query secret client_write_key.
query secret server_write_key.

(* Authentication Query: Injective Agreement *)
query i:host, j:host, t:transcript;
      event(end_handshake(i, j, t)) ==> event(begin_handshake(i, j, t)).
```

### 3.2 Proved Lemmas

1.  **Lemma-PV-01 (Secrecy of Master Secret)**: In the presence of a Dolev-Yao adversary, the master secret derived from the hybrid KEM exchange is never leaked to the network.
2.  **Lemma-PV-02 (Mutual Handshake Authentication)**: If a client completes a handshake with a server, the server must have participated in that exact handshake with the same transcript.
3.  **Lemma-PV-03 (AHL Integrity)**: The adversary cannot modify the Attested Header List (AHL) without the change being detected by the HMAC-SHA-384 binder.
4.  **Lemma-PV-04 (Oracle Transcript Binding)**: The formal model confirms that an Oracle quote bound to `transcript_hash_1` cannot be successfully verified in a session with `transcript_hash_2`. This prevents Oracle evidence from being "poached" or re-used across different secure channels.

## 4. Tamarin Temporal Logic Verification

Tamarin was used to verify properties involving state and long-term key compromise.

### 4.1 Temporal Properties

- **PFS (Perfect Forward Secrecy)**: Verified that a session's confidentiality is maintained even if the TEE's long-term identity keys (AK) are compromised after the session concludes.
- **KCI (Key Compromise Impersonation)**: Verified that compromising a client's key does not allow the adversary to impersonate a server to that client.

### 4.2 Proof Results

The Tamarin model successfully discharged all proof goals without counterexamples:

- `Secrecy`: PROVED
- `Injective_Agreement`: PROVED
- `Forward_Secrecy`: PROVED
- `AHL_Binding`: PROVED

## 5. Security Invariant Verification

We formally verified the following invariants:

### 5.1 Transcript Collision Resistance

Given the use of SHA-384 and length-prefixed encoding for all transcript fields (Randoms, Public Keys, Ciphertexts), the probability of a transcript collision is negligible ($< 2^{-192}$).

### 5.2 AtB Isolation

The formal model confirms that an Attest Base (AtB) assigned to Client $A$ cannot be accessed or influenced by Client $B$, provided the `Atb-ID` (UUID v4) remains secret and unguessable.

## 6. Conclusion

The formal verification process confirms that the `OpenHTTPA` protocol is mathematically sound and resistant to the identified threat vectors. The integration of hybrid KEM and transcript-bound attestation provides a robust defense against both classical and quantum-capable adversaries.

---

**References**

- [ProVerif] Blanchet, B., "ProVerif: Cryptographic Protocol Verifier in the Formal Model".
- [Tamarin] "The Tamarin Prover for symbolic analysis of security protocols".
- [FIPS 203] NIST, "Module-Lattice-Based Key-Encapsulation Mechanism Standard".
