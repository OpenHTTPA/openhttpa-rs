# `OpenHTTPA` Protocol Deniability Analysis

This document analyzes the trade-off between **Attestation** (non-repudiation) and **Deniability** in the `OpenHTTPA` protocol.

## 1. Context: Non-Repudiation vs. Deniability

In standard TLS 1.3, communication is often considered _deniable_ because both parties know the shared session key and could, in theory, forge any message after the handshake. However, `OpenHTTPA` introduces **TEE Attestation**, which provides hardware-enforced proof of the server's identity and the session's integrity.

## 2. `OpenHTTPA` Deniability Profile

### 2.1 Server Non-Repudiation (Low Deniability)

The server's role in `OpenHTTPA` is designed for **High Accountability**. Because the server sends an attestation quote (signed by the TEE's private identity key) that is cryptographically bound to the session transcript (via the `Transcript-Hash`), the server cannot easily deny having participated in the session.

- **Proof**: The `AtHS` response contains a `sign(h(transcript), sk_tee)`.
- **Impact**: This is a desired property for **Agentic Provenance** and **Confidential Computing**, where the client must be certain of the server's TEE status.

### 2.2 Client Deniability (High Deniability)

The client in `OpenHTTPA` remains largely deniable. While the client participates in the handshake with a `client_random` and `challenge`, the client does not (by default) provide a hardware-backed signature of their own.

- **Exception**: In Mutual `OpenHTTPA` (mOpenHTTPA), where the client also provides a TEE quote, both parties lose deniability in favor of mutual accountability.

## 3. Mitigation Strategies for Privacy-Preserving Contexts

For use cases where deniability is a requirement (e.g., anonymous whistleblowing to an attested collector), the following strategies are recommended:

1.  **Deniable Attestation**: Future versions of `OpenHTTPA` could utilize **Zero-Knowledge Proofs (ZKP)** or **Group Signatures** for attestation. This would prove that "a valid TEE" generated the quote without revealing the specific hardware identity.
2.  **Quote Discarding**: Clients may choose to verify the quote and then discard it, rather than logging it. However, the `Transcript-Hash` binding still leaves a trace that can be re-verified if the handshake messages are captured.

## 4. Audit Conclusion

`OpenHTTPA` prioritizes **Transparency** and **Provenance** over Deniability. This choice is deliberate, as the primary use case is building a **Verifiable Agent Mesh** where accountability is the foundation of trust.

---

_Maintained by the `OpenHTTPA` Security Team_
