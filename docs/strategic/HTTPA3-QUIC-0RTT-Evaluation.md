# SPDX-License-Identifier: Apache-2.0 OR MIT

# Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

# `OpenHTTPA` Strategic Future: Expert Panel Consultation

**Date:** 2026-05-06  
**Subject:** Evaluation of HTTPA/3 (QUIC) & 0-RTT Confidentiality  
**Panel:** Security Lead · Architecture · IETF Liaison · TEE Hardware Expert

---

## 1. Executive Summary

This consultation evaluates the integration of **HTTPA/3 (QUIC)** and **0-RTT Confidentiality** into the `OpenHTTPA` protocol suite. The goal is to reduce latency while maintaining the high-assurance hardware-binding and post-quantum security properties established in `OpenHTTPA`.

The panel concludes that **HTTPA/3 is the essential evolution** for high-performance TEE-to-TEE communication, particularly for large-scale agent meshes. We propose a specific **0-RTT Confidentiality** mechanism built on top of `OpenHTTPA`'s existing Session Resumption architecture, enabling the first "Trusted Request" (TrR) to be sent in the first flight of the QUIC connection.

---

## 2. HTTPA/3 (QUIC) Integration

### 2.1 Strategic Rationale

`OpenHTTPA` currently operates over TCP (via HTTP/2) or gRPC. While secure, these transports suffer from **Head-of-Line (HoL) Blocking** and high connection setup latency. In multi-hop TEE environments (e.g., `OpenHTTPA` Mesh), these delays compound.

**HTTPA/3 (QUIC) provides:**

- **Multiplexing without HoL Blocking**: Stream-level isolation prevents a slow TEE attestation process on one stream from blocking other trusted requests.
- **Connection Migration**: Essential for mobile agents and dynamic cloud environments.
- **Integrated TLS 1.3**: Reduces the handshake overhead by combining transport and application security flights.

### 2.2 Architectural Impact

The `openhttpa-transport` crate already contains a stub for `H3Transport`. Moving this to production involves:

- **Quinn Integration**: Leveraging the `quinn` crate for robust UDP/QUIC management.
- **Double Encryption Management**: Ensuring that the overhead of QUIC-level encryption (TLS 1.3) and `OpenHTTPA`-level encryption (AES-256-GCM inside TEE) is minimized through efficient buffer handling and potentially AES-NI hardware offloading.

---

## 3. 0-RTT Confidentiality Evaluation

### 3.1 The Challenge

Standard `OpenHTTPA` requires a full SIGMA-I handshake (AtHS) to exchange nonces, public keys, and hardware quotes. This involves at least 1-RTT (Attest Request -> Attest Response) before the first Trusted Request (TrR) can be sent.

**Goal**: Enable "0-RTT TrR" where the client sends the first encrypted payload in the first QUIC flight.

### 3.2 Proposed Mechanism: Resumption-Bound 0-RTT

The panel recommends binding 0-RTT confidentiality to the **`OpenHTTPA` Session Resumption** (`Attest-Ticket-Resumption`) mechanism.

**Protocol Flow:**

1.  **Pre-requisite**: Client and Server have established a previous session and the client holds a valid `Attest-Ticket`.
2.  **QUIC Handshake**: Client initiates QUIC connection and includes the `Attest-Ticket` in the `Initial` packet (as part of the HTTP/3 request headers).
3.  **Key Derivation**: Using the `Master Secret` from the ticket and the new QUIC connection ID (or a dedicated 0-RTT nonce), both sides derive the 0-RTT session keys.
4.  **0-RTT Payload**: Client sends the first `TrR` (encrypted with 0-RTT keys) in the same flight as the `Initial` packet.

### 3.3 Security Audit Results (Expert Panel Analysis)

| Risk Area                | Evaluation                                                                 | Mitigation Strategy                                                                                                                                |
| :----------------------- | :------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Replay Attacks**       | **High Risk**. 0-RTT is notoriously vulnerable to replay.                  | Enforce strict `ReplayGuard` with monotonic nonces stored in the `Attest-Ticket`. Servers MUST maintain a short-term bloom filter of 0-RTT nonces. |
| **Forward Secrecy**      | **Moderate Loss**. 0-RTT keys are derived from a long-lived Master Secret. | Limit the lifetime of `Attest-Tickets` (e.g., < 1 hour). Rotate Master Secrets upon the first 1-RTT handshake after resumption.                    |
| **TEE State Binding**    | **Crucial**. Ensure the 0-RTT request is bound to the same enclave.        | The `Attest-Ticket` contains the original Enclave Identity (MRENCLAVE). The server MUST verify that the resuming enclave matches the ticket.       |
| **Transcript Integrity** | **Maintained**.                                                            | The 0-RTT request includes an AHL Binder. The 0-RTT transcript is deterministic based on the ticket + 0-RTT nonces.                                |

---

## 4. Formal Verification Plan

To ensure the 0-RTT extension does not introduce protocol-level vulnerabilities, the panel mandates the following formal updates:

1.  **ProVerif Model**: Extend `handshake.pv` with a `process_resumption` macro that models 0-RTT as a separate entry point. Prove `0RTT_Secrecy` and `0RTT_Agreement` lemmas.
2.  **Tamarin Prover**: Update `handshake.spthy` to model the persistent state of the ticket store. Verify that a compromised ticket only compromises the specific resumed session, not past or future 1-RTT sessions.

---

## 6. Confidential Oracle Bridge (Web3 Scaling)

The panel also evaluates the **Confidential Oracle Bridge** as a critical scaling vector for `OpenHTTPA`. By acting as a trusted data provider for L1/L2 blockchains, `OpenHTTPA` can capture significant value in the "Confidential Coprocessor" market.

**Recommendations:**

- **Standardize BitVM2 Bindings**: Develop formal Taproot templates for verifying `OpenHTTPA` transcripts on Bitcoin.
- **ZK-Hardware Acceleration**: Leverage the `nvidia_gpu` provider to accelerate ZK-STARK proof generation for Oracle responses. The build system automatically detects `nvcc` (CUDA) on Linux or `metal` on macOS to enable zero-config hardware acceleration while maintaining compatibility with non-GPU runners.

---

### Panel Sign-off

- **Security Lead**: _Approved (pending ReplayGuard audit)_
- **Architecture**: _Approved (essential for Mesh scaling)_
- **IETF Liaison**: _Approved (aligns with HTTP/3 semantics)_
- **TEE Expert**: _Approved (ensures attestation freshness)_
