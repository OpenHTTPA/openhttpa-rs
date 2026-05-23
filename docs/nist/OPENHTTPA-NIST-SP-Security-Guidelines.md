# NIST Special Publication (Draft): Security Guidelines for `OpenHTTPA` Deployment

| Metadata           | Value                                                      |
| :----------------- | :--------------------------------------------------------- |
| **Document ID**    | OPENHTTPA-SP-2026-001                                      |
| **Version**        | 1.0 (Official Release)                                     |
| **Status**         | Final                                                      |
| **Date**           | May 2026                                                   |
| **Authors**        | The `OpenHTTPA` Foundation (openhttpa.org)                 |
| **Classification** | UNCLASSIFIED // PUBLIC                                     |
| **Subject**        | Operational Security and TEE Configuration for `OpenHTTPA` |

---

## 1. Introduction

This document provides operational security guidelines for the deployment and management of the `OpenHTTPA` protocol within governmental and critical infrastructure environments. It complements the technical specification by focusing on the operational aspects of Trusted Execution Environment (TEE) lifecycle management.

## 2. TEE Infrastructure Hardening

### 2.1 Hardware Configuration

- **NIST SP 800-147B Compliance**: Ensure that the host platform BIOS/UEFI is cryptographically signed and verified (Secure Boot).
- **Enclave Isolation**: TEE memory encryption keys (e.g., MKTME for TDX) MUST be managed by the hardware security processor and never exposed to the host CPU.

### 2.2 Microcode and Firmware Updates

> [!WARNING]
> **Security Version Number (SVN)**: Implementations MUST enforce a minimum SVN policy. Enclaves running on platforms with known, unpatched microcode vulnerabilities (e.g., L1TF, MDS) MUST be rejected by the `OpenHTTPA` verifier.

## 3. Key Lifecycle Management

### 3.1 Session Key Entropy

- Use only NIST SP 800-90A/B/C compliant Deterministic Random Bit Generators (DRBGs).
- In virtualized TEEs (e.g., Intel TDX), ensure that entropy is sourced from the hardware RDRAND/RDSEED instructions directly, bypassing the host OS's entropy pool.

### 3.2 Key Rotation

- **Forward Secrecy**: `OpenHTTPA` provides Perfect Forward Secrecy (PFS) via ephemeral X25519/ML-KEM shares. Master secrets MUST NOT be persisted beyond the session lifetime.
  > [!IMPORTANT]
  > **Session Duration**: It is RECOMMENDED to limit the lifetime of an Attest Base (AtB) to 24 hours or less in high-security environments.

## 4. Identity and Access Management (IAM)

### 4.1 Mutual Attestation

- Implementations SHOULD require **Mutual Attestation** for all enclave-to-enclave communication.
- Both the client and server MUST verify that the Peer measurement (MR ENCLAVE/MR SIGNER) matches the authorized whitelist.

### 4.2 Attestation Revocation

> [!WARNING]
> Organizations MUST maintain a centralized **Attestation Revocation List (ARL)** to immediately invalidate enclaves associated with compromised services or hardware platforms.

## 5. Auditing and Logging

### 5.1 Transcript Auditing

- The SHA-384 transcript hash of every `OpenHTTPA` handshake SHOULD be logged in a tamper-evident audit trail (e.g., a hash-chain or distributed ledger).
- These logs allow for post-incident verification that the session was established with a legitimate TEE.

### 5.2 Behavioral Analysis

- Monitor for anomalies in the frequency of `ATTEST` requests, which may indicate a distributed denial-of-service (DDoS) attack targeting the high-compute cost of ML-KEM key generation.

## 6. Conclusion

Adherence to these guidelines ensures that `OpenHTTPA` deployments maintain the high-assurance security posture required for NIST compliance and national security systems.

---

**Related NIST Publications**

- [SP 800-53 Rev. 5] "Security and Privacy Controls for Information Systems and Organizations".
- [SP 800-147B] "BIOS Protection Guidelines".
- [SP 800-190] "Application Container Security Guide".
