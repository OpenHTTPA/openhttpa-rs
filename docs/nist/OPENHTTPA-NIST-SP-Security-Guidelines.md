# NIST Special Publication (Draft): Security Guidelines for `OpenHTTPA` Deployment

| Metadata           | Value                                                      |
| :----------------- | :--------------------------------------------------------- |
| **Document ID**    | OPENHTTPA-SP-2026-001                                      |
| **Version**        | 1.1 (Revision 1)                                           |
| **Status**         | Final                                                      |
| **Date**           | November 2026                                              |
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
- Both the client and server MUST verify that the peer's measurements match the authorized allow-list for its Attestation Profile: `launch_measurement` (`direct-sev-snp`), `MRTD` and `RTMR[0..3]` (`direct-tdx`), or the reviewed paravisor build plus vTPM PCRs 4, 7 and 11 (`azure-cvm-snp`, `azure-cvm-tdx`).

### 4.1a Attestation Profiles (Revision 1)

- Policies SHOULD name the profile a server must prove. Verifiers MUST refuse profiles they do not implement and MUST NOT accept evidence of one profile as another.
- **Class B (Azure)**: the paravisor's launch measurement or `MRTD` changes with the Azure host build. Operators MUST keep a reviewed allow-list of builds and treat a new build as a change requiring review, not as an automatic update.
- **Identity keys at rest**: seal them to the vTPM under a PCR policy (Class B), or under an SNP `MSG_KEY_REQ` derived key bound to the launch measurement (`direct-sev-snp`). TDX has no sealing key, so `direct-tdx` identity keys are per boot or released by a key broker after attestation. A key protected only by a host-provided vTPM is exposed to the host.
- Where possible, clients SHOULD pin the server's identity key after first verification: later sessions are then authenticated by ML-DSA-65 even if a classical attestation root is broken.

### 4.2 Attestation Revocation

> [!WARNING]
> Organizations MUST maintain a centralized **Attestation Revocation List (ARL)** to immediately invalidate enclaves associated with compromised services or hardware platforms.

## 5. Auditing and Logging

### 5.1 Transcript Auditing

- The SHA-384 transcript hash of every `OpenHTTPA` handshake SHOULD be logged in a tamper-evident audit trail (e.g., a hash-chain or distributed ledger).
- These logs allow for post-incident verification that the session was established with a legitimate TEE.
- For independent review, record handshakes as `openhttpa-audit-v1` records (raw `ATTEST` heads, evidence and AEAD framing; never plaintext). Auditors verify them offline from the raw octets with their own tools, without trusting the implementation that produced them. The recorder's clock is not authenticated; the epoch issue time is.

### 5.1a HTTP Field Names (Revision 1)

- Proxies emit the RFC 6648 field names `OpenHTTPA-Verified`, `OpenHTTPA-Attestation-Type`, `OpenHTTPA-Measurement`, `OpenHTTPA-Sealed-Key-Fingerprint`, `OpenHTTPA-Upstream-Endpoint` and `OpenHTTPA-Error`, together with the legacy `X-OpenHTTPA-*` aliases during the transition. Consumers SHOULD read the unprefixed field first.
- Proxies MUST strip every field in the namespace, in both spellings and any letter case, from relayed requests and responses before adding their own; consumers MUST NOT trust these fields on traffic that bypassed their own proxy.

### 5.2 Behavioral Analysis

- Monitor for anomalies in the frequency of `ATTEST` requests, which may indicate a distributed denial-of-service (DDoS) attack targeting the high-compute cost of ML-KEM key generation.

## 6. Conclusion

Adherence to these guidelines ensures that `OpenHTTPA` deployments maintain the high-assurance security posture required for NIST compliance and national security systems.

---

**Related NIST Publications**

- [SP 800-53 Rev. 5] "Security and Privacy Controls for Information Systems and Organizations".
- [SP 800-147B] "BIOS Protection Guidelines".
- [SP 800-190] "Application Container Security Guide".

**Revision History**

| Version | Date          | Changes                                                                                                                                 |
| ------- | ------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| 1.0     | May 2026      | Initial release.                                                                                                                        |
| 1.1     | November 2026 | Profile-specific measurements (§4.1), Attestation Profiles and key sealing (§4.1a), raw wire audit records (§5.1), field names (§5.1a). |
