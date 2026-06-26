# `OpenHTTPA` FIPS 140-3 Compliance Capability Report

| Metadata           | Value                                                         |
| :----------------- | :------------------------------------------------------------ |
| **Document ID**    | OPENHTTPA-FIPS-2026-001                                       |
| **Version**        | 1.0 (Official Release)                                        |
| **Status**         | Final                                                         |
| **Date**           | May 2026                                                      |
| **Authors**        | The `OpenHTTPA` Foundation (openhttpa.org)                    |
| **Classification** | UNCLASSIFIED // PUBLIC                                        |
| **Subject**        | Assessment of `OpenHTTPA` Cryptographic Module for FIPS 140-3 |

---

## 1. Introduction

This report evaluates the `OpenHTTPA` cryptographic implementation against the requirements specified in FIPS 140-3, "Security Requirements for Cryptographic Modules". `OpenHTTPA` is designed to meet or exceed Level 3 requirements when deployed within a validated Trusted Execution Environment (TEE). _Note: `OpenHTTPA` utilizes NIST-standardized algorithms (e.g., FIPS 203, FIPS 204), but formal CMVP certification of the underlying cryptographic modules (like aws-lc-rs and liboqs) is currently pending._

## 2. Cryptographic Module Specification

### 2.1 Module Boundary

The cryptographic module is defined as the `openhttpa-crypto` library, which provides the core implementations of:

- **Hybrid KEM Combiner**
- **HKDF Key Schedule**
- **AEAD (AES-GCM / ChaCha20-Poly1305)**
- **SHA-384 Hashing**

### 2.2 Operational Environment

The module operates within a **Hardware-Isolated Enclave** (e.g., Intel TDX, AMD SEV-SNP). The hardware provides the physical security and memory protection required for Level 3 compliance.

## 3. Approved Algorithms and Primitives

The following table maps the `OpenHTTPA` primitives to NIST-approved standards:

| Function                  | Algorithm           | NIST Standard         |
| ------------------------- | ------------------- | --------------------- |
| Symmetric Encryption      | AES-256-GCM         | FIPS 197 / SP 800-38D |
| Hashing (Transcript)      | SHA-384             | FIPS 180-4            |
| Hashing (Domain Binding)  | SHA-512             | FIPS 180-4            |
| Key Derivation            | HKDF (HMAC-SHA-384) | RFC 5869 / SP 800-56C |
| Key Agreement (PQ)        | ML-KEM-768          | FIPS 203              |
| Key Agreement (Classical) | X25519              | RFC 7748 / SP 800-186 |
| Digital Signature (PQ)    | ML-DSA-65           | FIPS 204              |

## 4. Self-Tests and Integrity Checks

To ensure the integrity of the cryptographic module, `OpenHTTPA` implements the following self-tests:

### 4.1 Power-Up Self-Tests (POST)

- **Known Answer Tests (KAT)**: Performed for AES-GCM, SHA-384, ML-KEM, and ML-DSA upon library initialization.
- **Software Integrity Test**: Verification of the library's HMAC-SHA-384 digest before execution.

### 4.2 Conditional Self-Tests

- **Continuous RNG Test**: Performed on each output from the TRNG.
- **Pair-wise Consistency Test**: Performed upon generation of a new X25519/ML-KEM/ML-DSA key pair.

## 5. Key Management and Zeroization

### 5.1 Key Generation

All session keys and ephemeral shares are generated using a NIST SP 800-90A compliant DRBG, seeded with hardware-backed entropy from the TEE processor.

### 5.2 Key Storage

Keys are stored exclusively within the enclave's encrypted memory. They are never exported to non-volatile storage or exposed to the host operating system.

### 5.3 Zeroization

All secret-bearing structures implement the `Zeroize` trait, ensuring that memory is wiped (overwritten with zeros) immediately after use or when the structure is dropped.

## 6. Physical Security (Level 3)

Physical security is inherited from the TEE hardware, which provides:

- **Enclave Isolation**: Active memory encryption with hardware-managed keys.
- **Side-Channel Mitigation**: Microarchitectural hardening against timing and cache attacks.

## 7. Conclusion

The `OpenHTTPA` cryptographic module architecture is fully aligned with FIPS 140-3 Level 3 requirements. By leveraging NIST-approved primitives and hardware-based isolation, `OpenHTTPA` provides a compliant and highly secure foundation for federal and critical infrastructure data protection.

---

**References**

- [FIPS 140-3] "Security Requirements for Cryptographic Modules".
- [FIPS 203] "Module-Lattice-Based Key-Encapsulation Mechanism Standard".
- [FIPS 204] "Module-Lattice-Based Digital Signature Standard".
- [SP 800-131A] "Transitions: Recommendation for Transitioning the Use of Cryptographic Algorithms and Key Lengths".
