# Privacy Impact Assessment (PIA): `OpenHTTPA` Protocol

| Metadata           | Value                                                |
| :----------------- | :--------------------------------------------------- |
| **Document ID**    | OPENHTTPA-PIA-2026-001                               |
| **Version**        | 1.0 (Official Release)                               |
| **Status**         | Final                                                |
| **Date**           | May 2026                                             |
| **Authors**        | The `OpenHTTPA` Foundation (openhttpa.org)           |
| **Classification** | UNCLASSIFIED // PUBLIC                               |
| **Subject**        | Privacy Risk Analysis and Mitigation for `OpenHTTPA` |

---

## 1. Introduction

This Privacy Impact Assessment (PIA) evaluates the `OpenHTTPA` protocol against the **NIST Privacy Framework**. While `OpenHTTPA` is primarily a security protocol, the inclusion of hardware attestation quotes and provenance tracking introduces specific privacy risks related to device fingerprinting and user tracking.

## 2. Privacy Risk Characterization

We identify two primary privacy-sensitive data categories in `OpenHTTPA`:

### 2.1 Hardware Attestation Fingerprinting

Hardware quotes (e.g., Intel TDX/SGX) may contain stable identifiers (e.g., unique CPU IDs, fused keys) that allow a server to track a specific TEE instance across multiple sessions, even if the user changes IP addresses or credentials.

### 2.2 Provenance Chain Leakage

The `Attest-Provenance` header reveals the sequence of agents that have handled a request. In a multi-hop scenario, this can leak the user's internal network topology or the identities of specialized agents (e.g., "Medical Diagnoser Agent") to unauthorized observers.

## 3. Privacy Risk Assessment

| Risk ID  | Threat Actor     | Impact                                    | Likelihood | Mitigation Strategy                      |
| -------- | ---------------- | ----------------------------------------- | ---------- | ---------------------------------------- |
| **P-01** | Malicious Server | Long-term tracking of TEE instance        | High       | Use Privacy-Preserving Attestation (DAA) |
| **P-02** | Network Observer | Identification of agent mesh topology     | Medium     | Encrypt Provenance within the session    |
| **P-03** | Service Provider | Linking disparate user accounts via HW ID | High       | Strict Data Minimization Policies        |

## 4. Technical Mitigations and Best Practices

### 4.1 Privacy-Preserving Attestation (DAA/EPID)

Implementations SHOULD prefer attestation schemes that utilize **Direct Anonymous Attestation (DAA)** or **Enhanced Privacy ID (EPID)**. These technologies allow the TEE to prove its hardware integrity without revealing its unique, serial-number-level identity.

### 4.2 Provenance Minimization

The `Attest-Provenance` header MUST only contain the minimal information required for security auditing. Identifiers for intermediate agents SHOULD be ephemeral or localized to the specific agent mesh.

### 4.3 Provenance Encryption

`OpenHTTPA` ensures that all sensitive headers, including `Attest-Provenance`, are encrypted within the established AtHS session, protecting them from passive network observers.

### 4.4 Encrypted Client Hello (Metadata Protection)

Handshake parameters such as the requested protocol versions, cipher suites, and specific routing identifiers can uniquely fingerprint a client or agent prior to session establishment. `OpenHTTPA` mitigates this via the `Attest-Encrypted-Hello` extension, allowing the client to encapsulate these fields using ML-KEM HPKE. This reduces the observable metadata to cover traffic, hindering traffic analysis and censorship attempts.

## 5. User Agency and Transparency

- **Policy Disclosure**: Service providers utilizing `OpenHTTPA` SHOULD disclose their attestation policies and whether hardware identifiers are used for tracking.
- **Opt-In/Opt-Out**: Where feasible, users SHOULD be given the choice to use "Standard Confidential" sessions (no hardware ID revealed) vs. "Verified Trusted" sessions (full hardware quote provided).

## 6. Conclusion

By integrating privacy-preserving attestation technologies and enforcing strict data minimization, `OpenHTTPA` balances the need for hardware-verified security with the fundamental right to user privacy.

---

**References**

- [NIST Privacy Framework] "A Tool for Improving Privacy through Enterprise Risk Management".
- [ISO/IEC 29100] "Information technology — Security techniques — Privacy framework".
- [EPID] Intel, "Enhanced Privacy ID (EPID) Technology".
