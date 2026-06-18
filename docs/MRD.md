# Market Requirements Document (MRD): OpenHTTPA

**Version:** 1.1 (Revised post-Audit)
**Date:** June 2026
**Authors:** Gordon King, Hans Wang
**Project:** OpenHTTPA (Open Post-Quantum Hardware-Attested Protocol)

---

## 1. Executive Summary

### 1.1 Document Purpose

This Market Requirements Document (MRD) outlines the market opportunity, target audiences, and high-level requirements for OpenHTTPA. It is designed to align engineering, marketing, and business stakeholders on the strategic direction required to establish OpenHTTPA as the de-facto standard for post-quantum, hardware-attested application transport.

### 1.2 Product Vision

To redefine the foundational layer of secure internet communication by delivering a zero-trust, mathematically verifiable transport protocol. OpenHTTPA eliminates the vulnerabilities of traditional perimeter-based TLS by enforcing cryptographic termination directly within hardware-isolated Trusted Execution Environments (TEEs), securing the next generation of Confidential AI, Web3, and Agentic Swarms against "Harvest Now, Decrypt Later" (HNDL) quantum threats.

---

## 2. Market Needs & Problem Statement

### 2.1 The Problem

The current standard for data-in-transit, TLS 1.3, is fundamentally flawed for the emerging era of decentralized, high-value compute:

- **Perimeter Termination Vulnerability:** TLS typically terminates at the network edge (load balancers), exposing plaintext data to internal networks, privileged admins, and host OS vulnerabilities.
- **Quantum Vulnerability:** Traditional key exchange mechanisms (RSA, ECC) will be broken by Cryptographically Relevant Quantum Computers (CRQCs).
- **Lack of Hardware-Rooted Trust:** TLS cannot cryptographically prove _what_ software or hardware is processing the data after decryption.
- **The Confused Deputy Problem:** Standard transport protocols do not bind application semantics (L7) to the cryptographic session, enabling semantic re-routing.

### 2.2 Market Drivers

- **Enterprise AI Adoption:** Organizations hesitate to send sensitive proprietary data (PHI, PII, IP) to cloud-hosted LLMs due to a lack of provable privacy.
- **Autonomous Agentic Swarms:** AI agents require mutually authenticated, hardware-verified communication channels to perform high-value automated transactions without human oversight.
- **Web3 & DeFi Evolution:** Smart contracts need trustless, cryptographically proven real-world data (Oracles) without relying on trusted intermediaries.
- **Regulatory Compliance:** Approaching FIPS 140-3 mandates and NIST PQC transition requirements are forcing federal and enterprise infrastructure upgrades.

---

## 3. Target Market, Personas & Sizing

### 3.1 Target Segments

1.  **Cloud Providers & AI Hyperscalers:** Enterprises hosting foundational LLMs (e.g., OpenAI, Anthropic, AWS, Azure, Google Cloud).
2.  **Enterprise Security & FinTech:** Organizations handling highly regulated data requiring Multi-Party Computation (MPC).
3.  **Web3 Protocols & Oracle Networks:** Blockchain infrastructures requiring trustless off-chain computation.
4.  **Federal & Defense:** Government agencies migrating to Zero-Trust and Post-Quantum cryptographic standards.

### 3.2 Market Sizing (TAM / SAM / SOM)

- **Total Addressable Market (TAM):** $12 Billion (representing the projected global market specifically for Confidential Computing and hardware-attested security by 2028).
- **Serviceable Available Market (SAM):** $2.5 Billion (targeting enterprise sectors currently deploying or actively piloting TEE-based infrastructure for AI and highly regulated workloads).
- **Serviceable Obtainable Market (SOM):** $45 Million in the first 3 years, specifically capturing early-adopter Enterprise AI pipelines and high-value Web3 Oracle networks actively seeking post-quantum transport security.

### 3.3 User Personas

- **The Enterprise CTO (The Buyer):** Cares about compliance (FIPS 140-3, NIST), future-proofing against quantum threats, reducing the blast radius of data breaches, and enabling confidential AI adoption without regulatory risk.
- **The Security Architect (The Evaluator):** Cares about formal verification (ProVerif/Tamarin), memory safety (Rust), minimal Trusted Computing Base (TCB), and protection against semantic manipulation.
- **The Lead Developer (The Adopter):** Cares about developer ergonomics (FFI bindings for Python/Node.js/Go), integration with existing tooling (HTTP/3, gRPC), comprehensive documentation, and robust SDKs.

---

## 4. Product Value Proposition

**For AI Infrastructure:** "Compute on sensitive data without ever seeing it." OpenHTTPA provides mathematically proven guarantees that user prompts and data are only accessible by the authorized LLM running inside a verified TEE.

**For Web3 & Decentralized Systems:** "The Trustless Bridge." OpenHTTPA replaces centralized Oracle operators with hardware-attested cryptographic proofs.

**For Enterprise Security:** "Zero-Trust at the Silicon Level." Eliminates the host OS and cloud provider from the Trusted Computing Base, securing data-in-transit from the client all the way to the CPU enclave.

---

## 5. High-Level Market Requirements

### 5.1 Functional Requirements

- **Post-Quantum Agility:** Must natively support NIST-standardized algorithms (ML-KEM-768, ML-DSA-65) with hybrid fallback options.
- **Agnostic TEE Support:** Seamless compatibility with major enclaves: Intel TDX, AMD SEV-SNP, AWS Nitro Enclaves, ARM TrustZone.
- **Multi-Language SDKs:** Must provide first-class bindings for Python (AI workflows), Node.js (Web/Agentic), Go (Cloud Native), and C/C++ (Legacy integration).
- **Protocol Interoperability:** Must multiplex cleanly over existing transport architectures (HTTP/2, HTTP/3/QUIC, gRPC).
- **Semantic Context Binding (AHL):** Must cryptographically bind application-layer metadata (HTTP Method, URI) to the session MAC.

### 5.2 Non-Functional & Operational Requirements

- **Formal Security Proofs:** The protocol must maintain ongoing machine-checked formal verification (e.g., ProVerif) proving perfect forward secrecy and injective authentication.
- **Performance Overhead & SLAs:** The post-quantum math and TEE transitions (ECALLs/OCALLs) must be heavily optimized. The protocol must enforce a maximum performance degradation SLA of **< 5ms overhead** per handshake compared to standard TLS 1.3, specifically utilizing 0-RTT session resumption for latency-critical paths.
- **Memory Safety & Reliability:** Core implementation must be in Rust, featuring strict `#![deny(warnings)]`, memory-safe cryptographic buffer zeroization, and deterministic behavior.
- **Compliance & Certification:** Must be architected to achieve FIPS 140-3 validation boundaries via dependencies like `aws-lc-rs`.

### 5.3 Cryptographic Lifecycle, Disaster Recovery & Deployment

- **Key Lifecycle Management:** Mandatory implementation of automated key rotation policies and Attestation Revocation Lists (ARLs).
- **Disaster Recovery:** Clear fallback and incident response mechanisms in the event a specific hardware enclave generation (e.g., specific microcode version) is mathematically or physically compromised.
- **High-Availability Topologies:** The `openhttpa-broker` and orchestration layers must natively support state replication and high-availability clustering to ensure enterprise uptime.

---

## 6. Competitive Landscape

| Competitor / Standard      | Strengths                                        | Weaknesses against OpenHTTPA                                                      |
| :------------------------- | :----------------------------------------------- | :-------------------------------------------------------------------------------- |
| **TLS 1.3 (Standard)**     | Ubiquitous, heavily vetted.                      | Edge-termination, lacks hardware attestation, quantum-vulnerable (mostly).        |
| **mTLS**                   | Stronger authentication.                         | Hard to manage at scale, still terminates outside TEEs, no semantic L7 binding.   |
| **Proprietary Cloud TEEs** | Integrated deeply into specific clouds.          | Vendor lock-in, lacks cross-cloud heterogeneous attestation, often closed-source. |
| **OpenHTTPA (Ours)**       | Hardware-attested, PQC-native, semantic binding. | Nascent adoption curve, requires TEE-compatible hardware for full benefits.       |

---

## 7. Go-To-Market Strategy & Business Model

### 7.1 Positioning & Messaging

- **Core Narrative:** "OpenHTTPA is to the AI and Quantum era what TLS 1.0 was to the early e-commerce era."
- **Standardization Push:** Actively drive `draft-openhttpa-protocol-00` through IETF HTTPBIS/SECDISPATCH to achieve official RFC status.

### 7.2 Key GTM Channels & Incentives

1.  **Developer Relations (DevRel):** Hackathons targeting Confidential AI and Web3 Oracles. Interactive demos (e.g., the 100-agent Swarm simulation).
2.  **Strategic Partnerships:** Collaborate with hardware vendors (Intel, AMD, AWS) and AI model providers to create joint reference architectures.
3.  **Ecosystem Grants:** Establish a grant pool to incentivize Web3 Oracle networks and open-source AI projects to implement OpenHTTPA.

### 7.3 Business & Monetization Model

- **Open-Source Core:** The protocol and SDKs remain free and dual-licensed (Apache 2.0 / MIT) to guarantee widespread adoption.
- **Enterprise Monetization:** The OpenHTTPA Foundation/Entity will generate revenue via:
  - **Commercial Support & SLAs:** Paid enterprise contracts providing guaranteed issue resolution and architecture consulting.
  - **Managed Orchestration:** A managed, high-availability SaaS offering of the `openhttpa-ingress` and `openhttpa-broker` control planes.
  - **Certification Programs:** Paid cryptographic and operational certification for third-party hardware modules and agentic swarms.

---

## 8. Product Roadmap & Phasing

- **Phase 1: Foundation & Core Adopters (H1 2026)**
  - Deliver stable Rust core with basic TEE adapters (Intel TDX, AWS Nitro).
  - Finalize ProVerif models and secure FIPS 140-3 readiness for underlying crypto.
  - Release Python & Node.js bindings focusing on Confidential LLM integration.
- **Phase 2: Decentralization & Web3 Expansion (H2 2026)**
  - Deliver the ZK-Oracle bridge for EVM and Bitcoin networks.
  - Launch the Attested Agent Mesh (AAM) for Agentic Swarms.
  - Publish `draft-openhttpa-protocol-00` to the IETF.
- **Phase 3: Enterprise Scale & Federation (2027)**
  - Implement cross-cloud, heterogeneous TEE composite attestation.
  - Launch commercial enterprise orchestration SaaS and managed services.
  - Obtain official IETF RFC status and full NIST validations.

---

## 9. Success Metrics (KPIs)

- **Adoption Metrics:** Number of active enterprise deployments, GitHub stars, monthly SDK downloads (npm, PyPI, Crates.io).
- **Developer Ergonomics SLA (Time-to-Value):**
  - A developer must be able to integrate OpenHTTPA into a standard application with **< 10 lines of code**.
  - Time from repository clone to a successful hardware-attested handshake in a local mock environment must be **< 15 minutes**.
- **Standardization Milestones:** IETF Draft progression, NIST Technical Report inclusions, FIPS 140-3 certification of underlying modules.
- **Ecosystem Growth:** Number of third-party AI agents and Web3 Oracles utilizing OpenHTTPA for mutual attestation.
