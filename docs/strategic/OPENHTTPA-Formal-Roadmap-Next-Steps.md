# SPDX-License-Identifier: Apache-2.0 OR MIT

# Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

# `OpenHTTPA` Formal Strategic Roadmap & Next Steps

**Date**: 2026-06-15  
**Status**: Formal Roadmap  
**Contributors**: Top-Tier Domain Experts (CEO, CTO, Security, Product, CSPs, Enterprise & Industry Customers)

---

## 1. Executive Summary

This formal roadmap defines the strategic trajectory and concrete next steps for the `OpenHTTPA` protocol. Synthesized from the collective expertise of top-tier domain leaders, this document aligns the project's evolution with strict operational rules: security-first engineering, Post-Quantum Cryptography (PQC) supremacy, fully autonomous validation, and leveraging modern language advancements such as Rust 2024 edition.

Our overarching goal is to establish `OpenHTTPA` as the ubiquitous, hardware-attested transport standard for Zero-Trust Confidential Computing and Agentic AI ecosystems.

---

## 2. Domain Expert Perspectives & Strategic Directives

### 2.1 Chief Executive Officer (CEO) - Vision & Market Positioning

**Directive**: Drive the adoption of `OpenHTTPA` as the foundational trust fabric for the emerging AI economy and enterprise confidential computing.

- **Goal**: Monetize and standardize "Agentic Trust" while safeguarding the open-source ecosystem through robust patent defense strategies.
- **Next Steps**:
  - Engage with standards bodies (IETF, NIST) to advance `draft-openhttpa-protocol-00` to a formally published RFC.
  - Form strategic alliances with leading AI labs to mandate `OpenHTTPA` for High-Assurance Web3 Oracles and Secure Multi-Party Computation (MPC).
  - Advocate the Defensive Termination Clause to guarantee patent safe harbors for enterprise adopters.

### 2.2 Chief Technology Officer (CTO) - Architecture & Engineering Excellence

**Directive**: Uphold the highest engineering standards by leveraging cutting-edge language features and enforcing fully autonomous validation.

- **Goal**: Maintain a resilient, performant, and memory-safe monorepo built on modern primitives.
- **Next Steps**:
  - **Rust 2024 Migration**: Systematically migrate the entire workspace to the Rust 2024 edition to leverage the latest language paradigms and optimizations.
  - **Literal Extraction**: Refactor all literal strings across the codebase into named constant strings to ensure consistency and readability.
  - **Autonomous Testing Pipelines**: Enhance CI/CD to feature fully autonomous validation, incorporating edge cases, functional tests, and end-to-end (e2e) tests. Ensure all temporary generation scripts (`/tmp`) are strictly isolated and ephemeral.

### 2.3 Security Expert - Cryptography & Threat Modeling

**Directive**: Guarantee an impenetrable, post-quantum resilient cryptographic posture with zero compromises on secret management.

- **Goal**: Maintain resilience against "Harvest Now, Decrypt Later" (HNDL) threats and rigorous adherence to FIPS 140-3 compliance.
- **Next Steps**:
  - **PQC Exclusivity**: Enforce that all cryptographic key exchanges and signature schemes are exclusively Post-Quantum Cryptography (PQC) qualified (e.g., ML-KEM-768, ML-DSA-65).
  - **Zero Hardcoded Secrets**: Implement continuous static analysis to ensure absolutely no cryptographic values or secrets are hardcoded in the repository.
  - **Continuous Formal Verification**: Integrate ProVerif and Tamarin Prover into the autonomous CI pipeline to mathematically prove security properties on every commit.

### 2.4 Product & Service Manager - Developer Experience & Ecosystem

**Directive**: Ensure `OpenHTTPA` is accessible, configurable, and seamlessly integrates with diverse technological stacks.

- **Goal**: Expand the developer ecosystem through robust language bindings (Python, Node.js, C, Go, Wasm) and intuitive SDKs.
- **Next Steps**:
  - **Verified AI (V-AI) Rollout**: Polish the `openhttpa-llm` and `openhttpa-mcp` crates to deliver a frictionless experience for building hardware-backed AI Agentic Swarms.
  - **Documentation Alignment**: Actively update all documentation, code comments, and webpage contents consistently with any new features, adhering to the "documentation as code" philosophy.

### 2.5 Cloud Service Providers (CSPs) - Infrastructure Integration

**Directive**: Enable seamless, scale-out TEE deployments in the cloud without increasing the Trusted Computing Base (TCB) of the host provider.

- **Goal**: Provide native orchestration components that interoperate flawlessly with modern cloud infrastructure.
- **Next Steps**:
  - **Multi-Vendor TEE Federation**: Mature `openhttpa-tee` abstractions to allow interoperability across Intel TDX, AMD SEV-SNP, and AWS Nitro Enclaves.
  - **TEE-Native Orchestration**: Standardize deployment artifacts for `openhttpa-ingress` and `openhttpa-broker` tailored for Kubernetes, ensuring sessions terminate natively within enclaves.

### 2.6 Enterprise & Industry Customers - Compliance & Governance

**Directive**: Deliver a dynamic, policy-driven authorization layer to meet strict regulatory and compliance requirements.

- **Goal**: Shift from static access control to dynamic, context-aware Policy-as-Code.
- **Next Steps**:
  - **Dynamic Policy Integration (OPA)**: Deploy Open Policy Agent (OPA) integration within the `openhttpa-mesh` to evaluate hardware quotes and geographic attestation data in real-time.
  - **ZK-Aggregated Attestation (ZAA)**: Finalize `openhttpa-zk` to compress complex DCAP hardware quotes into concise ZK-SNARKs, allowing resource-constrained enterprise edge devices to participate in the trust fabric.

---

## 3. Consolidated Implementation Timeline & Next Steps

| Phase                                  | Timeframe | Focus Area             | Key Deliverables                                                                                                                                                        |
| :------------------------------------- | :-------- | :--------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Phase 1: Hardening & Modernization** | Q3 2026   | Engineering & Security | Migrate to Rust 2024; Constant extraction for all literal strings; PQC validation sweep; Integrate formal verification into CI; Remove any potential hardcoded secrets. |
| **Phase 2: AI & Policy Expansion**     | Q4 2026   | Product & Enterprise   | Release OPA Policy Engine integration; Launch Verified AI (V-AI) components for MCP/AAM; Publish formal IETF/NIST updates.                                              |
| **Phase 3: Scale & Federation**        | Q1 2027   | CSPs & Ecosystem       | Multi-Vendor TEE sync implementation; ZK-DCAP Compression stable release; Expand Agentic Swarm orchestration testing.                                                   |

---

## 4. Conclusion

The path forward for `OpenHTTPA` demands uncompromising adherence to security-first principles, autonomous verification, and strategic alignment with global standardization efforts. By executing on these specific next steps, the project will cement its position as the critical trust layer for next-generation confidential computing.
