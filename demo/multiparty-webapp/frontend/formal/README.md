# `OpenHTTPA` Formal Models & Verification Guide

This directory contains the formal security models for the `OpenHTTPA` Attested Handshake (AtHS). Follow this guide to reproduce the mathematical verification of the protocol.

## 🚀 Quick Start: Running the Proofs

### Prerequisites

You need the following tools installed:

- **ProVerif**: [Installation Guide](https://proverif.inria.fr/)
- **Tamarin Prover**: [Installation Guide](https://tamarin-prover.github.io/)

### 1. Run ProVerif (Symbolic Verification)

ProVerif verifies core secrecy and authentication properties.

```bash
proverif formal/handshake.pv
```

Expected output should show `Query ... is true` for all security properties.

### 2. Run Tamarin Prover (Temporal Verification)

Tamarin verifies stateful properties like Forward Secrecy.

**To run in CLI mode:**

```bash
tamarin-prover --prove formal/handshake.spthy
```

**To run in Interactive Mode (Web UI):**

```bash
tamarin-prover interactive formal/
```

Then open `http://127.0.0.1:3001` (default port) in your browser to visualize the attack graph exploration.

## 📂 File Structure

- `handshake.pv`: ProVerif model (Dolev-Yao symbolic analysis).
- `handshake.spthy`: Tamarin model (Temporal logic and state-based analysis).
- `PROVERIF.md`: Comprehensive report of ProVerif results.
- `TAMARIN.md`: Comprehensive report of Tamarin results.

## 🛡️ Security Properties Verified

1. **Secrecy**: Session keys are never exposed.
2. **Authentication**: Identity of the TEE server is cryptographically bound.
3. **Forward Secrecy**: Historical data is safe even if long-term keys leak later.
4. **Replay Protection**: Fresh nonces prevent message reuse.

---

_Maintained by the `OpenHTTPA` Security Team_
