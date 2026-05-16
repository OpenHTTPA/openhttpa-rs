# `OpenHTTPA` Smart Contracts

<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org) -->

This directory contains the smart contract components for the `OpenHTTPA` protocol, specifically focusing on **Confidential Oracle** verification.

## Architecture

### 1. EVM Verifier (`src/OpenHttpaVerifier.sol`)

The `OpenHttpaOracleVerifier` contract provides on-chain verification for `OpenHTTPA` Oracle payloads. It validates:

- **Domain Separation**: Ensures the TEE quote was intended for the `OpenHTTPA` protocol.
- **Transcript Binding**: Verifies that the TEE quote is mathematically bound to the specific `OpenHTTPA` session transcript hash (SHA-384).
- **ZK Proofs**: (Optional) Integrates with RISC Zero verifiers to validate Web2 payload integrity.

### 2. Bitcoin Taproot Scripts (`bitcoin/taproot_template.ts`)

Reference scripts for bridging `OpenHTTPA` data to Bitcoin using Taproot and BitVM.

## Development

### Requirements

- [Foundry](https://book.getfoundry.sh/) (Forge, Cast, Anvil)

### Build & Test

```bash
# Build contracts
forge build

# Run tests
forge test

# Format code
forge fmt
```

## Security

These contracts are part of the `OpenHTTPA` high-assurance infrastructure. They enforce strict transcript binding to mitigate replay and man-in-the-middle attacks on the Oracle bridge.
