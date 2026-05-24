# openhttpa-contract — API Specification

**Crate**: `openhttpa-contract`  
**License**: Apache-2.0 OR MIT  
**Solidity Version**: `^0.8.20`  
**Repository**: [openhttpa-rs](file:///home/ub/tmp/openhttpa-rs)

---

## Overview

`openhttpa-contract` contains the **on-chain Solidity smart contracts** for the OpenHTTPA ecosystem. These contracts enable decentralised, trustless verification of OpenHTTPA oracle payloads and TEE attestation data on EVM-compatible blockchains.

The contracts bridge the off-chain OpenHTTPA attestation system to on-chain environments by:

1. Verifying that an oracle payload was produced inside a TEE (via QUDD domain prefix checks and transcript hash binding).
2. Optionally delegating to a RISC Zero verifier contract for ZK proof verification (ZAA), enabling trustless verification without requiring on-chain TEE-specific infrastructure.

---

## Table of Contents

1. [`OpenHttpaOracleVerifier` Contract](#1-openhttpaoracleverifier-contract)
2. [`Counter` Contract (Development Utility)](#2-counter-contract)

---

## 1. `OpenHttpaOracleVerifier` Contract

Source: [OpenHttpaVerifier.sol](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-contract/src/OpenHttpaVerifier.sol)

```solidity
contract OpenHttpaOracleVerifier {
    ...
}
```

Verifies OpenHTTPA Oracle TEE quotes and optional ZK proofs on-chain. Intended for use by DeFi protocols, DAO governance systems, or any smart contract that requires verifiable off-chain data from a confidential TEE oracle.

---

### Structs

#### `OraclePayload` (Struct)

```solidity
struct OraclePayload {
    bytes transcriptHash;  // 48 bytes — SHA-384 of the OpenHTTPA handshake transcript
    bytes quote;           // Raw TEE attestation quote (platform-dependent format)
    bytes reportData;      // 64 bytes — QUDD embedded in the TEE quote
    bytes data;            // Arbitrary Web2 response payload fetched by the oracle
    bytes zkReceipt;       // Optional: RISC Zero ZK proof receipt (ZAA mode)
}
```

| Field            | Length             | Description                                                                                                                         |
| ---------------- | ------------------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| `transcriptHash` | 48 bytes           | SHA-384 transcript hash of the OpenHTTPA session that authorised this oracle fetch.                                                 |
| `quote`          | Platform-dependent | Raw hardware attestation quote. SGX DCAP quotes are ~4 KB; ZK-compressed quotes (~200 B) may be used when `zkReceipt` is non-empty. |
| `reportData`     | 64 bytes           | The QUDD (Quote User-Defined Data) embedded in the TEE quote. Must follow the OpenHTTPA domain-separation layout.                   |
| `data`           | Arbitrary          | The Web2 response body fetched by `OracleNode::fetch_and_prove`.                                                                    |
| `zkReceipt`      | Variable           | Optional `bincode`-serialised RISC Zero `Receipt` from `ZkProver::prove(ZkMode::Oracle)`.                                           |

---

### Events

#### `PayloadVerified`

```solidity
event PayloadVerified(bytes transcriptHash, address sender);
```

Emitted by `verifyOraclePayload` when verification succeeds. Indexable for off-chain monitoring and auditing.

| Parameter        | Type      | Description                                 |
| ---------------- | --------- | ------------------------------------------- |
| `transcriptHash` | `bytes`   | The verified transcript hash.               |
| `sender`         | `address` | The `msg.sender` who submitted the payload. |

---

### Functions

#### `verifyOraclePayload`

```solidity
function verifyOraclePayload(OraclePayload calldata payload) external returns (bool)
```

Verifies a submitted OpenHTTPA oracle payload.

**Verification Steps**:

1. **Length validation**:
   - Reverts with `"Invalid transcriptHash length (expected 48)"` if `payload.transcriptHash.length != 48`.
   - Reverts with `"Invalid reportData length (expected 64)"` if `payload.reportData.length != 64`.

2. **Domain separation prefix check** (T-10 hardening):
   Verifies that `payload.reportData[0..16]` matches the OpenHTTPA domain prefix `b"openhttpa hs server"` (first 16 bytes).
   - Reverts with `"Invalid domain separation prefix"` on mismatch.

3. **Transcript hash binding check**:
   Verifies that `payload.reportData[16..64]` contains `payload.transcriptHash`. This ensures the TEE quote was generated specifically for the session identified by `transcriptHash`, preventing quote replay from other sessions.
   - Reverts with `"Transcript hash mismatch in reportData"` on mismatch.

4. **ZK proof verification** (if `payload.zkReceipt.length > 0`):
   In production, delegates to a deployed RISC Zero verifier contract:

   ```solidity
   IRiscZeroVerifier(verifierAddress).verify(payload.zkReceipt, imageId, journal);
   ```

   This verifies that:
   - The ZK receipt proves the RISC Zero guest (`OPENHTTPA_GUEST_ID`) ran correctly.
   - The guest journal (decoded as `ZkOutput`) shows `is_valid = true` and the `oracle_payload_hash` matches `SHA-256(payload.data)`.

   > **Note**: The RISC Zero verifier contract call is stubbed in the current milestone. Integration requires deploying the RISC Zero groth16 verifier contract (available from [RISC Zero's GitHub](https://github.com/risc0/risc0)) and providing its address.

5. Emits `PayloadVerified(payload.transcriptHash, msg.sender)` on success.
6. Returns `true`.

**Returns**: `bool` — always `true` on successful verification (reverts on any failure).

**Gas Considerations**: The transcript hash binding loop and prefix check are O(n) where n is 48–64 bytes; gas cost is bounded and predictable. ZK proof verification gas cost is determined by the RISC Zero groth16 verifier contract (typically ~250,000 gas for a groth16 proof).

---

## 2. `Counter` Contract (Development Utility)

Source: [Counter.sol](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-contract/src/Counter.sol)

A minimal `Counter` contract generated by Foundry scaffolding. Used only for development and testing the Foundry toolchain setup.

```solidity
contract Counter {
    uint256 public number;
    function setNumber(uint256 newNumber) public;
    function increment() public;
}
```

This contract has **no role in the OpenHTTPA protocol** and should not be deployed to mainnet.

---

## Integration Guide

### On-Chain Usage

```javascript
// Deploy the verifier contract once per chain
const verifier = await OpenHttpaOracleVerifier.deploy();

// Submit an oracle response from openhttpa-oracle's OracleResponse
const tx = await verifier.verifyOraclePayload({
  transcriptHash: oracleResponse.transcript_hash,
  quote: oracleResponse.quote,
  reportData: extractReportDataFromQuote(oracleResponse.quote),
  data: oracleResponse.data,
  zkReceipt: oracleResponse.zk_receipt ?? '0x',
});
await tx.wait();
// PayloadVerified event is emitted on success
```

### Off-Chain (Event Monitoring)

```javascript
verifier.on('PayloadVerified', (transcriptHash, sender) => {
  console.log('Verified transcript:', Buffer.from(transcriptHash).toString('hex'));
  console.log('Submitted by:', sender);
});
```

---

## Security Invariants

| Invariant                       | Mechanism                                                         |
| ------------------------------- | ----------------------------------------------------------------- |
| Quote bound to session          | `reportData[16..64] == transcriptHash` check                      |
| Domain separation (anti-replay) | `reportData[0..16] == "openhttpa hs server"` prefix check         |
| Quote authenticity              | Off-chain TEE verification (DCAP / SNP) or ZK proof via RISC Zero |
| ZK proof authenticity           | `IRiscZeroVerifier.verify(receipt, OPENHTTPA_GUEST_ID)`           |

---

## Dependency Graph Position

```
openhttpa-contract (Solidity, not a Rust crate)
├── Foundry (forge, cast, anvil — build and test toolchain)
├── RISC Zero on-chain verifier (IRiscZeroVerifier — for zkReceipt verification)
└── (Consumed by) openhttpa-oracle (produces payloads for this contract)
```
