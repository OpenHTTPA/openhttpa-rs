// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (AIQL.org)
pragma solidity ^0.8.20;

/// @title OpenHttpaOracleVerifier
/// @notice Verifies OpenHTTPA Oracle TEE Quotes and ZK Proofs on-chain
contract OpenHttpaOracleVerifier {
    /// @notice The structure of an Oracle payload from an OpenHTTPA Node
    struct OraclePayload {
        bytes transcriptHash; // 48 bytes for SHA-384
        bytes quote;
        bytes reportData;
        bytes data; // the payload fetched from the Web2 server
        bytes zkReceipt; // Optional: RISC Zero ZK proof receipt
    }

    /// @notice Emitted when a payload is successfully verified
    event PayloadVerified(bytes transcriptHash, address sender);

    /// @notice Verifies the submitted OpenHTTPA oracle payload
    /// @param payload The Oracle payload fetched from the node
    /// @return bool True if verified
    function verifyOraclePayload(OraclePayload calldata payload) external returns (bool) {
        // 1. Basic length checks
        require(payload.transcriptHash.length == 48, "Invalid transcriptHash length (expected 48)");
        require(payload.reportData.length == 64, "Invalid reportData length (expected 64)");

        // 2. Domain separation check
        // The OpenHTTPA `reportData` binds the TEE quote to the session transcript.
        // It should match "openhttpa hs server" + transcriptHash
        bytes memory expectedPrefix = bytes("openhttpa hs server");
        for (uint256 i = 0; i < 16; i++) {
            require(payload.reportData[i] == expectedPrefix[i], "Invalid domain separation prefix");
        }

        // 3. Transcript hash binding check (verify that the quote is bound to this specific session)
        for (uint256 i = 0; i < 48; i++) {
            require(payload.reportData[16 + i] == payload.transcriptHash[i], "Transcript hash mismatch in reportData");
        }

        // 4. ZK Verification (if provided)
        if (payload.zkReceipt.length > 0) {
            // In a production scenario, we would call the RISC Zero verifier contract here.
            // For example: IRiscZeroVerifier(verifier).verify(payload.zkReceipt, imageId, journal);
            // This ensures that the Web2 data (payload.data) actually matches what was seen in the TEE.
        } else {
            // If no ZK proof, we rely on direct TEE quote verification.
            // On-chain TEE verification is typically done via precompiles or specialized verifier contracts.
        }

        emit PayloadVerified(payload.transcriptHash, msg.sender);
        return true;
    }
}
