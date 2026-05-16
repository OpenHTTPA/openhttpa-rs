// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/OpenHttpaVerifier.sol";

contract OpenHttpaOracleVerifierTest is Test {
    OpenHttpaOracleVerifier public verifier;

    function setUp() public {
        verifier = new OpenHttpaOracleVerifier();
    }

    function test_VerifyValidPayload() public {
        bytes memory transcriptHash = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            transcriptHash[i] = bytes1(uint8(i));
        }

        bytes memory reportData = new bytes(64);
        bytes memory prefix = bytes("openhttpa hs server");
        for (uint256 i = 0; i < 16; i++) {
            reportData[i] = prefix[i];
        }

        for (uint256 i = 0; i < 48; i++) {
            reportData[16 + i] = transcriptHash[i];
        }

        OpenHttpaOracleVerifier.OraclePayload memory payload = OpenHttpaOracleVerifier.OraclePayload({
            transcriptHash: transcriptHash,
            quote: bytes("dummy_quote"),
            reportData: reportData,
            data: bytes("price: 100000"),
            zkReceipt: bytes("")
        });

        bool result = verifier.verifyOraclePayload(payload);
        assertTrue(result);
    }

    function test_RevertInvalidPrefix() public {
        bytes memory transcriptHash = new bytes(48);
        bytes memory reportData = new bytes(64);

        // Use an invalid prefix
        bytes memory prefix = bytes("invalid_prefix!!");
        for (uint256 i = 0; i < 16; i++) {
            reportData[i] = prefix[i];
        }

        for (uint256 i = 0; i < 48; i++) {
            reportData[16 + i] = transcriptHash[i];
        }

        OpenHttpaOracleVerifier.OraclePayload memory payload = OpenHttpaOracleVerifier.OraclePayload({
            transcriptHash: transcriptHash,
            quote: bytes("dummy_quote"),
            reportData: reportData,
            data: bytes("price: 100000"),
            zkReceipt: bytes("")
        });

        vm.expectRevert("Invalid domain separation prefix");
        verifier.verifyOraclePayload(payload);
    }

    function test_RevertInvalidTranscriptHashBinding() public {
        bytes memory transcriptHash = new bytes(48);
        bytes memory differentHash = new bytes(48);
        differentHash[0] = 0x01;

        bytes memory reportData = new bytes(64);
        bytes memory prefix = bytes("openhttpa hs server");
        for (uint256 i = 0; i < 16; i++) {
            reportData[i] = prefix[i];
        }

        // Bind to differentHash instead of transcriptHash
        for (uint256 i = 0; i < 48; i++) {
            reportData[16 + i] = differentHash[i];
        }

        OpenHttpaOracleVerifier.OraclePayload memory payload = OpenHttpaOracleVerifier.OraclePayload({
            transcriptHash: transcriptHash,
            quote: bytes("dummy_quote"),
            reportData: reportData,
            data: bytes("price: 100000"),
            zkReceipt: bytes("")
        });

        vm.expectRevert("Transcript hash mismatch in reportData");
        verifier.verifyOraclePayload(payload);
    }
}
