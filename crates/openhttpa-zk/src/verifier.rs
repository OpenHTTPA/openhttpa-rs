// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

#[cfg(feature = "zk")]
use crate::OPENHTTPA_GUEST_ID;
use crate::{ZkError, ZkOutput, prover::Receipt};

pub struct ZkVerifier;

impl ZkVerifier {
    /// Succinctly verify a ZK receipt.
    ///
    /// # Errors
    /// Returns [`ZkError`] if the receipt is invalid or the journal data is malformed.
    pub fn verify(receipt: &Receipt, expected_transcript: &[u8; 48]) -> Result<ZkOutput, ZkError> {
        // 1. Cryptographic verification of the proof against the circuit ID.
        #[cfg(feature = "zk")]
        {
            receipt
                .verify(OPENHTTPA_GUEST_ID)
                .map_err(|e| ZkError::Verification(e.to_string()))?;
        }

        // 2. Extract and verify the journaled statement.
        let output = crate::prover::ZkProver::extract_output(receipt)?;

        if !output.is_valid {
            return Err(ZkError::Verification(
                "guest program reported invalid attestation".to_owned(),
            ));
        }

        if &output.transcript_hash != expected_transcript {
            return Err(ZkError::Verification(
                "transcript hash mismatch in ZK proof".to_owned(),
            ));
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ZkInput, ZkMode, prover::ZkProver};

    fn prove_oracle(transcript: [u8; 48]) -> Receipt {
        let input = ZkInput {
            mode: ZkMode::Oracle,
            transcript_hash: transcript,
            quote_bytes: vec![0x01],
            report_data: [0u8; 64],
            oracle_data: Some(b"data".to_vec()),
            vai_data: None,
            dcap_collateral: None,
        };
        ZkProver::prove(&input).expect("prove should succeed in non-zk mode")
    }

    #[test]
    fn verify_succeeds_with_matching_transcript() {
        let transcript = [0xdeu8; 48];
        let receipt = prove_oracle(transcript);
        let output = ZkVerifier::verify(&receipt, &transcript)
            .expect("verify should succeed with matching transcript");
        assert!(output.is_valid);
        assert_eq!(output.transcript_hash, transcript);
    }

    #[test]
    fn verify_fails_on_transcript_mismatch() {
        let proof_transcript = [0x01u8; 48];
        let check_transcript = [0x02u8; 48]; // Different!
        let receipt = prove_oracle(proof_transcript);
        let result = ZkVerifier::verify(&receipt, &check_transcript);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("transcript hash mismatch"),
            "Expected transcript hash mismatch error"
        );
    }

    #[cfg(not(feature = "zk"))]
    #[test]
    fn verify_fails_on_corrupted_journal() {
        // Create a receipt with garbage journal bytes
        let bad_receipt = Receipt {
            journal: crate::prover::Journal {
                bytes: vec![0xff, 0xfe, 0xfd],
            },
        };
        let transcript = [0u8; 48];
        let result = ZkVerifier::verify(&bad_receipt, &transcript);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), crate::ZkError::Serialization(_)),
            "Corrupted journal should yield a Serialization error"
        );
    }

    #[cfg(not(feature = "zk"))]
    #[test]
    fn verify_fails_safely_on_parsing_bomb() {
        // Create a massive garbage journal to ensure postcard or memory doesn't panic
        let bad_receipt = Receipt {
            journal: crate::prover::Journal {
                // Large enough to test limits but small enough to not actually OOM
                bytes: vec![0xff; 10 * 1024 * 1024], // 10MB
            },
        };
        let transcript = [0u8; 48];
        let result = ZkVerifier::verify(&bad_receipt, &transcript);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), crate::ZkError::Serialization(_)),
            "Massive garbage journal should cleanly fail serialization without panic"
        );
    }
}
