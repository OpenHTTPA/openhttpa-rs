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
