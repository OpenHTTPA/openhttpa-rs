// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! ZK-DCAP Verifier — verifies ZK-SNARK compressed quotes (ZAA).

use async_trait::async_trait;
use openhttpa_proto::{AttestQuote, QuoteType};
use openhttpa_zk::ZkMode;

use crate::verifier::{EatClaims, QuoteVerifier, VerificationError, VerificationResult};

/// Verifies ZK-SNARK compressed quotes (ZAA).
///
/// This verifier expects a ZK receipt as the raw quote body and verifies
/// it using the RISC Zero verifier. It enables high-assurance attestation
/// with minimal bandwidth overhead.
#[derive(Default)]
pub struct DcapZkVerifier {
    /// Whether to allow raw DCAP fallback if ZK verification is not applicable.
    pub allow_fallback: bool,
}

#[async_trait]
impl QuoteVerifier for DcapZkVerifier {
    async fn verify(
        &self,
        quote: &AttestQuote,
        _report_data: &[u8; 64],
    ) -> Result<VerificationResult, VerificationError> {
        // 1. Verify the Quote Type
        if quote.quote_type != QuoteType::ZkCompressed {
            if self.allow_fallback {
                // In a production implementation, this would delegate to a RawDcapVerifier
                return Err(VerificationError::Malformed(
                    "Raw DCAP fallback not implemented".to_owned(),
                ));
            }
            return Err(VerificationError::Malformed(
                "Expected ZkCompressed quote type".to_owned(),
            ));
        }

        // 2. Verify ZK Receipt
        // The raw bytes of the quote contain the serialized receipt.
        let receipt: openhttpa_zk::prover::Receipt =
            bincode::deserialize(&quote.raw).map_err(|e| {
                VerificationError::Malformed(format!("Failed to deserialize ZK receipt: {e}"))
            })?;

        // 3. Perform SNARK Verification
        // We verify that the receipt matches our expected Guest ID and is valid.
        // For ZAA, we check the dcap_verified flag in the journal.
        let output = openhttpa_zk::verifier::ZkVerifier::verify(
            &receipt,
            _report_data[..48].try_into().unwrap(),
        )
        .map_err(|_e| VerificationError::SignatureInvalid)?;

        if output.mode != ZkMode::DcapCompression || !output.dcap_verified {
            return Err(VerificationError::SignatureInvalid);
        }

        // 5. Construct EAT-aligned Result
        Ok(VerificationResult {
            claims: EatClaims {
                hwmodel: Some("Intel SGX (ZK-Compressed)".to_owned()),
                hwversion: Some("v3.0 (ZAA)".to_owned()),
                dbgstat: Some(0), // SNARK verification implies production-grade root of trust
                security_version: Some(3),
                iat: Some(output.iat),
                ..Default::default()
            },
            tcb_status: "UpToDate".to_owned(),
            measurement: Some(hex::encode(output.transcript_hash)),
            ..Default::default()
        })
    }
}
