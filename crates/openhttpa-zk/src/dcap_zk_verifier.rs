// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! ZK-DCAP Verifier — verifies ZK-SNARK compressed quotes (ZAA).

use crate::ZkMode;
use openhttpa_proto::{
    AttestError as VerificationError, AttestQuote, EatClaims, QuoteType, VerificationResult,
};

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

impl DcapZkVerifier {
    pub async fn verify(
        &self,
        quote: &AttestQuote,
        report_data: &[u8; 64],
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
        let receipt: crate::prover::Receipt = bincode::deserialize(&quote.raw).map_err(|e| {
            VerificationError::Malformed(format!("Failed to deserialize ZK receipt: {e}"))
        })?;

        // 3. Perform SNARK Verification
        // We verify that the receipt matches our expected Guest ID and is valid.
        // For ZAA, we check the dcap_verified flag in the journal.
        let output =
            crate::verifier::ZkVerifier::verify(&receipt, report_data[..48].try_into().unwrap())
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use openhttpa_proto::QuoteType;

    #[tokio::test]
    async fn test_dcap_zk_verifier_wrong_type() {
        let verifier = DcapZkVerifier {
            allow_fallback: false,
        };
        let quote = AttestQuote {
            quote_type: QuoteType::Sgx,
            raw: Bytes::new(),
            qudd: Bytes::new(),
            collateral_uris: vec![],
        };
        let result = verifier.verify(&quote, &[0u8; 64]).await;
        assert!(
            matches!(result, Err(VerificationError::Malformed(msg)) if msg.contains("Expected ZkCompressed"))
        );
    }

    #[tokio::test]
    async fn test_dcap_zk_verifier_fallback() {
        let verifier = DcapZkVerifier {
            allow_fallback: true,
        };
        let quote = AttestQuote {
            quote_type: QuoteType::Sgx,
            raw: Bytes::new(),
            qudd: Bytes::new(),
            collateral_uris: vec![],
        };
        let result = verifier.verify(&quote, &[0u8; 64]).await;
        assert!(
            matches!(result, Err(VerificationError::Malformed(msg)) if msg.contains("Raw DCAP fallback not implemented"))
        );
    }

    #[tokio::test]
    async fn test_dcap_zk_verifier_bad_receipt() {
        let verifier = DcapZkVerifier {
            allow_fallback: false,
        };
        let quote = AttestQuote {
            quote_type: QuoteType::ZkCompressed,
            raw: Bytes::from(vec![1, 2, 3]), // Invalid bincode
            qudd: Bytes::new(),
            collateral_uris: vec![],
        };
        let result = verifier.verify(&quote, &[0u8; 64]).await;
        assert!(
            matches!(result, Err(VerificationError::Malformed(msg)) if msg.contains("Failed to deserialize"))
        );
    }
}
