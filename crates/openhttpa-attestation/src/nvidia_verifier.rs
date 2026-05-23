// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! NVIDIA GPU quote verifier.

use async_trait::async_trait;
use openhttpa_proto::{AttestQuote, QuoteType};

use crate::verifier::{EatClaims, QuoteVerifier, VerificationError, VerificationResult};

/// Verifier for NVIDIA Hopper GPU attestation quotes.
#[derive(Debug, Default)]
pub struct NvidiaGpuVerifier;

#[async_trait]
impl QuoteVerifier for NvidiaGpuVerifier {
    async fn verify(
        &self,
        quote: &AttestQuote,
        report_data: &[u8; 64],
    ) -> Result<VerificationResult, VerificationError> {
        if quote.quote_type != QuoteType::NvidiaGpu {
            return Err(VerificationError::MalformedQuote(
                "not an nvidia_gpu quote".to_owned(),
            ));
        }

        // Verify that report_data matches the QUDD in the quote
        if quote.qudd.as_ref() != report_data {
            return Err(VerificationError::PolicyViolation(
                "QUDD mismatch".to_owned(),
            ));
        }

        // In a real implementation:
        // 1. Parse the NVIDIA Rim report.
        // 2. Validate the certificate chain against NVIDIA Root CA.
        // 3. Verify the signature of the report.
        // 4. Check measurements (VBIOS, etc.) against reference values.

        // For the simulation:
        if quote
            .raw
            .starts_with(b"NVIDIA-HOPPER-ATTESTATION-REPORT-SIM")
        {
            return Ok(VerificationResult {
                claims: EatClaims {
                    hwmodel: Some("NVIDIA H100".to_owned()),
                    hwversion: Some("hopper_v1".to_owned()),
                    oemid: Some("NVIDIA".to_owned()),
                    dbgstat: Some(0),
                    boot_progress: Some("simulated_gpu_measurement".to_owned()),
                    ..Default::default()
                },
                tcb_status: "UpToDate".to_owned(),
                measurement: Some("simulated_gpu_measurement".to_owned()),
                signer_id: Some("nvidia_prod_signer".to_owned()),
                ..Default::default()
            });
        }

        Err(VerificationError::SignatureInvalid)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_verify_simulated_gpu_report() {
        let verifier = NvidiaGpuVerifier;
        let report_data = [0xAAu8; 64];
        let quote = AttestQuote {
            quote_type: QuoteType::NvidiaGpu,
            raw: b"NVIDIA-HOPPER-ATTESTATION-REPORT-SIM-001".to_vec().into(),
            qudd: report_data.to_vec().into(),
            collateral_uris: vec![],
        };

        let result = verifier.verify(&quote, &report_data).await.unwrap();
        assert_eq!(result.claims.hwmodel.unwrap(), "NVIDIA H100");
        assert_eq!(result.tcb_status, "UpToDate");
        assert_eq!(result.measurement.unwrap(), "simulated_gpu_measurement");
    }

    #[tokio::test]
    async fn test_verify_fails_on_qudd_mismatch() {
        let verifier = NvidiaGpuVerifier;
        let report_data = [0xAAu8; 64];
        let quote = AttestQuote {
            quote_type: QuoteType::NvidiaGpu,
            raw: b"NVIDIA-HOPPER-ATTESTATION-REPORT-SIM-001".to_vec().into(),
            qudd: vec![0u8; 64].into(), // Different QUDD
            collateral_uris: vec![],
        };

        let result = verifier.verify(&quote, &report_data).await;
        assert!(matches!(result, Err(VerificationError::PolicyViolation(_))));
    }

    #[tokio::test]
    async fn test_verify_fails_on_wrong_quote_type() {
        let verifier = NvidiaGpuVerifier;
        let report_data = [0xAAu8; 64];
        let quote = AttestQuote {
            quote_type: QuoteType::Mock, // Wrong type
            raw: b"NVIDIA-HOPPER-ATTESTATION-REPORT-SIM-001".to_vec().into(),
            qudd: report_data.to_vec().into(),
            collateral_uris: vec![],
        };

        let result = verifier.verify(&quote, &report_data).await;
        assert!(matches!(result, Err(VerificationError::MalformedQuote(_))));
    }
}
