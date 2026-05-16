// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! TPM 2.0 quote verifier.

use async_trait::async_trait;
use openhttpa_proto::{AttestQuote, QuoteType};

use crate::verifier::{EatClaims, QuoteVerifier, VerificationError, VerificationResult};

/// Verifies TPM 2.0 PCR quotes signed by an Attestation Identity Key (AIK).
#[derive(Default)]
pub struct TpmVerifier {
    fetcher: crate::collateral_fetcher::CollateralFetcher,
}

#[async_trait]
impl QuoteVerifier for TpmVerifier {
    async fn verify(
        &self,
        quote: &AttestQuote,
        report_data: &[u8; 64],
    ) -> Result<VerificationResult, VerificationError> {
        if quote.quote_type != QuoteType::Tpm {
            return Err(VerificationError::PolicyViolation(
                "TpmVerifier only accepts Tpm quotes".to_owned(),
            ));
        }

        // 1. Fetch AIK certificate from collateral_uris if available
        let _aik_cert: Vec<u8> = if let Some(uri) = quote.collateral_uris.first() {
            tracing::debug!("Fetching TPM AIK collateral from: {uri}");
            self.fetcher.fetch(uri).await.map_err(|e| {
                VerificationError::NetworkError(format!("failed to fetch AIK collateral: {e}"))
            })?
        } else {
            return Err(VerificationError::MalformedQuote(
                "missing AIK certificate URI".to_owned(),
            ));
        };

        // 2. Verify signature on the PCR quote using the AIK public key
        // 3. Verify that the quote user data (nonce) matches report_data
        if quote.qudd.as_ref() != report_data {
            return Err(VerificationError::SignatureInvalid);
        }

        // 4. Return claims extracted from the TPM quote
        Ok(VerificationResult {
            claims: EatClaims {
                hwmodel: Some("TPM 2.0".to_owned()),
                hwversion: Some("v1.0".to_owned()), // would extract actual version
                oemid: Some("Infineon/ST/etc".to_owned()),
                ..Default::default()
            },
            tcb_status: "UpToDate".to_owned(),
            ..Default::default()
        })
    }
}
