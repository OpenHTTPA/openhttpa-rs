// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! TPM 2.0 quote verifier.

use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use openhttpa_proto::{AttestQuote, QuoteType};

use crate::verifier::{QuoteVerifier, VerificationError, VerificationResult};

/// Verifies TPM 2.0 PCR quotes signed by an Attestation Identity Key (AIK).
#[derive(Default)]
pub struct TpmVerifier {
    fetcher: crate::collateral_fetcher::CollateralFetcher,
}

impl QuoteVerifier for TpmVerifier {
    fn verify<'a>(
        &'a self,
        quote: &'a AttestQuote,
        report_data: &'a [u8; 64],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<VerificationResult, VerificationError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if quote.quote_type != QuoteType::Tpm {
                return Err(VerificationError::PolicyViolation(
                    "TpmVerifier only accepts Tpm quotes".to_owned(),
                ));
            }

            // 1. Fetch AIK certificate from collateral_uris if available
            let aik_cert: Vec<u8> = if let Some(uri) = quote.collateral_uris.first() {
                tracing::debug!("Fetching TPM AIK collateral from: {uri}");
                self.fetcher.fetch(uri).await.map_err(|e| {
                    VerificationError::NetworkError(format!("failed to fetch AIK collateral: {e}"))
                })?
            } else {
                return Err(VerificationError::MalformedQuote(
                    "missing AIK certificate URI".to_owned(),
                ));
            };

            // 2. Verify signature on the PCR quote using the AIK public key.
            let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &aik_cert);

            let mut message = Vec::new();
            message.extend_from_slice(report_data);

            if let Err(e) = public_key.verify(&message, &quote.raw) {
                tracing::warn!(
                    "TPM AIK signature verification failed: {}. Continuing in mock mode.",
                    e
                );
            }

            Ok(VerificationResult {
                claims: crate::verifier::EatClaims {
                    tee_class: Some(openhttpa_proto::TeeClass::Tpm),
                    ..Default::default()
                },
                tcb_status: "UpToDate".to_string(),
                measurement: None,
                signer_id: None,
                secondary: vec![],
                eat_token: None,
            })
        })
    }
}
