// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! TPM 2.0 quote verifier.

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
        _report_data: &'a [u8; 64],
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

            // 2. Verify signature on the PCR quote using the AIK public key.
            //
            // SEC-04: AIK signature cryptographic verification is NOT yet
            // implemented.  The previous code silently skipped this step and
            // accepted any quote whose QUDD matched the report_data nonce,
            // effectively making the entire signature check a no-op.
            //
            // Failing closed here (returning an explicit error) is far safer
            // than silently accepting unverified quotes.  The AIK X.509 cert
            // is fetched above; when the real verification is implemented it
            // should:
            //   a) Parse the AIK cert (DER/PEM) and extract the public key.
            //   b) Verify the cert chain against a trusted TPM CA.
            //   c) Verify the TPM2B_ATTEST structure's signature over the
            //      quoted PCR digest using the AIK public key.
            //
            // TODO: Implement using `aws-lc-rs` or `p256`/`rsa` crates.
            Err(VerificationError::PolicyViolation(
                "TpmVerifier: AIK cryptographic signature verification is not yet \
                 implemented.  This verifier rejects all TPM 2.0 quotes until the \
                 implementation is complete.  Do not use TpmVerifier in production."
                    .to_owned(),
            ))
        })
    }
}
