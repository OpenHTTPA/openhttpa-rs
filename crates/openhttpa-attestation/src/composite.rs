// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! Composite verifier for heterogeneous TEE environments.

use async_trait::async_trait;
use std::collections::HashMap;

use crate::verifier::{QuoteVerifier, VerificationError, VerificationResult};
use openhttpa_proto::{AttestQuote, QuoteType};

/// A verifier that delegates to multiple sub-verifiers based on [`QuoteType`].
///
/// This is essential for verifying composite attestations (e.g., host TEE + GPU).
#[derive(Default)]
pub struct CompositeVerifier {
    verifiers: HashMap<String, Box<dyn QuoteVerifier>>,
    /// If true, requires all quotes in a bundle to pass verification.
    pub strict_mode: bool,
}

impl CompositeVerifier {
    /// Create a new empty composite verifier.
    #[must_use]
    pub fn new() -> Self {
        Self {
            verifiers: HashMap::new(),
            strict_mode: true,
        }
    }

    /// Register a verifier for a specific quote type.
    pub fn add_verifier(&mut self, quote_type: &QuoteType, verifier: Box<dyn QuoteVerifier>) {
        self.verifiers.insert(quote_type.to_string(), verifier);
    }
}

#[async_trait]
impl QuoteVerifier for CompositeVerifier {
    async fn verify(
        &self,
        quote: &AttestQuote,
        report_data: &[u8; 64],
    ) -> Result<VerificationResult, VerificationError> {
        let type_key = quote.quote_type.to_string();

        let verifier = self.verifiers.get(&type_key).ok_or_else(|| {
            VerificationError::PolicyViolation(format!(
                "no verifier registered for quote type: {type_key}"
            ))
        })?;

        verifier.verify(quote, report_data).await
    }

    /// Optimized bundle verification for composite environments.
    async fn verify_bundle(
        &self,
        quotes: &[AttestQuote],
        report_data: &[u8; 64],
    ) -> Result<VerificationResult, VerificationError> {
        if quotes.is_empty() {
            return Err(VerificationError::Malformed(
                "empty quote bundle".to_owned(),
            ));
        }

        let mut results = Vec::with_capacity(quotes.len());

        for quote in quotes {
            let res = self.verify(quote, report_data).await?;
            results.push(res);
        }

        // Aggregate results:
        // The first result is treated as the 'primary' (host TEE).
        // Secondary results (GPU, TPM) are nested.
        let mut primary = results.remove(0);
        primary.secondary = results;

        Ok(primary)
    }
}
