// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! The [`QuoteVerifier`] trait and result types.

pub use openhttpa_proto::{AttestQuote, EatClaims, QuoteType, VerificationResult};

pub use openhttpa_proto::AttestError as VerificationError;

/// Pluggable provider for revocation status.
pub trait RevocationProvider: Send + Sync + std::fmt::Debug {
    /// Check if a specific TEE platform or enclave has been revoked.
    ///
    /// # Errors
    /// Returns [`Err`] with `VerificationError::Revoked` if the identity is revoked.
    fn check_revocation<'a>(
        &'a self,
        result: &'a VerificationResult,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), VerificationError>> + Send + 'a>,
    >;
}

/// A policy for deciding whether to accept a [`VerificationResult`].
pub trait PolicyEngine: Send + Sync + std::fmt::Debug {
    /// Evaluate the verification result against the policy.
    fn evaluate<'a>(
        &'a self,
        result: &'a VerificationResult,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), VerificationError>> + Send + 'a>,
    >;
}

/// An async pluggable quote verifier.
pub trait QuoteVerifier: Send + Sync {
    /// Verify a single `quote` and return the verification result.
    ///
    /// # Arguments
    /// * `quote` - The raw attestation quote.
    /// * `report_data` - The 64-byte data buffer expected to be embedded in the quote.
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
    >;

    /// Verify multiple quotes (a composite bundle).
    ///
    /// # Arguments
    /// * `quotes` - A list of quotes to verify.
    /// * `report_data` - The 64-byte data buffer expected to be embedded in all quotes.
    ///
    /// The default implementation verifies each quote individually and returns
    /// a failure if any single verification fails (Fail-fast).
    fn verify_bundle<'a>(
        &'a self,
        quotes: &'a [AttestQuote],
        report_data: &'a [u8; 64],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<VerificationResult, VerificationError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if quotes.is_empty() {
                return Err(VerificationError::MalformedQuote(
                    "empty quote bundle".to_owned(),
                ));
            }

            let mut primary_res = self.verify(&quotes[0], report_data).await?;

            for quote in &quotes[1..] {
                let secondary_res = self.verify(quote, report_data).await?;
                primary_res.secondary.push(secondary_res);
            }

            Ok(primary_res)
        })
    }

    /// Verify multiple quotes independently and concurrently.
    ///
    /// The default implementation uses futures to verify all quotes concurrently.
    /// Any failure is returned immediately.
    ///
    /// # Errors
    /// Returns [`Err`] if any verification fails or if input lengths do not match.
    fn verify_batch<'a>(
        &'a self,
        quotes: &'a [AttestQuote],
        report_data: &'a [[u8; 64]],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Vec<VerificationResult>, VerificationError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if quotes.len() != report_data.len() {
                return Err(VerificationError::MalformedQuote(
                "quotes and report_data slices must have the same length for batch verification"
                    .to_owned(),
            ));
            }

            let mut futures = Vec::with_capacity(quotes.len());
            for (quote, rd) in quotes.iter().zip(report_data.iter()) {
                futures.push(self.verify(quote, rd));
            }

            futures::future::try_join_all(futures).await
        })
    }
}

/// A basic in-memory revocation provider.
///
/// # Warning
///
/// M-01: This provider is **test-only**. It stores revocations in an in-process
/// `DashSet` that does not persist across restarts, is not loaded from a CRL or
/// OCSP endpoint, and is not shared across server replicas. Use
/// `ItaVerifier` or a production-grade
/// CRL-backed implementation in any deployed environment.
#[deprecated(
    note = "M-01: test-only — does not persist or load revocations from a CRL/OCSP \
            endpoint. Use a production-grade RevocationProvider in deployments."
)]
#[derive(Debug, Default)]
pub struct SimpleRevocationProvider {
    /// Set of revoked identity strings (e.g. MRENCLAVE or specific claims).
    pub revoked_identities: dashmap::DashSet<String>,
}

#[allow(deprecated)] // M-01: internal impl of the deprecated test-only type
impl RevocationProvider for SimpleRevocationProvider {
    /// Check revocation against all available identity fields.
    ///
    /// SEC-06: Checks `boot_progress`, `measurement`, and `signer_id` to
    /// prevent a revoked enclave from bypassing the check by omitting
    /// `boot_progress` while supplying the same identity via another field.
    fn check_revocation<'a>(
        &'a self,
        result: &'a VerificationResult,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), VerificationError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let candidates: [Option<&String>; 3] = [
                result.claims.boot_progress.as_ref(),
                result.measurement.as_ref(),
                result.signer_id.as_ref(),
            ];
            for identity in candidates.into_iter().flatten() {
                if self.revoked_identities.contains(identity) {
                    return Err(VerificationError::Revoked(format!(
                        "identity '{identity}' is on the revocation list"
                    )));
                }
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(debug: bool) -> VerificationResult {
        VerificationResult {
            claims: EatClaims {
                hwmodel: Some("mock".to_owned()),
                hwversion: Some("ok".to_owned()),
                dbgstat: Some(u8::from(debug)),
                ..Default::default()
            },
            tcb_status: "UpToDate".to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn verification_result_rejection() {
        let res = VerificationResult {
            claims: EatClaims {
                hwmodel: Some("sgx".to_owned()),
                hwversion: Some("up-to-date".to_owned()),
                boot_progress: Some("f1a7e2b8d9c0".to_owned()),
                dbgstat: Some(0),
                ..Default::default()
            },
            tcb_status: "UpToDate".to_owned(),
            measurement: Some("f1a7e2b8d9c0".to_owned()),
            signer_id: Some("e0f2a1b3c4d5".to_owned()),
            ..Default::default()
        };
        assert!(res.reject_debug_builds(false).is_ok());
    }

    #[test]
    fn production_rejects_debug_build() {
        let r = result(true);
        assert!(r.reject_debug_builds(false).is_err());
    }

    #[test]
    fn production_accepts_non_debug_build() {
        let r = result(false);
        assert!(r.reject_debug_builds(false).is_ok());
    }

    #[test]
    fn allow_debug_flag_accepts_debug_build() {
        let r = result(true);
        assert!(r.reject_debug_builds(true).is_ok());
    }

    #[tokio::test]
    #[allow(deprecated)] // M-01: internal test exercises the deprecated test-only provider
    async fn revocation_provider_rejects_listed_identity() {
        let provider = SimpleRevocationProvider::default();
        let identity = "revoked-enclave-id".to_string();
        provider.revoked_identities.insert(identity.clone());

        let res = VerificationResult {
            claims: EatClaims {
                boot_progress: Some(identity),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(provider.check_revocation(&res).await.is_err());
    }

    #[tokio::test]
    #[allow(deprecated)] // M-01: internal test exercises the deprecated test-only provider
    async fn revocation_provider_accepts_non_listed_identity() {
        let provider = SimpleRevocationProvider::default();
        provider.revoked_identities.insert("revoked-id".to_string());

        let res = VerificationResult {
            claims: EatClaims {
                boot_progress: Some("valid-id".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(provider.check_revocation(&res).await.is_ok());
    }

    #[tokio::test]
    async fn policy_engine_rejects_low_svn() {
        let policy = crate::policy::SimplePolicy {
            min_security_version: Some(10),
            ..Default::default()
        };

        let res = VerificationResult {
            claims: EatClaims {
                security_version: Some(5),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(policy.evaluate(&res).await.is_err());
    }

    #[tokio::test]
    async fn policy_engine_accepts_high_svn() {
        let policy = crate::policy::SimplePolicy {
            min_security_version: Some(10),
            ..Default::default()
        };

        let res = VerificationResult {
            claims: EatClaims {
                security_version: Some(15),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(policy.evaluate(&res).await.is_ok());
    }

    #[tokio::test]
    async fn test_verify_batch() {
        struct DummyVerifier;
        impl QuoteVerifier for DummyVerifier {
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
                    if quote.raw.as_ref() == b"fail" {
                        return Err(VerificationError::SignatureInvalid);
                    }
                    Ok(VerificationResult {
                        tcb_status: format!("verified-{}", report_data[0]),
                        ..Default::default()
                    })
                })
            }
        }

        let verifier = DummyVerifier;
        let quotes = vec![
            AttestQuote {
                quote_type: QuoteType::Mock,
                format: openhttpa_proto::QuoteFormat::default(),
                raw: bytes::Bytes::from_static(b"ok1"),
                qudd: bytes::Bytes::new(),
                collateral_uris: vec![],
            },
            AttestQuote {
                quote_type: QuoteType::Mock,
                format: openhttpa_proto::QuoteFormat::default(),
                raw: bytes::Bytes::from_static(b"ok2"),
                qudd: bytes::Bytes::new(),
                collateral_uris: vec![],
            },
        ];
        let mut rd1 = [0u8; 64];
        rd1[0] = 10;
        let mut rd2 = [0u8; 64];
        rd2[0] = 20;
        let report_data = vec![rd1, rd2];

        let results = verifier.verify_batch(&quotes, &report_data).await.unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].tcb_status, "verified-10");
        assert_eq!(results[1].tcb_status, "verified-20");

        // Test length mismatch
        let bad_report_data = vec![rd1];
        let result = verifier.verify_batch(&quotes, &bad_report_data).await;
        assert!(result.is_err());

        // Test individual failure
        let failed_quotes = vec![AttestQuote {
            quote_type: QuoteType::Mock,
            format: openhttpa_proto::QuoteFormat::default(),
            raw: bytes::Bytes::from_static(b"fail"),
            qudd: bytes::Bytes::new(),
            collateral_uris: vec![],
        }];
        let result = verifier.verify_batch(&failed_quotes, &[rd1]).await;
        assert!(result.is_err());
    }
}
