// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Mock TEE provider for testing and autonomous verification.
//!
//! This module provides a highly configurable Mock TEE that can simulate multiple
//! hardware types (TDX, SEV-SNP, TPM, NVIDIA GPU) and various failure modes.
//! It is designed for use in CI/CD pipelines where real TEE hardware is unavailable.
//!
//! # Security Warning
//! The Mock provider produces deterministic pseudo-quotes that are NOT cryptographically
//! secure. It MUST NOT be used in production environments.

use bytes::Bytes;
use hkdf::Hkdf;
use sha2::{Digest, Sha384};

use openhttpa_proto::{AttestQuote, QuoteType};

use crate::evidence::AttestationEvidence;
use crate::provider::{QuoteRequest, TeeAdapter, TeeProvider, TeeProviderError};

/// A highly configurable Mock TEE provider for autonomous testing.
///
/// Behaves as a TDX, SEV-SNP, TPM, or GPU based on the `OPENHTTPA_MOCK_TEE_TYPE`
/// environment variable. Can simulate failures via `OPENHTTPA_MOCK_FAILURE`.
/// A highly configurable Mock TEE provider for autonomous testing.
///
/// On construction, validates that the `OPENHTTPA_MOCK_TEE_TYPE` environment
/// variable (if set) does not resolve to a real hardware type — fail-fast at
/// startup rather than discovering the misconfiguration at the first
/// `quote_type()` call.  See SEC-09.
#[derive(Debug)]
pub struct MockTeeProvider {
    /// M-02: Private field — use [`MockTeeProvider::with_override`] to set.
    ///
    /// The field MUST be private to prevent callers from bypassing the
    /// real-hardware guard (SEC-09) introduced in `Default::default()`.
    override_type: Option<QuoteType>,
}

impl Default for MockTeeProvider {
    /// Creates a `MockTeeProvider` with no type override.
    ///
    /// # Panics
    /// Panics in non-test builds if `OPENHTTPA_MOCK_TEE_TYPE` resolves to a real
    /// hardware type, preventing silent production misuse (SEC-09).
    fn default() -> Self {
        let provider = Self {
            override_type: None,
        };
        // Eagerly run the same real-hardware guard that quote_type() would run,
        // so misconfiguration is detected at construction time, not later.
        // SEC-09: Allow hardware impersonation in tests and debug builds.
        #[cfg(all(not(test), not(debug_assertions)))]
        {
            let type_str =
                std::env::var("OPENHTTPA_MOCK_TEE_TYPE").unwrap_or_else(|_| "mock".to_owned());
            let resolved: QuoteType = type_str.parse().unwrap_or(QuoteType::Mock);
            let allow_mock_hw = Self::is_mock_allowed();

            assert!(
                !is_real_hardware_type(&resolved) || allow_mock_hw,
                "SEC-09: MockTeeProvider constructed with OPENHTTPA_MOCK_TEE_TYPE={type_str:?} \
                 which resolves to real hardware {resolved:?}. \
                 Set OPENHTTPA_MOCK_TEE_TYPE=mock, enable OPENHTTPA_ALLOW_MOCK_HARDWARE=1, \
                 or disable the 'mock' feature in production."
            );
        }
        provider
    }
}

impl MockTeeProvider {
    /// Create a `MockTeeProvider` with an explicit TEE-type override.
    ///
    /// Applies the same real-hardware guard as `Default::default()` so
    /// callers cannot bypass SEC-09 by passing a hardware type.
    ///
    /// # Panics
    /// Panics in non-test builds if `qt` resolves to real hardware.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // non-const: assert! uses format arg in non-test builds
    pub fn with_override(qt: QuoteType) -> Self {
        // SEC-09: Allow hardware impersonation in tests and debug builds.
        #[cfg(all(not(test), not(debug_assertions)))]
        {
            let allow_mock_hw = Self::is_mock_allowed();
            assert!(
                !is_real_hardware_type(&qt) || allow_mock_hw,
                "SEC-09: MockTeeProvider::with_override called with real hardware type {qt:?}. \
                 Only QuoteType::Mock is permitted outside test builds unless OPENHTTPA_ALLOW_MOCK_HARDWARE=1 is set."
            );
        }
        Self {
            override_type: Some(qt),
        }
    }

    /// Internal helper to check if mock hardware impersonation is allowed.
    ///
    /// SEC-09: Checks for `OPENHTTPA_ALLOW_MOCK_HARDWARE=1` (standard)
    /// or `OpenHTTPA_ALLOW_MOCK_HARDWARE=1` (mixed case fallback).
    #[cfg(all(not(test), not(debug_assertions)))]
    fn is_mock_allowed() -> bool {
        std::env::var("OPENHTTPA_ALLOW_MOCK_HARDWARE").is_ok_and(|v| v == "1")
            || std::env::var("OpenHTTPA_ALLOW_MOCK_HARDWARE").is_ok_and(|v| v == "1")
    }

    /// Internal helper to check for simulated failure modes.
    ///
    /// If `OPENHTTPA_MOCK_FAILURE` is set to a known error type, this method
    /// returns the corresponding [`TeeProviderError`].
    ///
    /// # Errors
    /// Returns a simulated error if requested via environment variables.
    fn simulate_failure() -> Result<(), TeeProviderError> {
        if let Ok(fail_type) = std::env::var("OPENHTTPA_MOCK_FAILURE") {
            match fail_type.as_str() {
                "driver" => {
                    return Err(TeeProviderError::Driver(
                        "Simulated driver failure".to_owned(),
                    ));
                }
                "enclave" => {
                    return Err(TeeProviderError::Enclave(
                        "Simulated enclave crash".to_owned(),
                    ));
                }
                "config" => {
                    return Err(TeeProviderError::Config(
                        "Simulated platform misconfiguration".to_owned(),
                    ));
                }
                "not_available" => {
                    return Err(TeeProviderError::NotAvailable(
                        "Simulated hardware missing".to_owned(),
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Returns `true` if the given [`QuoteType`] represents real TEE hardware
/// (i.e., NOT `QuoteType::Mock` or `QuoteType::Unknown`).
///
/// Used as a safety guard to detect when a `MockTeeProvider` is configured
/// to impersonate genuine hardware — a condition that is never valid outside
/// of a controlled test environment.
pub(crate) const fn is_real_hardware_type(qt: &QuoteType) -> bool {
    matches!(
        qt,
        QuoteType::Tdx
            | QuoteType::SevSnp
            | QuoteType::Sgx
            | QuoteType::Tpm
            | QuoteType::NvidiaGpu
            | QuoteType::TrustZone
    )
}

impl TeeAdapter for MockTeeProvider {
    /// Returns the mocked TEE type based on `OPENHTTPA_MOCK_TEE_TYPE`.
    /// Defaults to `QuoteType::Mock`.
    ///
    /// # Security Invariant (SA-07)
    ///
    /// If the resolved type is a real hardware TEE (TDX, SEV-SNP, etc.), this
    /// function:
    /// 1. Emits a `tracing::error!` tagged `security = true` in all builds.
    /// 2. **Panics** in non-test builds to prevent silent production misuse.
    ///
    /// In test builds, returning a real hardware type via `OPENHTTPA_MOCK_TEE_TYPE`
    /// is intentional (it drives hardware-specific code paths in CI).
    fn quote_type(&self) -> QuoteType {
        if let Some(t) = self.override_type.clone() {
            return t;
        }
        let type_str =
            std::env::var("OPENHTTPA_MOCK_TEE_TYPE").unwrap_or_else(|_| "mock".to_owned());
        let resolved: QuoteType = type_str.parse().unwrap_or(QuoteType::Mock);

        if is_real_hardware_type(&resolved) {
            // Always log at ERROR level with a security tag so log aggregators
            // can alert on this condition regardless of build type.
            tracing::error!(
                security = true,
                resolved_type = ?resolved,
                env_value = %type_str,
                "SECURITY: MockTeeProvider is impersonating a real TEE hardware type. \
                 This is ONLY valid in test/CI environments. \
                 Set OPENHTTPA_MOCK_TEE_TYPE=mock or disable the 'mock' feature in production."
            );

            // In non-test builds, escalate to a panic unless explicitly allowed
            // via OPENHTTPA_ALLOW_MOCK_HARDWARE=1.
            // SEC-09: Allow hardware impersonation in tests and debug builds.
            #[cfg(all(not(test), not(debug_assertions)))]
            {
                let allow_mock_hw = Self::is_mock_allowed();
                assert!(
                    allow_mock_hw,
                    "MockTeeProvider MUST NOT impersonate hardware type {resolved:?} in non-test code \
                     unless OPENHTTPA_ALLOW_MOCK_HARDWARE=1 is set. \
                     Set OPENHTTPA_MOCK_TEE_TYPE=mock or disable the 'mock' feature in production builds."
                );
            }
        }

        resolved
    }

    /// Generates structured attestation evidence based on the current mock type.
    ///
    /// Supports simulation of TDX, SEV-SNP, TPM, and NVIDIA GPU evidence bundles.
    /// Inlines mock URIs for attestation collateral to test URI-based flows.
    ///
    /// # Errors
    /// Returns a simulated error if `OPENHTTPA_MOCK_FAILURE` is set.
    fn generate_evidence(
        &self,
        request: &QuoteRequest,
    ) -> Result<AttestationEvidence, TeeProviderError> {
        // 1. Check for simulated failure
        Self::simulate_failure()?;

        // 2. Identify current mock identity
        let t_type = <Self as TeeAdapter>::quote_type(self);

        // 3. Generate a deterministic pseudo-quote bound to report_data
        let hash = Sha384::digest(request.report_data);

        match t_type {
            QuoteType::Tdx => Ok(AttestationEvidence::Tdx(crate::evidence::TdxEvidence {
                quote: Bytes::from(hash.to_vec()),
                pck_cert_uri: Some("https://mock.attestation/intel/tdx/pck".to_owned()),
            })),
            QuoteType::SevSnp => Ok(AttestationEvidence::SevSnp(
                crate::evidence::SevSnpEvidence {
                    report: Bytes::from(hash.to_vec()),
                    vcek_cert_uri: Some("https://mock.attestation/amd/snp/vcek".to_owned()),
                },
            )),
            QuoteType::Tpm => Ok(AttestationEvidence::Tpm(crate::evidence::TpmEvidence {
                quote: Bytes::from(hash.to_vec()),
                pcr_values: std::iter::once((0, vec![0; 48])).collect(),
                aik_cert_uri: Some("https://mock.attestation/tpm/aik".to_owned()),
            })),
            QuoteType::NvidiaGpu => Ok(AttestationEvidence::NvidiaGpu(
                crate::evidence::NvidiaGpuEvidence {
                    rim_report: Bytes::from(hash.to_vec()),
                    gpu_cert_uri: Some("https://mock.attestation/nvidia/gpu/cert".to_owned()),
                },
            )),
            _ => Ok(AttestationEvidence::Mock(Bytes::from(hash.to_vec()))),
        }
    }

    /// Mock provider is always available unless simulated otherwise.
    fn is_available(&self) -> bool {
        Self::simulate_failure().is_ok()
    }
}

impl TeeProvider for MockTeeProvider {
    fn quote_type(&self) -> QuoteType {
        <Self as TeeAdapter>::quote_type(self)
    }

    /// Backward compatibility bridge to produce wire-format quotes.
    fn generate_quote(&self, request: &QuoteRequest) -> Result<AttestQuote, TeeProviderError> {
        self.generate_evidence(request)
            .map(|e| e.to_quote(Bytes::from(request.report_data.to_vec())))
    }

    fn is_available(&self) -> bool {
        <Self as TeeAdapter>::is_available(self)
    }

    fn seal_data(&self, plaintext: &[u8]) -> Result<Vec<u8>, TeeProviderError> {
        let mut sealed = b"MOCK_SEAL:".to_vec();
        sealed.extend_from_slice(plaintext);
        Ok(sealed)
    }

    fn unseal_data(&self, ciphertext: &[u8]) -> Result<Vec<u8>, TeeProviderError> {
        if ciphertext.starts_with(b"MOCK_SEAL:") {
            Ok(ciphertext[b"MOCK_SEAL:".len()..].to_vec())
        } else {
            Err(TeeProviderError::Enclave(
                "Invalid mock sealed data".to_owned(),
            ))
        }
    }

    fn derive_key(&self, context: &[u8]) -> Result<[u8; 32], TeeProviderError> {
        let hardware_secret = b"MOCK_HARDWARE_SECRET_KEY_1234567890";
        let hkdf = Hkdf::<Sha384>::new(Some(b"mock_salt"), hardware_secret);
        let mut okm = [0u8; 32];
        hkdf.expand(context, &mut okm).map_err(|_| {
            TeeProviderError::Enclave("HKDF expansion failed for mock key derivation".to_owned())
        })?;
        Ok(okm)
    }
}

/// Verify a mock quote by re-deriving its hash.
///
/// This utility is used in test suites to ensure the attestation binding (QUDD)
/// is correctly propagated through the protocol stack.
///
/// # Errors
/// Returns [`Err`] if the quote was not produced by a Mock provider or if the
/// hash binding is incorrect.
pub fn verify_mock_quote(quote: &AttestQuote, report_data: &[u8; 64]) -> Result<(), String> {
    // Note: Mock quotes in this version are raw SHA-384 hashes of report_data
    let expected = Sha384::digest(report_data);
    if quote.raw.as_ref() != expected.as_slice() {
        println!(
            "mock expected: {:?}, got: {:?}",
            expected.as_slice(),
            quote.raw.as_ref()
        );
        return Err("mock quote hash mismatch".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openhttpa_config::{ENV_MOCK_FAILURE, ENV_MOCK_TEE_TYPE};

    #[test]
    fn mock_quote_generated_and_verified() {
        let provider = MockTeeProvider::default();
        assert!(<MockTeeProvider as TeeProvider>::is_available(&provider));
        let req = QuoteRequest {
            report_data: [0x42u8; 64],
        };
        let quote = provider.generate_quote(&req).unwrap();
        verify_mock_quote(&quote, &req.report_data).expect("Verification failed");
    }

    #[test]
    fn mock_simulate_failure() {
        temp_env::with_var(ENV_MOCK_FAILURE, Some("driver"), || {
            let provider = MockTeeProvider::default();
            let req = QuoteRequest {
                report_data: [0x01u8; 64],
            };
            let res = provider.generate_quote(&req);
            assert!(matches!(res, Err(TeeProviderError::Driver(_))));
        });
    }

    #[test]
    fn mock_identity_switching() {
        let provider = MockTeeProvider::default();

        temp_env::with_var(ENV_MOCK_TEE_TYPE, Some("tdx"), || {
            assert_eq!(
                <MockTeeProvider as TeeAdapter>::quote_type(&provider),
                QuoteType::Tdx
            );
        });

        temp_env::with_var(ENV_MOCK_TEE_TYPE, Some("tpm"), || {
            assert_eq!(
                <MockTeeProvider as TeeAdapter>::quote_type(&provider),
                QuoteType::Tpm
            );
        });
    }

    /// SA-07: `is_real_hardware_type` must correctly classify all known types.
    #[test]
    fn is_real_hardware_type_classification() {
        // Mock and Unknown are NOT real hardware.
        assert!(!is_real_hardware_type(&QuoteType::Mock));
        assert!(!is_real_hardware_type(&QuoteType::Unknown(
            "custom".to_owned()
        )));
        // All genuine hardware types must be classified as real.
        assert!(is_real_hardware_type(&QuoteType::Tdx));
        assert!(is_real_hardware_type(&QuoteType::SevSnp));
        assert!(is_real_hardware_type(&QuoteType::Tpm));
        assert!(is_real_hardware_type(&QuoteType::NvidiaGpu));
        assert!(is_real_hardware_type(&QuoteType::Sgx));
    }

    /// SA-07: When `OPENHTTPA_MOCK_TEE_TYPE` resolves to a real hardware type,
    /// the `quote_type()` call must still succeed in test code (to allow CI
    /// to exercise hardware-specific paths), but MUST return the resolved type
    /// so callers can detect the condition.
    ///
    /// Note: This test would trigger a `panic!` in a non-test (production) build.
    #[test]
    fn mock_real_type_allowed_in_test_returns_correct_type() {
        // In test builds, a real TEE type via env var is accepted (CI use-case).
        temp_env::with_var(ENV_MOCK_TEE_TYPE, Some("tdx"), || {
            let provider = MockTeeProvider::default();
            // The call must NOT panic in test context, and must return the real type.
            let qt = <MockTeeProvider as TeeAdapter>::quote_type(&provider);
            assert_eq!(
                qt,
                QuoteType::Tdx,
                "mock must return the configured type in test builds"
            );
        });
    }
}
