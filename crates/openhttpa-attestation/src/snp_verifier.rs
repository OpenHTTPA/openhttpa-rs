// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! AMD SEV-SNP quote verifier.
//!
//! ## Verification pipeline
//!
//! 1. Parse the versioned bundle containing the report and firmware certificate table.
//! 2. Verify the ARK/ASK/VEK chain and pin the ARK to an AMD trust anchor.
//! 3. Verify the report signature with the chained VCEK/VLEK.
//! 4. Verify report-data binding, debug policy, and the configured SVN floor.
//!
//! Steps 2–3 require the `amd_snp` feature to be enabled; without it every
//! call returns [`VerificationError::PolicyViolation`].
//!
//! The default trust anchors are the Milan, Genoa, and Turin ARKs bundled by
//! the pinned `sev` crate. Operator-provided roots are loaded locally and are
//! never fetched from the same untrusted source as the quote.

use crate::verifier::{QuoteVerifier, VerificationError, VerificationResult};
use openhttpa_proto::{AttestQuote, QuoteType};
#[cfg(feature = "amd_snp")]
use openhttpa_proto::{QuoteFormat, SevSnpCertificateType, SevSnpQuoteBundleV1};

#[cfg(feature = "amd_snp")]
use crate::verifier::EatClaims;
#[cfg(feature = "amd_snp")]
use openhttpa_proto::TeeClass;

use std::path::PathBuf;

/// Azure paravisor binding: the report holds `SHA256(runtime claims)` and the claims hold the nonce.
#[cfg(feature = "amd_snp")]
fn verify_azure_hcl_binding(
    embedded: &[u8; 64],
    runtime_data: &[u8],
    expected: &[u8; 64],
) -> Result<(), VerificationError> {
    use sha2::{Digest, Sha256};

    let violation = |m: &str| VerificationError::PolicyViolation(m.to_owned());
    if Sha256::digest(runtime_data).as_slice() != &embedded[..32] {
        return Err(violation(
            "Azure HCL runtime data does not match SNP report_data",
        ));
    }
    let claims: serde_json::Value = serde_json::from_slice(runtime_data)
        .map_err(|e| VerificationError::MalformedQuote(format!("invalid HCL runtime data: {e}")))?;
    let user_data = claims
        .get("user-data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| violation("Azure HCL runtime data is missing user-data"))?;
    if !user_data.eq_ignore_ascii_case(&hex::encode(expected)) {
        return Err(violation(
            "Azure HCL user-data does not match the expected report_data",
        ));
    }
    Ok(())
}

/// Source of the AMD Root Key (ARK) for VCEK chain verification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AmdCaSource {
    /// Use the AMD ARKs bundled in the pinned `sev` crate (Milan, Genoa, Turin).
    #[default]
    Builtin,
    /// Use a DER- or PEM-encoded operator-pinned AMD ARK certificate.
    Static(&'static [u8]),
    /// Load a DER- or PEM-encoded operator-pinned AMD ARK certificate.
    File(PathBuf),
    /// Dynamic trust-on-first-use is intentionally unsupported.
    FetchFromKDS,
}

/// AMD SEV-SNP quote verifier.
///
/// Implements [`QuoteVerifier`] for `QuoteType::SevSnp` attestation reports.
/// Use [`SevSnpVerifier::new`] to create an instance, then register it with
/// [`CompositeVerifier`] or [`FederatedVerifier`].
///
/// [`CompositeVerifier`]: crate::composite::CompositeVerifier
/// [`FederatedVerifier`]: crate::federation::FederatedVerifier
pub struct SevSnpVerifier {
    /// Minimum required reported microcode SVN. Verification fails if this is unset.
    pub min_svn: Option<u16>,
    /// Golden SNP launch measurement required by the relying-party policy.
    pub expected_measurement: Option<[u8; 48]>,
    /// If `true`, debug-mode SNP reports are accepted.  Always `false` in
    /// production — set only in CI/test builds.
    pub allow_debug: bool,
    /// The configured source for the AMD Root Key (ARK) CA certificate.
    pub ca_source: AmdCaSource,
}

impl SevSnpVerifier {
    #[cfg(feature = "amd_snp")]
    fn check_expected_measurement(
        &self,
        report: &sev::firmware::guest::AttestationReport,
    ) -> Result<(), VerificationError> {
        let expected_measurement = self.expected_measurement.ok_or_else(|| {
            VerificationError::PolicyViolation(
                "expected SNP launch measurement must be configured".to_owned(),
            )
        })?;
        if report.measurement != expected_measurement {
            return Err(VerificationError::PolicyViolation(
                "SNP launch measurement does not match the pinned value".to_owned(),
            ));
        }
        Ok(())
    }

    /// Create a verifier using bundled AMD roots, with debug reports rejected.
    #[must_use]
    pub fn new() -> Self {
        Self {
            min_svn: None,
            expected_measurement: None,
            allow_debug: false,
            ca_source: AmdCaSource::default(),
        }
    }

    /// Builder: configure the AMD Root Key (ARK) CA certificate source.
    #[must_use]
    pub fn with_ca_source(mut self, source: AmdCaSource) -> Self {
        self.ca_source = source;
        self
    }

    /// Builder: set the minimum required Security Version Number.
    #[must_use]
    pub const fn with_min_svn(mut self, min_svn: u16) -> Self {
        self.min_svn = Some(min_svn);
        self
    }

    /// Pin the expected 48-byte SNP launch measurement.
    #[must_use]
    pub const fn with_expected_measurement(mut self, measurement: [u8; 48]) -> Self {
        self.expected_measurement = Some(measurement);
        self
    }

    /// Builder: allow debug-mode reports.  **Only for test environments.**
    ///
    /// # Panics (release builds)
    ///
    /// Panics in non-debug (release) builds to prevent accidental enablement.
    #[must_use]
    #[cfg(debug_assertions)]
    pub const fn allow_debug(mut self) -> Self {
        self.allow_debug = true;
        self
    }

    /// Builder: allow debug-mode reports.  **Only for test environments.**
    ///
    /// # Panics (release builds)
    ///
    /// Panics in non-debug (release) builds to prevent accidental enablement.
    #[must_use]
    #[cfg(not(debug_assertions))]
    pub const fn allow_debug(self) -> Self {
        panic!(
            "SevSnpVerifier::allow_debug() must not be called in release builds. \
             Use a test/development build instead."
        );
    }
}

impl Default for SevSnpVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SevSnpVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SevSnpVerifier")
            .field("min_svn", &self.min_svn)
            .field(
                "expected_measurement",
                &self.expected_measurement.map(hex::encode),
            )
            .field("allow_debug", &self.allow_debug)
            .field("ca_source", &self.ca_source)
            .finish()
    }
}

// ─── Core verification ────────────────────────────────────────────────────────

impl QuoteVerifier for SevSnpVerifier {
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
            // Reject anything that isn't an SNP report.
            if quote.quote_type != QuoteType::SevSnp {
                return Err(VerificationError::PolicyViolation(format!(
                    "SevSnpVerifier: unexpected quote type '{:?}'; expected SevSnp",
                    quote.quote_type
                )));
            }

            #[cfg(feature = "amd_snp")]
            {
                self.verify_snp_report(quote, report_data)
            }

            #[cfg(not(feature = "amd_snp"))]
            {
                // Feature not compiled in — return a policy error rather than a
                // silent pass that would be a security hole.
                let _ = (quote, report_data);
                Err(VerificationError::PolicyViolation(
                    "SevSnpVerifier: the 'amd_snp' feature is not enabled in this build. \
                 Recompile with --features amd_snp to enable AMD SEV-SNP verification."
                        .to_owned(),
                ))
            }
        })
    }
}

// ─── Feature-gated implementation ────────────────────────────────────────────

#[cfg(feature = "amd_snp")]
impl SevSnpVerifier {
    /// Full SEV-SNP report verification (steps 1–5).
    fn verify_snp_report(
        &self,
        quote: &AttestQuote,
        report_data: &[u8; 64],
    ) -> Result<VerificationResult, VerificationError> {
        use sev::certs::snp::{Chain, Verifiable};
        use sev::firmware::guest::AttestationReport;
        use sev::firmware::host::{CertTableEntry, CertType};
        use sev::parser::ByteParser;

        if quote.qudd.as_ref() != report_data {
            return Err(VerificationError::PolicyViolation(
                "SEV-SNP quote QUDD mismatch".to_owned(),
            ));
        }
        if quote.format != QuoteFormat::SevSnpBundleV1 || !quote.collateral_uris.is_empty() {
            return Err(VerificationError::MalformedQuote(
                "SEV-SNP quotes must use the certificate-bearing sev_snp_bundle_v1 format"
                    .to_owned(),
            ));
        }

        let bundle: SevSnpQuoteBundleV1 = serde_json::from_slice(&quote.raw).map_err(|error| {
            VerificationError::MalformedQuote(format!("invalid SNP bundle: {error}"))
        })?;
        if bundle.certificate_table.is_empty() {
            return Err(VerificationError::MalformedQuote(
                "SEV-SNP bundle is missing its certificate table".to_owned(),
            ));
        }

        // ── Step 1: Parse raw report bytes ────────────────────────────────
        let report_bytes = bundle.report.as_slice();
        // The wire format is 1184 bytes; `size_of` of the in-memory struct differs.
        let expected_len = <AttestationReport as ByteParser<()>>::EXPECTED_LEN.unwrap_or(1184);
        if report_bytes.len() != expected_len {
            return Err(VerificationError::MalformedQuote(format!(
                "SNP report has invalid length: {} bytes (expected {expected_len})",
                report_bytes.len(),
            )));
        }

        // C-03: Alignment-safe report parsing.
        // `report_bytes` is `&[u8]` (1-byte aligned) but `AttestationReport`
        // may require higher alignment.  Copy into a properly aligned buffer
        // to avoid undefined behavior from misaligned pointer dereference.
        let report = AttestationReport::from_bytes(report_bytes).map_err(|error| {
            VerificationError::MalformedQuote(format!("invalid SNP report: {error}"))
        })?;

        // ── Step 2: Report data (nonce) binding ───────────────────────────
        // The SNP report embeds the caller-supplied `report_data` (64 bytes)
        // in `report.report_data`.  Verify that it matches our expected value
        // to prevent cross-session replay.
        if let Some(runtime_data) = &bundle.hcl_runtime_data {
            verify_azure_hcl_binding(&report.report_data, runtime_data, report_data)?;
        } else if report.report_data != *report_data {
            return Err(VerificationError::PolicyViolation(
                "SNP report_data mismatch: the embedded nonce does not match the expected value"
                    .to_owned(),
            ));
        }

        self.check_expected_measurement(&report)?;

        // ── Step 3: Debug status check ─────────────────────────────────────
        // H-02: Parse the actual debug flag from `guest_policy`.
        // Per AMD SEV-SNP Firmware ABI Specification §7.3, bit 19 of
        // `guest_policy` is the DEBUG flag. When set, the guest is running
        // in debug mode and its memory is accessible to the hypervisor.
        // Previous code incorrectly checked `signing_key` (VCEK vs VLEK),
        // which is unrelated to debug status.
        let is_debug = report.policy.debug_allowed();
        if is_debug && !self.allow_debug {
            return Err(VerificationError::PolicyViolation(
                "SNP report: debug-mode reports are not accepted in production".to_owned(),
            ));
        }

        // The hardware certificate table is untrusted input. Build and verify its
        // full chain, then pin its ARK to an AMD root or operator-provided root.
        let certificate_entries = bundle
            .certificate_table
            .into_iter()
            .filter_map(|entry| {
                let cert_type = match entry.certificate_type {
                    SevSnpCertificateType::Ark => CertType::ARK,
                    SevSnpCertificateType::Ask => CertType::ASK,
                    SevSnpCertificateType::Vcek => CertType::VCEK,
                    SevSnpCertificateType::Vlek => CertType::VLEK,
                    SevSnpCertificateType::Crl | SevSnpCertificateType::Other(_) => return None,
                };
                Some(CertTableEntry::new(cert_type, entry.der))
            })
            .collect::<Vec<_>>();
        let chain = Chain::from_cert_table_der(certificate_entries).map_err(|error| {
            VerificationError::MalformedQuote(format!("invalid AMD certificate table: {error}"))
        })?;

        let report_ark_der = chain
            .ca
            .ark
            .to_der()
            .map_err(|error| VerificationError::MalformedQuote(error.to_string()))?;
        let trusted_arks = self.trusted_ark_der()?;
        if !trusted_arks
            .iter()
            .any(|trusted_ark| trusted_ark == &report_ark_der)
        {
            return Err(VerificationError::PolicyViolation(
                "SEV-SNP certificate chain does not terminate at a trusted AMD ARK".to_owned(),
            ));
        }

        (&chain, &report)
            .verify()
            .map_err(|_error| VerificationError::SignatureInvalid)?;

        // ── Step 6: TCB / SVN enforcement ─────────────────────────────────
        let svn = u16::from(report.reported_tcb.microcode);
        let min_svn = self.min_svn.ok_or_else(|| {
            VerificationError::PolicyViolation(
                "minimum SNP microcode SVN must be configured".to_owned(),
            )
        })?;
        if svn < min_svn {
            return Err(VerificationError::PolicyViolation(format!(
                "SNP reported_tcb.microcode SVN {svn} is below minimum {min_svn}"
            )));
        }

        // ── Step 7: Build normalised EatClaims ────────────────────────────
        // Extract the measurement (first 48 bytes of `report.measurement`).
        let measurement_hex = hex::encode(&report.measurement[..48]);

        Ok(VerificationResult {
            claims: EatClaims {
                tee_class: Some(TeeClass::AmdSevSnp),
                hwmodel: Some("AMD SEV-SNP".to_owned()),
                oemid: Some("AMD".to_owned()),
                boot_progress: Some(measurement_hex.clone()),
                security_version: Some(svn),
                dbgstat: Some(u8::from(is_debug)),
                ..Default::default()
            },
            tcb_status: format!("SVN={svn}"),
            measurement: Some(measurement_hex),
            signer_id: None,
            secondary: vec![],
            eat_token: None,
        })
    }

    fn trusted_ark_der(&self) -> Result<Vec<Vec<u8>>, VerificationError> {
        match &self.ca_source {
            AmdCaSource::Builtin => [
                sev::certs::snp::builtin::milan::ark(),
                sev::certs::snp::builtin::genoa::ark(),
                sev::certs::snp::builtin::turin::ark(),
            ]
            .into_iter()
            .map(|certificate| {
                certificate
                    .and_then(|certificate| certificate.to_der())
                    .map_err(|error| VerificationError::PolicyViolation(format!("invalid bundled AMD ARK: {error}")))
            })
            .collect(),
            AmdCaSource::Static(der_or_pem) => {
                let certificate = parse_amd_certificate(der_or_pem)?;
                Ok(vec![certificate
                    .to_der()
                    .map_err(|error| VerificationError::PolicyViolation(error.to_string()))?])
            }
            AmdCaSource::File(path) => {
                let bytes = std::fs::read(path).map_err(|error| {
                    VerificationError::PolicyViolation(format!("cannot read pinned AMD ARK: {error}"))
                })?;
                let certificate = parse_amd_certificate(&bytes)?;
                Ok(vec![certificate
                    .to_der()
                    .map_err(|error| VerificationError::PolicyViolation(error.to_string()))?])
            }
            AmdCaSource::FetchFromKDS => Err(VerificationError::PolicyViolation(
                "fetching an AMD root certificate at verification time is not a trust anchor; configure a pinned ARK".to_owned(),
            )),
        }
    }
}

#[cfg(feature = "amd_snp")]
fn parse_amd_certificate(
    der_or_pem: &[u8],
) -> Result<sev::certs::snp::Certificate, VerificationError> {
    use sev::certs::snp::Certificate;

    if der_or_pem.starts_with(b"-----BEGIN CERTIFICATE-----") {
        Certificate::from_pem(der_or_pem)
    } else {
        Certificate::from_der(der_or_pem)
    }
    .map_err(|error| VerificationError::PolicyViolation(format!("invalid pinned AMD ARK: {error}")))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[cfg(not(feature = "amd_snp"))]
    fn snp_quote(raw: &'static [u8]) -> AttestQuote {
        AttestQuote {
            quote_type: QuoteType::SevSnp,
            format: openhttpa_proto::QuoteFormat::default(),
            raw: Bytes::from_static(raw),
            qudd: Bytes::new(),
            collateral_uris: vec![],
        }
    }

    #[tokio::test]
    async fn rejects_wrong_quote_type() {
        let verifier = SevSnpVerifier::new();
        let quote = AttestQuote {
            quote_type: QuoteType::Tdx,
            format: openhttpa_proto::QuoteFormat::default(),
            raw: Bytes::from_static(b"fake"),
            qudd: Bytes::new(),
            collateral_uris: vec![],
        };
        let result = verifier.verify(&quote, &[0u8; 64]).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unexpected quote type")
        );
    }

    #[tokio::test]
    #[cfg(feature = "amd_snp")]
    async fn rejects_raw_snp_report_without_certificate_bundle() {
        let verifier = SevSnpVerifier::new().with_min_svn(0);
        let quote = AttestQuote {
            quote_type: QuoteType::SevSnp,
            format: QuoteFormat::Raw,
            raw: Bytes::from_static(b"raw-report-without-certificates"),
            qudd: Bytes::from_static(&[0u8; 64]),
            collateral_uris: vec![],
        };

        let result = verifier.verify(&quote, &[0u8; 64]).await;
        assert!(matches!(result, Err(VerificationError::MalformedQuote(_))));
    }

    #[tokio::test]
    #[cfg(feature = "amd_snp")]
    async fn rejects_snp_bundle_without_certificate_table() {
        let verifier = SevSnpVerifier::new().with_min_svn(0);
        let bundle = SevSnpQuoteBundleV1 {
            report: vec![],
            certificate_table: vec![],
            hcl_runtime_data: None,
        };
        let quote = AttestQuote {
            quote_type: QuoteType::SevSnp,
            format: QuoteFormat::SevSnpBundleV1,
            raw: Bytes::from(serde_json::to_vec(&bundle).unwrap()),
            qudd: Bytes::from_static(&[0u8; 64]),
            collateral_uris: vec![],
        };

        let result = verifier.verify(&quote, &[0u8; 64]).await;
        assert!(matches!(result, Err(VerificationError::MalformedQuote(_))));
    }

    #[test]
    #[cfg(feature = "amd_snp")]
    fn bundled_amd_trust_anchors_are_available() {
        let roots = SevSnpVerifier::new().trusted_ark_der().unwrap();
        assert!(roots.len() >= 3);
        assert!(roots.iter().all(|root| !root.is_empty()));
    }

    #[test]
    #[cfg(feature = "amd_snp")]
    fn expected_measurement_must_be_configured_and_match() {
        use sev::firmware::guest::AttestationReport;

        let verifier = SevSnpVerifier::new();
        let mut report = AttestationReport::default();
        assert!(verifier.check_expected_measurement(&report).is_err());

        let expected = [0x5au8; 48];
        report.measurement = expected;
        let verifier = verifier.with_expected_measurement(expected);
        assert!(verifier.check_expected_measurement(&report).is_ok());

        let verifier = verifier.with_expected_measurement([0xa5u8; 48]);
        assert!(verifier.check_expected_measurement(&report).is_err());
    }

    #[tokio::test]
    #[cfg(not(feature = "amd_snp"))]
    async fn returns_policy_error_without_feature() {
        let verifier = SevSnpVerifier::new();
        let result = verifier.verify(&snp_quote(b"fake"), &[0u8; 64]).await;
        assert!(matches!(
            result,
            Err(VerificationError::PolicyViolation(ref m)) if m.contains("amd_snp")
        ));
    }
}
