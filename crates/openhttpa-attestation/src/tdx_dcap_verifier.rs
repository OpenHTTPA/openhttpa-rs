// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Intel TDX quote verifier backed by Intel DCAP collateral (feature `tdx_dcap`).
//!
//! This is a **first-party** verifier: it does not delegate the trust decision
//! to a cloud attestation service. Every check runs locally against
//! Intel-signed data, using the pure-Rust [`dcap_qvl`] implementation of
//! Intel's Quote Verification Library.
//!
//! ## Verification pipeline (fail closed, in order)
//!
//! 1. **Envelope**: `quote_type == Tdx`, `qudd == report_data`, format is
//!    `tdx_bundle_v1` (or legacy `raw`).
//! 2. **Collateral**: fetched from Intel PCS (`api.trustedservices.intel.com`)
//!    for *this* quote's FMSPC on every verification — TCB info, QE identity,
//!    PCK CRL, Root CA CRL and their issuer chains. The prover cannot supply or
//!    choose collateral.
//! 3. **DCAP**: quote signature → attestation key → QE report → PCK leaf →
//!    PCK platform/processor CA → **pinned Intel SGX Root CA**
//!    (`certs/intel_sgx_root_ca.der`, SHA-256 [`INTEL_SGX_ROOT_CA_SHA256`]).
//!    TCB info and QE identity signatures are verified under the Intel TCB
//!    signing chain, and **both CRLs are enforced with their `nextUpdate`**
//!    (webpki `ExpirationPolicy::Enforce`). Revoked PCK/intermediate certs fail.
//! 4. **Collateral freshness**: [`dcap_qvl::QuotePolicy::strict`] rejects any
//!    collateral whose earliest `nextUpdate`/`notAfter` is in the past. There is
//!    no grace period.
//! 5. **TCB status**: only `UpToDate` is accepted unless the operator
//!    explicitly allow-lists another status ([`TdxPolicy::allowed_tcb_statuses`]).
//!    The converged status and every advisory ID are reported either way.
//! 6. **TD attributes**: `TUD.DEBUG` must be clear (checked by `dcap_qvl` *and*
//!    again here).
//! 7. **Report-data binding**: with Azure paravisor runtime data, the quote's
//!    `REPORTDATA[0..32]` must equal `SHA-256(runtime JSON)` and the JSON's
//!    `user-data` must equal the handshake report data; otherwise
//!    `REPORTDATA` must equal the report data exactly.
//! 8. **Measurement policy**: `MRTD` must be in the configured allow-list
//!    (fail closed if the list is empty). Optional `RTMR[0..3]` pins are
//!    enforced when configured.
//!
//! The offline entry point [`verify_tdx_bundle_with_collateral`] runs steps
//! 3–8 against caller-supplied collateral and a caller-supplied clock. It is
//! intended for **re-verification of recorded evidence** (audits, investor
//! dossiers) and unit tests with real Intel fixtures.

use std::time::{SystemTime, UNIX_EPOCH};

use dcap_qvl::quote::TDReport10;
use dcap_qvl::verify::QuoteVerifier as DcapQuoteVerifier;
use dcap_qvl::{PckCertFlag, QuoteCollateralV3, QuotePolicy, TcbStatus};
use openhttpa_proto::{AttestQuote, QuoteFormat, QuoteType, TdxQuoteBundleV1, TeeClass};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::azure_hcl::verify_azure_hcl_binding;
use crate::verifier::{EatClaims, QuoteVerifier, VerificationError, VerificationResult};

/// Intel PCS collateral (TCB info, QE identity, PCK/Root CA CRLs and their
/// issuer chains) as fetched by [`fetch_intel_collateral`]. Serializable, so
/// relying parties can store it beside the quote for later re-verification.
pub use dcap_qvl::QuoteCollateralV3 as IntelCollateral;

/// Intel SGX Provisioning Certification Root CA (DER), identical to
/// <https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer>.
pub const INTEL_SGX_ROOT_CA_DER: &[u8] = include_bytes!("../certs/intel_sgx_root_ca.der");

/// SHA-256 of [`INTEL_SGX_ROOT_CA_DER`]; checked before every verification.
pub const INTEL_SGX_ROOT_CA_SHA256: &str =
    "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3";

/// Intel Provisioning Certification Service base URL.
pub const INTEL_PCS_URL: &str = "https://api.trustedservices.intel.com";

/// Relying-party policy for TDX quotes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
// Each flag is an independent, explicitly reviewed relying-party decision.
#[allow(clippy::struct_excessive_bools)]
pub struct TdxPolicy {
    /// Accepted converged TCB statuses **in addition to** `UpToDate`.
    /// Empty (the default) means only `UpToDate`.
    pub allowed_tcb_statuses: Vec<String>,
    /// Allow-listed `MRTD` values (48 bytes). Must be non-empty.
    pub expected_mrtds: Vec<[u8; 48]>,
    /// Optional exact pins for `RTMR0..RTMR3`.
    pub expected_rtmrs: [Option<[u8; 48]>; 4],
    /// Accept debug TDs. Never enable outside a lab.
    pub allow_debug: bool,
    /// Accept a PCK certificate whose `dynamicPlatform` flag is set
    /// (multi-package platforms that can add CPU packages). Multi-socket cloud
    /// hosts set it; Intel QVL reports it without rejecting.
    pub allow_dynamic_platform: bool,
    /// Accept a PCK certificate whose `cachedKeys` flag is set (platform root
    /// keys cached by Intel for re-provisioning). Standard on cloud hosts.
    pub allow_cached_keys: bool,
    /// Accept a PCK certificate whose `smtEnabled` flag is set (Hyper-Threading).
    pub allow_smt: bool,
}

impl TdxPolicy {
    /// Policy for a public-cloud TDX host: strict TCB (`UpToDate` only), no
    /// debug, the given MRTD allow-list, and the three PCK platform flags that
    /// every multi-socket cloud host carries accepted. The flags are still
    /// reported in [`TdxVerificationReport::pck_flags`].
    #[must_use]
    pub fn cloud_host(expected_mrtds: Vec<[u8; 48]>) -> Self {
        Self {
            expected_mrtds,
            allow_dynamic_platform: true,
            allow_cached_keys: true,
            allow_smt: true,
            ..Self::default()
        }
    }
}

/// PCK certificate platform flags (`"true"`, `"false"` or `"undefined"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TdxPckFlags {
    /// `dynamicPlatform`.
    pub dynamic_platform: String,
    /// `cachedKeys`.
    pub cached_keys: String,
    /// `smtEnabled`.
    pub smt_enabled: String,
}

/// How the quote's `REPORTDATA` was bound to the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TdxReportDataBinding {
    /// `REPORTDATA[0..32] = SHA-256(Azure HCL runtime JSON)`, JSON `user-data` = report data.
    AzureHclSha256UserData,
    /// `REPORTDATA` equals the report data byte-for-byte (bare TDX guest).
    Direct,
}

/// Every claim established by a successful TDX verification. All hex strings
/// are lowercase. Suitable for audit logs and UI evidence panels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TdxVerificationReport {
    /// SHA-256 of the raw DCAP quote bytes.
    pub quote_sha256: String,
    /// DCAP quote header version (4 or 5).
    pub quote_version: u16,
    /// Converged platform+QE TCB status (e.g. `UpToDate`).
    pub tcb_status: String,
    /// Union of Intel security advisory IDs for the matched TCB levels.
    pub advisory_ids: Vec<String>,
    /// `tcbEvaluationDataNumber` of the collateral used.
    pub tcb_eval_data_number: u32,
    /// Platform FMSPC from the PCK certificate.
    pub fmspc: String,
    /// SHA-256 of the pinned Intel root CA that anchored the chain.
    pub root_ca_sha256: String,
    /// CRL numbers of the PCK CRL and Root CA CRL that were enforced.
    pub pck_crl_number: u32,
    /// Root CA CRL number.
    pub root_ca_crl_number: u32,
    /// Earliest `nextUpdate`/`notAfter` across all collateral (unix seconds).
    pub collateral_earliest_expiration: u64,
    /// Latest `issueDate`/`thisUpdate` across all collateral (unix seconds).
    pub collateral_latest_issue: u64,
    /// Verification clock (unix seconds).
    pub verified_at: u64,
    /// TD measurement registers and identity.
    pub mr_td: String,
    /// Runtime measurement registers 0–3.
    pub rtmr: [String; 4],
    /// TDX module measurement.
    pub mr_seam: String,
    /// TDX module signer.
    pub mr_signer_seam: String,
    /// Config ID / owner / owner-config.
    pub mr_config_id: String,
    /// `MROWNER`.
    pub mr_owner: String,
    /// `MROWNERCONFIG`.
    pub mr_owner_config: String,
    /// `TDATTRIBUTES` (8 bytes).
    pub td_attributes: String,
    /// `XFAM` (8 bytes).
    pub xfam: String,
    /// `TEE_TCB_SVN` (16 bytes).
    pub tee_tcb_svn: String,
    /// Raw `REPORTDATA` (64 bytes).
    pub report_data: String,
    /// Debug bit state (always `false` on success unless `allow_debug`).
    pub debug: bool,
    /// Binding mode used for `REPORTDATA`.
    pub report_data_binding: TdxReportDataBinding,
    /// PCK platform flags (accepted only if the policy allowed them).
    pub pck_flags: TdxPckFlags,
}

fn violation(message: impl Into<String>) -> VerificationError {
    VerificationError::PolicyViolation(message.into())
}

fn parse_status(name: &str) -> Result<TcbStatus, VerificationError> {
    serde_json::from_value(serde_json::Value::String(name.to_owned()))
        .map_err(|_| violation(format!("unknown TDX TCB status in policy: {name}")))
}

fn unix_now() -> Result<u64, VerificationError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| violation("system clock is before the Unix epoch"))
}

/// Decode a `tdx_bundle_v1` (or legacy raw) TDX quote envelope.
///
/// # Errors
/// [`VerificationError::MalformedQuote`] on a wrong type/format or bad JSON.
pub fn decode_tdx_bundle(quote: &AttestQuote) -> Result<TdxQuoteBundleV1, VerificationError> {
    if quote.quote_type != QuoteType::Tdx {
        return Err(violation(format!(
            "TdxDcapVerifier: unexpected quote type '{:?}'; expected Tdx",
            quote.quote_type
        )));
    }
    match &quote.format {
        QuoteFormat::TdxBundleV1 => serde_json::from_slice(&quote.raw)
            .map_err(|e| VerificationError::MalformedQuote(format!("invalid tdx_bundle_v1: {e}"))),
        QuoteFormat::Raw => Ok(TdxQuoteBundleV1 {
            quote: quote.raw.to_vec(),
            hcl_runtime_data: None,
        }),
        other => Err(VerificationError::MalformedQuote(format!(
            "unsupported TDX quote format '{other}'"
        ))),
    }
}

/// Offline TDX verification against caller-supplied Intel collateral.
///
/// Runs pipeline steps 3–8 (see module docs) with clock `now_secs`.
///
/// # Errors
/// Any failed signature, chain, CRL, freshness, TCB, debug, binding, or
/// measurement check.
pub fn verify_tdx_bundle_with_collateral(
    bundle: &TdxQuoteBundleV1,
    collateral: &QuoteCollateralV3,
    expected_report_data: &[u8; 64],
    now_secs: u64,
    policy: &TdxPolicy,
) -> Result<TdxVerificationReport, VerificationError> {
    let root_sha = hex::encode(Sha256::digest(INTEL_SGX_ROOT_CA_DER));
    if root_sha != INTEL_SGX_ROOT_CA_SHA256 {
        return Err(violation(
            "bundled Intel SGX Root CA does not match its pinned SHA-256",
        ));
    }
    if policy.expected_mrtds.is_empty() {
        return Err(violation(
            "at least one expected TDX MRTD must be configured",
        ));
    }

    let mut quote_policy = QuotePolicy::strict(now_secs)
        .allow_dynamic_platform(policy.allow_dynamic_platform)
        .allow_cached_keys(policy.allow_cached_keys)
        .allow_smt(policy.allow_smt);
    for name in &policy.allowed_tcb_statuses {
        quote_policy = quote_policy.allow_status(parse_status(name)?);
    }

    let claims = DcapQuoteVerifier::new(INTEL_SGX_ROOT_CA_DER.to_vec())
        .allow_debug(policy.allow_debug)
        .verify_with_policy(&bundle.quote, collateral.clone(), now_secs, &quote_policy)
        .map_err(|e| violation(format!("Intel DCAP verification failed: {e:#}")))?;

    if claims.tee_type != 0x0000_0081 {
        return Err(violation("DCAP quote is not a TDX quote"));
    }
    let td: &TDReport10 = claims
        .report
        .as_td10()
        .ok_or_else(|| violation("DCAP quote does not carry a TD report"))?;

    let debug = td.td_attributes[0] & 0x01 != 0;
    if debug && !policy.allow_debug {
        return Err(violation("TDX quote comes from a debug TD"));
    }

    let binding = if let Some(runtime) = &bundle.hcl_runtime_data {
        verify_azure_hcl_binding(&td.report_data, runtime, expected_report_data)?;
        TdxReportDataBinding::AzureHclSha256UserData
    } else if td.report_data == *expected_report_data {
        TdxReportDataBinding::Direct
    } else {
        return Err(violation(
            "TDX REPORTDATA does not match the expected report data",
        ));
    };

    if !policy.expected_mrtds.contains(&td.mr_td) {
        return Err(violation(format!(
            "TDX MRTD {} is not in the approved allow-list",
            hex::encode(td.mr_td)
        )));
    }
    let rtmrs = [&td.rt_mr0, &td.rt_mr1, &td.rt_mr2, &td.rt_mr3];
    for (index, (pin, actual)) in policy.expected_rtmrs.iter().zip(rtmrs).enumerate() {
        if let Some(pin) = pin
            && pin != actual
        {
            return Err(violation(format!(
                "TDX RTMR{index} {} does not match the pinned value",
                hex::encode(actual)
            )));
        }
    }

    Ok(TdxVerificationReport {
        quote_sha256: hex::encode(Sha256::digest(&bundle.quote)),
        quote_version: claims.header.version,
        tcb_status: format!("{:?}", claims.tcb.status),
        advisory_ids: claims.tcb.advisory_ids.clone(),
        tcb_eval_data_number: claims.tcb.eval_data_number,
        fmspc: hex::encode(claims.platform.pck.fmspc),
        root_ca_sha256: root_sha,
        pck_crl_number: claims.platform.pck_crl_num,
        root_ca_crl_number: claims.platform.root_ca_crl_num,
        collateral_earliest_expiration: claims.earliest_expiration_date,
        collateral_latest_issue: claims.latest_issue_date,
        verified_at: now_secs,
        mr_td: hex::encode(td.mr_td),
        rtmr: rtmrs.map(hex::encode),
        mr_seam: hex::encode(td.mr_seam),
        mr_signer_seam: hex::encode(td.mr_signer_seam),
        mr_config_id: hex::encode(td.mr_config_id),
        mr_owner: hex::encode(td.mr_owner),
        mr_owner_config: hex::encode(td.mr_owner_config),
        td_attributes: hex::encode(td.td_attributes),
        xfam: hex::encode(td.xfam),
        tee_tcb_svn: hex::encode(td.tee_tcb_svn),
        report_data: hex::encode(td.report_data),
        debug,
        report_data_binding: binding,
        pck_flags: TdxPckFlags {
            dynamic_platform: flag(claims.platform.pck.dynamic_platform),
            cached_keys: flag(claims.platform.pck.cached_keys),
            smt_enabled: flag(claims.platform.pck.smt_enabled),
        },
    })
}

fn flag(value: PckCertFlag) -> String {
    match value {
        PckCertFlag::True => "true",
        PckCertFlag::False => "false",
        PckCertFlag::Undefined => "undefined",
    }
    .to_owned()
}

/// Fetch Intel collateral for `raw_quote` from `pccs_url` (normally
/// [`INTEL_PCS_URL`]). The returned collateral includes the PCK chain.
///
/// # Errors
/// Network/HTTP/parse failures; the caller must treat them as verification failure.
pub async fn fetch_intel_collateral(
    pccs_url: &str,
    raw_quote: &[u8],
) -> Result<QuoteCollateralV3, VerificationError> {
    let client = dcap_qvl::collateral::CollateralClient::with_default_http(pccs_url)
        .map_err(|e| violation(format!("cannot build Intel PCS client: {e:#}")))?;
    client
        .fetch(raw_quote)
        .await
        .map_err(|e| violation(format!("Intel PCS collateral fetch failed: {e:#}")))
}

/// Online TDX DCAP [`QuoteVerifier`].
#[derive(Debug, Clone)]
pub struct TdxDcapVerifier {
    policy: TdxPolicy,
    pccs_url: String,
}

impl TdxDcapVerifier {
    /// Build a verifier using Intel PCS and the given policy.
    #[must_use]
    pub fn new(policy: TdxPolicy) -> Self {
        Self {
            policy,
            pccs_url: INTEL_PCS_URL.to_owned(),
        }
    }

    /// Override the collateral service (e.g. an organisation-run PCCS that
    /// mirrors Intel PCS). Collateral is still Intel-signed and fully checked.
    #[must_use]
    pub fn with_pccs_url(mut self, url: impl Into<String>) -> Self {
        self.pccs_url = url.into();
        self
    }

    /// The configured policy.
    #[must_use]
    pub const fn policy(&self) -> &TdxPolicy {
        &self.policy
    }

    /// Verify and return the full report (used by audit tooling).
    ///
    /// # Errors
    /// See [`verify_tdx_bundle_with_collateral`] and [`fetch_intel_collateral`].
    pub async fn verify_detailed(
        &self,
        quote: &AttestQuote,
        report_data: &[u8; 64],
    ) -> Result<(TdxVerificationReport, QuoteCollateralV3), VerificationError> {
        if quote.qudd.as_ref() != report_data {
            return Err(violation("TDX quote QUDD mismatch"));
        }
        let bundle = decode_tdx_bundle(quote)?;
        let collateral = fetch_intel_collateral(&self.pccs_url, &bundle.quote).await?;
        let report = verify_tdx_bundle_with_collateral(
            &bundle,
            &collateral,
            report_data,
            unix_now()?,
            &self.policy,
        )?;
        Ok((report, collateral))
    }
}

impl QuoteVerifier for TdxDcapVerifier {
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
            let (report, _) = self.verify_detailed(quote, report_data).await?;
            Ok(VerificationResult {
                claims: EatClaims {
                    tee_class: Some(TeeClass::IntelTdx),
                    hwmodel: Some("Intel TDX".to_owned()),
                    oemid: Some("Intel".to_owned()),
                    boot_progress: Some(report.mr_td.clone()),
                    dbgstat: Some(u8::from(report.debug)),
                    iat: Some(report.verified_at),
                    exp: Some(report.collateral_earliest_expiration),
                    ..Default::default()
                },
                tcb_status: report.tcb_status.clone(),
                measurement: Some(report.mr_td.clone()),
                signer_id: Some(report.mr_signer_seam.clone()),
                secondary: vec![],
                eat_token: serde_json::to_vec(&report).ok(),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    // Real Intel-signed TDX quotes and their PCS collateral, shipped with
    // dcap-qvl 0.7.0 (`sample/`). See testdata/intel/PROVENANCE.md.
    const QUOTE: &[u8] = include_bytes!("../testdata/intel/tdx_quote");
    const COLLATERAL: &[u8] = include_bytes!("../testdata/intel/tdx_quote_collateral.json");
    const OUTDATED_QUOTE: &[u8] = include_bytes!("../testdata/intel/tdx_quote_outdated");
    const OUTDATED_COLLATERAL: &[u8] =
        include_bytes!("../testdata/intel/tdx_quote_outdated_collateral.json");

    /// Fixed clock inside the sample collateral's validity window
    /// (TCB info issued 2025-06-19T10:16:03Z, next update 2025-07-19).
    const NOW: u64 = 1_750_500_000; // 2025-06-21T10:00:00Z

    fn collateral(raw: &[u8]) -> QuoteCollateralV3 {
        serde_json::from_slice(raw).unwrap()
    }

    fn td(raw: &[u8]) -> TDReport10 {
        let c = DcapQuoteVerifier::new(INTEL_SGX_ROOT_CA_DER.to_vec())
            .verify_with_policy(
                raw,
                collateral(COLLATERAL),
                NOW,
                &QuotePolicy::claims_only(NOW),
            )
            .unwrap();
        *c.report.as_td10().unwrap()
    }

    fn policy_for(raw: &[u8]) -> (TdxPolicy, [u8; 64]) {
        let t = td(raw);
        (TdxPolicy::cloud_host(vec![t.mr_td]), t.report_data)
    }

    fn bundle(raw: &[u8]) -> TdxQuoteBundleV1 {
        TdxQuoteBundleV1 {
            quote: raw.to_vec(),
            hcl_runtime_data: None,
        }
    }

    #[test]
    fn pinned_root_matches_intel_published_hash() {
        assert_eq!(
            hex::encode(Sha256::digest(INTEL_SGX_ROOT_CA_DER)),
            INTEL_SGX_ROOT_CA_SHA256
        );
    }

    #[test]
    fn real_intel_quote_verifies_up_to_date() {
        let (policy, rd) = policy_for(QUOTE);
        let report = verify_tdx_bundle_with_collateral(
            &bundle(QUOTE),
            &collateral(COLLATERAL),
            &rd,
            NOW,
            &policy,
        )
        .unwrap();
        assert_eq!(report.tcb_status, "UpToDate");
        assert_eq!(report.report_data_binding, TdxReportDataBinding::Direct);
        assert!(!report.debug);
        assert_eq!(report.root_ca_sha256, INTEL_SGX_ROOT_CA_SHA256);
        assert_eq!(report.pck_flags.dynamic_platform, "true");
    }

    #[test]
    fn pck_platform_flags_fail_closed_unless_allowed() {
        let (policy, rd) = policy_for(QUOTE);
        let strict = TdxPolicy {
            expected_mrtds: policy.expected_mrtds,
            ..TdxPolicy::default()
        };
        let err = verify_tdx_bundle_with_collateral(
            &bundle(QUOTE),
            &collateral(COLLATERAL),
            &rd,
            NOW,
            &strict,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("Dynamic platform"), "{err}");
    }

    #[test]
    fn expired_collateral_is_rejected() {
        let (policy, rd) = policy_for(QUOTE);
        let later = 1_900_000_000; // 2030: past every nextUpdate in the sample
        assert!(
            verify_tdx_bundle_with_collateral(
                &bundle(QUOTE),
                &collateral(COLLATERAL),
                &rd,
                later,
                &policy
            )
            .is_err()
        );
    }

    #[test]
    fn tampered_quote_is_rejected() {
        let (policy, rd) = policy_for(QUOTE);
        let mut raw = QUOTE.to_vec();
        // Flip a byte inside the TD report body (MRTD region) to break the signature.
        raw[48 + 136] ^= 0x01;
        assert!(
            verify_tdx_bundle_with_collateral(
                &bundle(&raw),
                &collateral(COLLATERAL),
                &rd,
                NOW,
                &policy
            )
            .is_err()
        );
    }

    #[test]
    fn tampered_collateral_is_rejected() {
        let (policy, rd) = policy_for(QUOTE);
        let mut c = collateral(COLLATERAL);
        c.tcb_info = c.tcb_info.replacen("UpToDate", "UpToDatf", 1);
        assert!(verify_tdx_bundle_with_collateral(&bundle(QUOTE), &c, &rd, NOW, &policy).is_err());
    }

    #[test]
    fn wrong_report_data_mrtd_and_rtmr_are_rejected() {
        let (policy, rd) = policy_for(QUOTE);
        let c = collateral(COLLATERAL);
        let mut other = rd;
        other[0] ^= 1;
        assert!(
            verify_tdx_bundle_with_collateral(&bundle(QUOTE), &c, &other, NOW, &policy).is_err()
        );

        let wrong_mrtd = TdxPolicy {
            expected_mrtds: vec![[0u8; 48]],
            ..policy.clone()
        };
        assert!(
            verify_tdx_bundle_with_collateral(&bundle(QUOTE), &c, &rd, NOW, &wrong_mrtd).is_err()
        );

        let empty = TdxPolicy::default();
        assert!(verify_tdx_bundle_with_collateral(&bundle(QUOTE), &c, &rd, NOW, &empty).is_err());

        let mut wrong_rtmr = policy.clone();
        wrong_rtmr.expected_rtmrs[0] = Some([0u8; 48]);
        assert!(
            verify_tdx_bundle_with_collateral(&bundle(QUOTE), &c, &rd, NOW, &wrong_rtmr).is_err()
        );

        let mut debug_ok = policy;
        debug_ok.allow_debug = true;
        // allow_debug only widens; a production TD still verifies.
        assert!(verify_tdx_bundle_with_collateral(&bundle(QUOTE), &c, &rd, NOW, &debug_ok).is_ok());
    }

    #[test]
    fn azure_binding_requires_matching_runtime_data() {
        let (policy, rd) = policy_for(QUOTE);
        let mut b = bundle(QUOTE);
        // The sample quote is not from Azure, so any runtime JSON must fail the hash link.
        b.hcl_runtime_data =
            Some(format!("{{\"user-data\":\"{}\"}}", hex::encode(rd)).into_bytes());
        assert!(
            verify_tdx_bundle_with_collateral(&b, &collateral(COLLATERAL), &rd, NOW, &policy)
                .is_err()
        );
    }

    #[test]
    fn quote_below_every_tcb_level_is_rejected_even_if_all_statuses_allowed() {
        // Real Intel quote whose TDX module SVN matches no TCB level in its
        // collateral. dcap-qvl only accepts it via a "dangerous" override.
        let c = collateral(OUTDATED_COLLATERAL);
        let tcb: serde_json::Value = serde_json::from_str(&c.tcb_info).unwrap();
        let now = parse_rfc3339(tcb["issueDate"].as_str().unwrap()) + 86_400;
        let policy = TdxPolicy {
            allowed_tcb_statuses: [
                "SWHardeningNeeded",
                "ConfigurationNeeded",
                "ConfigurationAndSWHardeningNeeded",
                "OutOfDate",
                "OutOfDateConfigurationNeeded",
                "TDRelaunchAdvised",
                "TDRelaunchAdvisedConfigurationNeeded",
            ]
            .map(str::to_owned)
            .to_vec(),
            ..TdxPolicy::cloud_host(vec![[0u8; 48]])
        };
        let err = verify_tdx_bundle_with_collateral(
            &bundle(OUTDATED_QUOTE),
            &c,
            &[0u8; 64],
            now,
            &policy,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("TCB level"), "{err}");
    }

    #[test]
    fn envelope_checks() {
        let q = AttestQuote {
            quote_type: QuoteType::SevSnp,
            format: QuoteFormat::TdxBundleV1,
            raw: Bytes::new(),
            qudd: Bytes::new(),
            collateral_uris: vec![],
        };
        assert!(decode_tdx_bundle(&q).is_err());
        let q = AttestQuote {
            quote_type: QuoteType::Tdx,
            format: QuoteFormat::SevSnpBundleV1,
            ..q
        };
        assert!(decode_tdx_bundle(&q).is_err());
        assert!(parse_status("Bogus").is_err());
        assert!(parse_status("UpToDate").is_ok());
    }

    /// `YYYY-MM-DDTHH:MM:SSZ` → unix seconds (UTC), enough for fixture dates.
    fn parse_rfc3339(text: &str) -> u64 {
        let num = |range: std::ops::Range<usize>| text[range].parse::<i64>().unwrap();
        assert_eq!(text.as_bytes()[10], b'T');
        let (year, month, day) = (num(0..4), num(5..7), num(8..10));
        let (hour, minute, second) = (num(11..13), num(14..16), num(17..19));
        // Julian day number (Fliegel & Van Flandern).
        let shift = (14 - month) / 12;
        let y_adj = year + 4800 - shift;
        let m_adj = month + 12 * shift - 3;
        let julian = day + (153 * m_adj + 2) / 5 + 365 * y_adj + y_adj / 4 - y_adj / 100
            + y_adj / 400
            - 32045;
        let days = julian - 2_440_588;
        u64::try_from(days * 86_400 + hour * 3600 + minute * 60 + second).unwrap()
    }
}
