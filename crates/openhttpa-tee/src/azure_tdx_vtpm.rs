// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Intel TDX evidence for **Azure confidential VMs** (DCesv5/DCesv6/ECesv6 …).
//!
//! On Azure the guest kernel runs behind the `OpenHCL` paravisor, which owns the
//! TDX module interface. `/dev/tdx_guest` is therefore *not* available to the
//! guest and [`crate::tdx::TdxTeeProvider`] cannot be used. Evidence is instead
//! produced in three steps:
//!
//! 1. Write the 64-byte handshake `report_data` into the vTPM report-data NV
//!    index and read back the **HCL report** (`az_cvm_vtpm::vtpm`). The
//!    paravisor generates a fresh TD report whose `REPORTDATA[0..32]` is
//!    `SHA-256(var_data)`, where `var_data` is a JSON document that contains
//!    the vTPM attestation-key public part and our report data (`user-data`).
//! 2. Send the TD report to the Azure IMDS endpoint
//!    `http://169.254.169.254/acc/tdquote`, which forwards it to the host TDX
//!    Quoting Enclave and returns an **Intel DCAP TD quote** (signed by the
//!    PCK chain rooted in the Intel SGX Root CA).
//! 3. Emit [`AttestationEvidence::Tdx`] with `hcl_runtime_data = var_data` so
//!    the verifier can recompute the binding.
//!
//! The provider never asserts trust: IMDS, the paravisor, and the vTPM are all
//! *transport* for hardware-signed evidence. Trust is established only by the
//! relying party's DCAP verification (`openhttpa-attestation`, feature
//! `tdx_dcap`).

use std::sync::OnceLock;

use az_cvm_vtpm::hcl::{HclReport, ReportType};
use az_cvm_vtpm::tdx::TdReport;
use bytes::Bytes;
use openhttpa_proto::{AttestQuote, QuoteType};
use sha2::{Digest, Sha256};

use crate::evidence::{AttestationEvidence, TdxEvidence};
use crate::provider::{QuoteRequest, TeeAdapter, TeeProvider, TeeProviderError};

fn err(msg: impl std::fmt::Display) -> TeeProviderError {
    TeeProviderError::QuoteGeneration(msg.to_string())
}

/// Azure paravisor (vTPM + IMDS) TDX evidence provider.
///
/// Construct with [`AzureTdxVtpmTeeProvider::new`]. Availability is probed once
/// (by reading the HCL report type from the vTPM) and cached.
#[derive(Debug, Default)]
pub struct AzureTdxVtpmTeeProvider {
    available: OnceLock<bool>,
}

impl AzureTdxVtpmTeeProvider {
    /// Create a provider. No hardware access happens until first use.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            available: OnceLock::new(),
        }
    }

    fn probe() -> bool {
        if !std::path::Path::new("/dev/tpmrm0").exists() {
            return false;
        }
        az_cvm_vtpm::vtpm::get_report()
            .ok()
            .and_then(|bytes| HclReport::new(bytes).ok())
            .is_some_and(|hcl| hcl.report_type() == ReportType::Tdx)
    }
}

/// Generate Azure TDX evidence bound to `report_data`.
///
/// # Errors
/// Fails closed if the vTPM is absent, the HCL report is not a TDX report, the
/// paravisor binding does not hold locally, or IMDS cannot produce a quote.
pub fn generate_evidence(report_data: &[u8]) -> Result<AttestationEvidence, TeeProviderError> {
    if report_data.len() != 64 {
        return Err(err("report_data must be 64 bytes"));
    }
    let hcl_bytes = az_cvm_vtpm::vtpm::get_report_with_report_data(report_data)
        .map_err(|e| err(format!("vTPM HCL report failed: {e}")))?;
    let hcl = HclReport::new(hcl_bytes).map_err(|e| err(format!("invalid HCL report: {e}")))?;
    if hcl.report_type() != ReportType::Tdx {
        return Err(err("Azure HCL report is not an Intel TDX report"));
    }
    let var_data = hcl.var_data().to_vec();
    let td_report = TdReport::try_from(&hcl).map_err(|e| err(format!("invalid TD report: {e}")))?;

    // Local self-check (not a trust decision): catch a paravisor/library
    // mismatch before shipping evidence that the verifier would reject anyway.
    check_local_binding(&td_report, &var_data)?;

    let quote = az_tdx_vtpm::imds::get_td_quote(&td_report)
        .map_err(|e| err(format!("Azure IMDS /acc/tdquote failed: {e}")))?;
    if quote.is_empty() {
        return Err(err("Azure IMDS returned an empty TD quote"));
    }

    Ok(AttestationEvidence::Tdx(TdxEvidence {
        quote: Bytes::from(quote),
        pck_cert_uri: None,
        hcl_runtime_data: Some(Bytes::from(var_data)),
    }))
}

fn check_local_binding(td_report: &TdReport, var_data: &[u8]) -> Result<(), TeeProviderError> {
    let digest = Sha256::digest(var_data);
    if td_report.report_mac.reportdata[..32] != digest[..] {
        return Err(err(
            "TD report REPORTDATA does not bind SHA-256(HCL runtime data)",
        ));
    }
    Ok(())
}

impl TeeAdapter for AzureTdxVtpmTeeProvider {
    fn quote_type(&self) -> QuoteType {
        QuoteType::Tdx
    }

    fn generate_evidence(
        &self,
        request: &QuoteRequest,
    ) -> Result<AttestationEvidence, TeeProviderError> {
        generate_evidence(&request.report_data)
    }

    fn is_available(&self) -> bool {
        *self.available.get_or_init(Self::probe)
    }
}

impl TeeProvider for AzureTdxVtpmTeeProvider {
    fn quote_type(&self) -> QuoteType {
        QuoteType::Tdx
    }

    fn generate_quote(&self, request: &QuoteRequest) -> Result<AttestQuote, TeeProviderError> {
        <Self as TeeAdapter>::generate_evidence(self, request)
            .map(|e| e.to_quote(Bytes::from(request.report_data.to_vec())))
    }

    fn is_available(&self) -> bool {
        <Self as TeeAdapter>::is_available(self)
    }

    fn derive_key(&self, _context: &[u8]) -> Result<[u8; 32], TeeProviderError> {
        Err(TeeProviderError::NotAvailable(
            "Azure TDX CVMs expose no guest sealing-key primitive through the paravisor".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real HCL report captured on an Azure TDX CVM, shipped by Microsoft in
    /// the `az-cvm-vtpm` crate (`test/hcl-report-tdx.bin`).
    const AZURE_HCL_TDX: &[u8] = include_bytes!("../testdata/azure/hcl-report-tdx.bin");

    #[test]
    fn real_azure_hcl_report_binds_var_data() {
        let hcl = HclReport::new(AZURE_HCL_TDX.to_vec()).unwrap();
        assert_eq!(hcl.report_type(), ReportType::Tdx);
        let var_data = hcl.var_data().to_vec();
        let td = TdReport::try_from(&hcl).unwrap();
        check_local_binding(&td, &var_data).unwrap();
    }

    #[test]
    fn tampered_var_data_is_rejected() {
        let hcl = HclReport::new(AZURE_HCL_TDX.to_vec()).unwrap();
        let mut var_data = hcl.var_data().to_vec();
        var_data[0] ^= 1;
        let td = TdReport::try_from(&hcl).unwrap();
        assert!(check_local_binding(&td, &var_data).is_err());
    }

    #[test]
    fn rejects_wrong_report_data_length() {
        assert!(generate_evidence(&[0u8; 32]).is_err());
    }
}
