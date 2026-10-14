// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! SEV-SNP evidence for Azure confidential VMs, where the paravisor hides `/dev/sev-guest`.
//!
//! The HCL report comes from the vTPM (`az-cvm-vtpm`) and the AMD certificate chain from the
//! Azure IMDS THIM endpoint (`az-snp-vtpm`).

use az_cvm_vtpm::hcl::{HclReport, ReportType, SNP_REPORT_SIZE};
use az_snp_vtpm::certs::{Vcek, build_cert_chain};
use bytes::Bytes;
use openhttpa_proto::{SevSnpCertificate, SevSnpCertificateType};

use crate::evidence::{AttestationEvidence, SevSnpEvidence};
use crate::provider::TeeProviderError;

/// Size of the HCL header that precedes the hardware report.
const HCL_HEADER_SIZE: usize = 32;

fn err(msg: impl std::fmt::Display) -> TeeProviderError {
    TeeProviderError::QuoteGeneration(msg.to_string())
}

pub fn generate_evidence(report_data: &[u8]) -> Result<AttestationEvidence, TeeProviderError> {
    if report_data.len() != 64 {
        return Err(err("report_data must be 64 bytes"));
    }
    let hcl_bytes = az_cvm_vtpm::vtpm::get_report_with_report_data(report_data)
        .map_err(|e| err(format!("vTPM HCL report failed: {e}")))?;
    let snp_report = snp_report_bytes(&hcl_bytes)?;
    let hcl = HclReport::new(hcl_bytes).map_err(|e| err(format!("invalid HCL report: {e}")))?;
    if hcl.report_type() != ReportType::Snp {
        return Err(err("Azure HCL report is not an SEV-SNP report"));
    }

    Ok(AttestationEvidence::SevSnp(SevSnpEvidence {
        report: Bytes::from(snp_report),
        certificate_table: fetch_certificates()?,
        vcek_cert_uri: None,
        hcl_runtime_data: Some(Bytes::copy_from_slice(hcl.var_data())),
    }))
}

fn snp_report_bytes(hcl_bytes: &[u8]) -> Result<Vec<u8>, TeeProviderError> {
    hcl_bytes
        .get(HCL_HEADER_SIZE..HCL_HEADER_SIZE + SNP_REPORT_SIZE)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| err("HCL report too short for an SNP report"))
}

fn fetch_certificates() -> Result<Vec<SevSnpCertificate>, TeeProviderError> {
    let certs = az_snp_vtpm::imds::get_certs()
        .map_err(|e| err(format!("IMDS THIM request failed: {e}")))?;
    let vcek = Vcek::from_pem(&certs.vcek).map_err(|e| err(format!("invalid VCEK: {e}")))?;
    let chain =
        build_cert_chain(&certs.amd_chain).map_err(|e| err(format!("invalid AMD chain: {e}")))?;

    let der = |cert: &az_snp_vtpm::certs::X509| cert.to_der().map_err(err);
    Ok(vec![
        SevSnpCertificate {
            certificate_type: SevSnpCertificateType::Vcek,
            der: der(&vcek.0)?,
        },
        SevSnpCertificate {
            certificate_type: SevSnpCertificateType::Ask,
            der: der(&chain.ask)?,
        },
        SevSnpCertificate {
            certificate_type: SevSnpCertificateType::Ark,
            der: der(&chain.ark)?,
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_hcl_report() {
        assert!(snp_report_bytes(&[0u8; 100]).is_err());
        assert!(HclReport::new(vec![0u8; 100]).is_err());
    }
}
