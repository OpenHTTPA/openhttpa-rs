// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Azure `OpenHCL` paravisor report-data binding, shared by the SEV-SNP and TDX
//! verifiers.
//!
//! On Azure confidential VMs the hardware report (SNP report or TD report) is
//! produced by the paravisor, not by the guest. The paravisor writes
//! `SHA-256(runtime claims JSON)` into the first 32 bytes of the hardware
//! `REPORTDATA` field and places the guest-supplied 64-byte report data,
//! hex-encoded, in the JSON's `user-data` member. Verifying both links proves
//! the hardware-signed report covers the handshake binding.

use crate::verifier::VerificationError;

/// Check the Azure paravisor binding between a hardware `REPORTDATA` field,
/// the HCL runtime-claims JSON, and the expected handshake report data.
///
/// # Errors
/// [`VerificationError::PolicyViolation`] if the hash or `user-data` does not
/// match, [`VerificationError::MalformedQuote`] if the JSON cannot be parsed.
pub fn verify_azure_hcl_binding(
    embedded: &[u8; 64],
    runtime_data: &[u8],
    expected: &[u8; 64],
) -> Result<(), VerificationError> {
    use sha2::{Digest, Sha256};

    let violation = |m: &str| VerificationError::PolicyViolation(m.to_owned());
    if Sha256::digest(runtime_data).as_slice() != &embedded[..32] {
        return Err(violation(
            "Azure HCL runtime data does not match hardware report_data",
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

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn embedded_for(runtime: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&Sha256::digest(runtime));
        out
    }

    #[test]
    fn binding_accepts_matching_user_data() {
        let expected = [7u8; 64];
        let runtime = format!("{{\"user-data\":\"{}\"}}", hex::encode(expected));
        verify_azure_hcl_binding(
            &embedded_for(runtime.as_bytes()),
            runtime.as_bytes(),
            &expected,
        )
        .unwrap();
    }

    #[test]
    fn binding_rejects_wrong_hash_wrong_user_data_and_missing_field() {
        let expected = [7u8; 64];
        let runtime = format!("{{\"user-data\":\"{}\"}}", hex::encode(expected));
        let mut bad = embedded_for(runtime.as_bytes());
        bad[0] ^= 1;
        assert!(verify_azure_hcl_binding(&bad, runtime.as_bytes(), &expected).is_err());

        let other = [8u8; 64];
        assert!(
            verify_azure_hcl_binding(
                &embedded_for(runtime.as_bytes()),
                runtime.as_bytes(),
                &other
            )
            .is_err()
        );

        let missing = b"{}";
        assert!(verify_azure_hcl_binding(&embedded_for(missing), missing, &expected).is_err());
    }
}
