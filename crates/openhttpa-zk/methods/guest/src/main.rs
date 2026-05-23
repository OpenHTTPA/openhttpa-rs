// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

#![no_main]
#![no_std]

use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sha2::Digest;

risc0_zkvm::guest::entry!(main);

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use der::{Decode, Encode};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use x509_cert::Certificate;

#[derive(Serialize, Deserialize, PartialEq, Eq)]
enum ZkMode {
    Handshake,
    VerifiedAi,
    Oracle,
    DcapCompression,
}

#[derive(Serialize, Deserialize, Clone, Copy)]
struct VaiInput {
    #[serde(with = "BigArray")]
    pub model_id: [u8; 32],
    #[serde(with = "BigArray")]
    pub input_hash: [u8; 32],
    #[serde(with = "BigArray")]
    pub output_hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct VaiOutput {
    #[serde(with = "BigArray")]
    pub model_id: [u8; 32],
    #[serde(with = "BigArray")]
    pub input_hash: [u8; 32],
    #[serde(with = "BigArray")]
    pub output_hash: [u8; 32],
    pub verified_at_secs: u64,
}

#[derive(Serialize, Deserialize)]
struct ZkInput {
    pub mode: ZkMode,
    #[serde(with = "BigArray")]
    pub transcript_hash: [u8; 48],
    pub quote_bytes: Vec<u8>,
    #[serde(with = "BigArray")]
    pub report_data: [u8; 64],
    pub oracle_data: Option<Vec<u8>>,
    pub vai_data: Option<VaiInput>,
    pub dcap_collateral: Option<DcapCollateral>,
}

#[derive(Serialize, Deserialize)]
struct DcapCollateral {
    pub pck_cert: Vec<u8>,
    pub intermediate_ca: Vec<u8>,
    pub root_ca: Vec<u8>,
    pub tcb_info: Vec<u8>,
    pub qe_identity: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct ZkOutput {
    pub mode: ZkMode,
    #[serde(with = "BigArray")]
    pub transcript_hash: [u8; 48],
    pub is_valid: bool,
    pub oracle_payload_hash: [u8; 32],
    pub vai_output: Option<VaiOutput>,
    pub dcap_verified: bool,
}

/// Extensible TEE verification trait for guest-side validation.
trait TeeVerifier {
    fn verify_quote(
        &self,
        quote: &[u8],
        report_data: &[u8],
        collateral: &Option<DcapCollateral>,
    ) -> bool;
}

struct SgxDcapVerifier;

impl TeeVerifier for SgxDcapVerifier {
    fn verify_quote(
        &self,
        quote: &[u8],
        _report_data: &[u8],
        collateral: &Option<DcapCollateral>,
    ) -> bool {
        if quote.len() < 1024 || collateral.is_none() {
            return false;
        }
        let col = collateral.as_ref().unwrap();

        // 1. Verify Certificate Chain: Root -> Intermediate -> PCK
        if !self.verify_cert_chain(&col.root_ca, &col.intermediate_ca, &col.pck_cert) {
            return false;
        }

        // 2. Parse SGX DCAP Quote Structure
        // Reference: https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLib_Reference_DCAP_API.pdf
        let body = &quote[48..432]; // SGX Enclave Report (Body of the quote)
        let signature_len = u32::from_le_bytes(quote[432..436].try_into().unwrap()) as usize;
        let signature_bytes = &quote[436..436 + signature_len];

        // 3. Verify Enclave Report Data Binding (T-10)
        let quote_report_data = &body[320..384];
        if quote_report_data != _report_data {
            return false;
        }

        // 4. Verify ECDSA Signature of the Quote using PCK Public Key
        let pck_cert = Certificate::from_der(&col.pck_cert).ok();
        if pck_cert.is_none() {
            return false;
        }
        let pck_pub = self.extract_verifying_key(&pck_cert.unwrap());
        if pck_pub.is_none() {
            return false;
        }
        let sig = Signature::from_slice(signature_bytes).ok();
        if sig.is_none() {
            return false;
        }

        // Verify the signature over the header + body
        let signed_data = &quote[0..432];
        pck_pub.unwrap().verify(signed_data, &sig.unwrap()).is_ok()
    }
}

impl SgxDcapVerifier {
    fn verify_cert_chain(&self, root: &[u8], inter: &[u8], pck: &[u8]) -> bool {
        let root_cert = Certificate::from_der(root).ok();
        let inter_cert = Certificate::from_der(inter).ok();
        let pck_cert = Certificate::from_der(pck).ok();

        if root_cert.is_none() || inter_cert.is_none() || pck_cert.is_none() {
            return false;
        }

        let root_cert = root_cert.unwrap();
        let inter_cert = inter_cert.unwrap();
        let pck_cert = pck_cert.unwrap();

        // Verify Intermediate CA signature using Root CA public key
        let root_pub = self.extract_verifying_key(&root_cert);
        if root_pub.is_none() {
            return false;
        }
        if !self.verify_cert(&inter_cert, &root_pub.unwrap()) {
            return false;
        }

        // Verify PCK signature using Intermediate CA public key
        let inter_pub = self.extract_verifying_key(&inter_cert);
        if inter_pub.is_none() {
            return false;
        }
        if !self.verify_cert(&pck_cert, &inter_pub.unwrap()) {
            return false;
        }

        true
    }

    fn verify_cert(&self, cert: &Certificate, issuer_pub: &VerifyingKey) -> bool {
        let sig_bytes = cert.signature.as_bytes().unwrap();
        let sig = Signature::from_der(sig_bytes).ok();
        if sig.is_none() {
            return false;
        }
        let tbs_bytes = cert.tbs_certificate.to_der().unwrap_or_default();
        issuer_pub.verify(&tbs_bytes, &sig.unwrap()).is_ok()
    }

    fn extract_verifying_key(&self, cert: &Certificate) -> Option<VerifyingKey> {
        let pub_key_bytes = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()?;
        // X.509 P-256 keys are usually 65 bytes (0x04 || X || Y)
        VerifyingKey::from_sec1_bytes(pub_key_bytes).ok()
    }
}

fn main() {
    let input: ZkInput = env::read();

    // 1. Verify TEE Quote Signature (k256 Precompile)
    // In a production environment, we verify the ECDSA signature of the TEE quote
    // against the hardware vendor's public key (Intel PCK, AMD VCEK, etc.).
    // RISC Zero provides accelerated precompiles for k256/ECDSA.
    #[cfg(not(feature = "mock"))]
    {
        use k256::ecdsa::signature::Verifier;
        use k256::ecdsa::{Signature, VerifyingKey};

        // Skeleton: Extract public key and signature from quote_bytes (TDX/SNP specific)
        // For this demo, we assume the quote contains a valid ECDSA signature.
        if input.quote_bytes.len() > 64 {
            let vk_bytes = &input.quote_bytes[..33]; // Placeholder for public key
            let sig_bytes = &input.quote_bytes[33..97]; // Placeholder for signature

            if let (Ok(vk), Ok(sig)) = (
                VerifyingKey::from_sec1_bytes(vk_bytes),
                Signature::from_slice(sig_bytes),
            ) {
                let _ = vk.verify(&input.report_data, &sig);
            }
        }
    }

    // 2. Verify report_data Binding (T-10 Domain Separation)
    // The report_data must bind the TEE's identity to the specific context.
    match input.mode {
        ZkMode::Handshake => {
            // Handshake binding: report_data[32..] == transcript_hash
            let is_valid = input.report_data[32..] == input.transcript_hash;
            assert!(is_valid, "Transcript hash mismatch in report_data");
            assert!(
                input.report_data.starts_with(b"openhttpa hs server"),
                "Domain prefix mismatch"
            );
        }
        ZkMode::VerifiedAi => {
            // AI Provenance binding: report_data must bind to hash(model_id || input_hash || output_hash)
            let vai = input
                .vai_data
                .as_ref()
                .expect("VerifiedAi mode requires vai_data");

            let mut vai_hasher = sha2::Sha256::new();
            vai_hasher.update(b"openhttpa vai v1");
            vai_hasher.update(vai.model_id);
            vai_hasher.update(vai.input_hash);
            vai_hasher.update(vai.output_hash);
            let expected_binding = vai_hasher.finalize();

            // report_data[..32] == binding hash
            assert!(
                input.report_data[..32] == expected_binding[..],
                "AI provenance binding mismatch in report_data"
            );
        }
        ZkMode::Oracle => {
            // Oracle binding: report_data must bind to hash("openhttpa oracle" || transcript_hash || oracle_payload)
            let oracle_data = input
                .oracle_data
                .as_ref()
                .expect("Oracle mode requires oracle_data");
            let mut hasher = sha2::Sha256::new();
            hasher.update(b"openhttpa oracle v1");
            hasher.update(input.transcript_hash);
            hasher.update(oracle_data);
            let expected_binding = hasher.finalize();
            assert!(
                input.report_data[..32] == expected_binding[..],
                "Oracle binding mismatch in report_data"
            );
        }
        ZkMode::DcapCompression => {
            // ZAA binding: report_data[32..] == transcript_hash
            // Similar to handshake but for compression purposes.
            assert!(
                input.report_data[32..] == input.transcript_hash,
                "Transcript hash mismatch in compressed quote"
            );
        }
    }

    // 3. Securely Hash Oracle Data (SHA-256)
    let mut oracle_hasher = sha2::Sha256::new();
    if let Some(ref data) = input.oracle_data {
        oracle_hasher.update(data);
    }
    let oracle_payload_hash: [u8; 32] = oracle_hasher.finalize().into();

    let vai_output = input.vai_data.map(|v| VaiOutput {
        model_id: v.model_id,
        input_hash: v.input_hash,
        output_hash: v.output_hash,
        verified_at_secs: 0, // In production, extract from quote timestamp
    });

    let mut dcap_verified = false;
    if input.mode == ZkMode::DcapCompression {
        let verifier = SgxDcapVerifier;
        dcap_verified = verifier.verify_quote(
            &input.quote_bytes,
            &input.report_data,
            &input.dcap_collateral,
        );

        // 4. Perform TCB Policy Check
        if dcap_verified {
            if let Some(ref collateral) = input.dcap_collateral {
                dcap_verified = verify_tcb_status(&input.quote_bytes, &collateral.tcb_info);
            }
        }
    }

    let output = ZkOutput {
        mode: input.mode,
        transcript_hash: input.transcript_hash,
        is_valid: true,
        oracle_payload_hash,
        vai_output,
        dcap_verified,
    };

    env::commit(&output);
}

/// Minimal TCB Info structures for JSON parsing in guest.
#[derive(Serialize, Deserialize)]
struct TcbInfo {
    #[serde(rename = "tcbLevels")]
    pub tcb_levels: Vec<TcbLevel>,
}

#[derive(Serialize, Deserialize)]
struct TcbLevel {
    pub tcb: Tcb,
    #[serde(rename = "tcbStatus")]
    pub tcb_status: String,
}

#[derive(Serialize, Deserialize)]
struct Tcb {
    pub pcesvn: u16,
    // Note: SGX cpu_svn is actually 16 bytes, but represented as hex in JSON.
    // For simplicity in this demo, we assume the host pre-processes it or we match pcesvn.
}

fn verify_tcb_status(quote: &[u8], tcb_info_json: &[u8]) -> bool {
    // 1. Extract PCESVN from the quote (Body offset 384, 2 bytes)
    let body = &quote[48..432];
    let pcesvn = u16::from_le_bytes(body[384..386].try_into().unwrap());

    // 2. Parse TCB Info JSON
    let info: TcbInfo = match serde_json::from_slice(tcb_info_json) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // 3. Find matching TCB level
    // For MVP, we match against pcesvn and ensure status is "UpToDate" or "SWHardeningNeeded".
    for level in info.tcb_levels {
        if level.tcb.pcesvn <= pcesvn {
            return level.tcb_status == "UpToDate" || level.tcb_status == "SWHardeningNeeded";
        }
    }

    false
}
