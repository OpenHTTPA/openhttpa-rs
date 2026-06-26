// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Integration tests for RAVS (Remote Attestation Verification Service).

#[cfg(test)]
use crate::composite::CompositeVerifier;
use crate::mock_verifier::MockVerifier;
use crate::verifier::QuoteVerifier;
use bytes::Bytes;
use openhttpa_proto::{AttestQuote, QuoteType};
use openhttpa_tee::{QuoteRequest, mock::MockTeeProvider, provider::TeeProvider};

/// Test helper to create a mock composite quote bundle.
fn create_mock_bundle(rd: &[u8; 64]) -> Vec<AttestQuote> {
    // SAFETY: single-threaded test context.
    unsafe { std::env::set_var("OPENHTTPA_ALLOW_MOCK_HARDWARE", "1") };

    let provider = MockTeeProvider::with_override(QuoteType::Tdx);

    // 1. Host TEE Quote (TDX)
    let q1 = provider
        .generate_quote(&QuoteRequest { report_data: *rd })
        .unwrap();

    // 2. GPU Quote
    let provider = MockTeeProvider::with_override(QuoteType::NvidiaGpu);
    let q2 = provider
        .generate_quote(&QuoteRequest { report_data: *rd })
        .unwrap();

    vec![q1, q2]
}

#[tokio::test]
async fn test_composite_verification_flow() {
    let rd = [0x99u8; 64];
    let bundle = create_mock_bundle(&rd);

    // Setup Composite Verifier
    let mut verifier = CompositeVerifier::new();
    verifier.add_verifier(&QuoteType::Tdx, Box::new(MockVerifier::default()));
    verifier.add_verifier(&QuoteType::NvidiaGpu, Box::new(MockVerifier::default()));

    // Verify bundle
    let result = verifier
        .verify_bundle(&bundle, &rd)
        .await
        .expect("Verification failed");

    // Assert results
    assert_eq!(result.claims.hwmodel.as_deref().unwrap(), "Intel TDX");
    assert_eq!(result.secondary.len(), 1);
    assert_eq!(
        result.secondary[0].claims.hwmodel.as_ref().unwrap(),
        "NVIDIA H100"
    );
}

#[tokio::test]
async fn test_composite_rejection_on_mismatched_report_data() {
    let rd = [0x11u8; 64];
    let bundle = create_mock_bundle(&rd);

    let mut verifier = CompositeVerifier::new();
    verifier.add_verifier(&QuoteType::Tdx, Box::new(MockVerifier::default()));
    verifier.add_verifier(&QuoteType::NvidiaGpu, Box::new(MockVerifier::default()));

    // Verify with WRONG report data
    let wrong_rd = [0x22u8; 64];
    let res = verifier.verify_bundle(&bundle, &wrong_rd).await;

    assert!(res.is_err(), "Should reject mismatched report data");
}

#[tokio::test]
async fn test_composite_fail_fast_on_one_bad_quote() {
    let rd = [0x33u8; 64];
    let mut bundle = create_mock_bundle(&rd);

    // Tamper with the GPU quote
    bundle[1].raw = Bytes::from_static(b"corrupted-data");

    let mut verifier = CompositeVerifier::new();
    verifier.add_verifier(&QuoteType::Tdx, Box::new(MockVerifier::default()));
    verifier.add_verifier(&QuoteType::NvidiaGpu, Box::new(MockVerifier::default()));

    let res = verifier.verify_bundle(&bundle, &rd).await;
    assert!(res.is_err(), "Should fail if any quote is invalid");
}

#[tokio::test]
async fn test_tpm_verification_with_collateral() {
    use crate::tpm_verifier::TpmVerifier;

    let rd = [0x77u8; 64];
    let quote = AttestQuote {
        quote_type: QuoteType::Tpm,
        format: openhttpa_proto::QuoteFormat::default(),
        raw: Bytes::from_static(b"mock-tpm-quote"),
        qudd: Bytes::copy_from_slice(&rd),
        collateral_uris: vec!["https://127.0.0.1/aik.cert".to_owned()],
    };

    let verifier = TpmVerifier::default();

    // This will fail because no server is running at 127.0.0.1,
    // but it verifies that the fetcher is being called.
    let res = verifier.verify(&quote, &rd).await;
    assert!(res.is_err());
    if let Err(crate::verifier::VerificationError::NetworkError(m)) = res {
        assert!(m.contains("failed to fetch AIK collateral"));
    }
}
