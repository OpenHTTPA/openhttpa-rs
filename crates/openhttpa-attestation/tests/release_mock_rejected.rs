#![cfg(not(debug_assertions))]

use bytes::Bytes;
use openhttpa_attestation::{MockVerifier, QuoteVerifier, VerificationError};
use openhttpa_proto::{AttestQuote, QuoteFormat, QuoteType};

#[tokio::test]
async fn release_mock_verifier_rejects_mock_quotes() {
    let report_data = [0x5au8; 64];
    let quote = AttestQuote {
        quote_type: QuoteType::Mock,
        format: QuoteFormat::Raw,
        raw: Bytes::from_static(b"mock quote"),
        qudd: Bytes::copy_from_slice(&report_data),
        collateral_uris: vec![],
    };

    let result = MockVerifier::default().verify(&quote, &report_data).await;
    assert!(matches!(
        result,
        Err(VerificationError::PolicyViolation(message)) if message.contains("release")
    ));
}
