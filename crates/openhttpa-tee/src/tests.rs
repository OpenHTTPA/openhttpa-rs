// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Comprehensive test suite for TEE adapters and provider orchestration.

#[cfg(test)]
use crate::provider::{
    QuoteRequest, TeeConfig, TeeProvider, TeeProviderError, detect_best_provider,
};
use openhttpa_proto::QuoteType;
use std::sync::Arc;

use crate::mock::MockTeeProvider;
use crate::provider::CompositeTeeProvider;

use crate::ENV_MUTEX;

/// Test helper to get a clean TEE config.
fn test_config() -> TeeConfig {
    TeeConfig {
        allow_mock: true,
        preferred_type: None,
    }
}

/// Test normal provider detection and selection.
#[test]
fn test_detect_best_provider() {
    let _guard = ENV_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // SAFETY: ENV_MUTEX is held, ensuring exclusive env access for this test.
    unsafe { std::env::remove_var("OPENHTTPA_TEE_PROVIDER") };
    // SAFETY: ENV_MUTEX is held, ensuring exclusive env access for this test.
    unsafe { std::env::set_var("OPENHTTPA_MOCK_TEE_TYPE", "mock") };

    let config = test_config();

    // Default behavior (Mock)
    let provider = detect_best_provider(&config).expect("Detection failed");
    assert!(provider.is_available());

    // Force specific type via environment
    // SAFETY: ENV_MUTEX is held, ensuring exclusive env access for this test.
    unsafe { std::env::set_var("OPENHTTPA_TEE_PROVIDER", "mock") };
    let provider = detect_best_provider(&config).expect("Force Mock failed");
    assert_eq!(provider.quote_type(), QuoteType::Mock);

    // SAFETY: ENV_MUTEX is held, ensuring exclusive env access for this test.
    unsafe { std::env::remove_var("OPENHTTPA_TEE_PROVIDER") };
}

/// Test failure to detect hardware when Mock is disabled.
#[test]
fn test_fail_when_mock_disabled() {
    let _guard = ENV_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // SAFETY: ENV_MUTEX is held, ensuring exclusive env access for this test.
    unsafe { std::env::remove_var("OPENHTTPA_TEE_PROVIDER") };
    // SAFETY: ENV_MUTEX is held, ensuring exclusive env access for this test.
    unsafe { std::env::set_var("OPENHTTPA_MOCK_TEE_TYPE", "mock") };

    let config = TeeConfig {
        allow_mock: false,
        preferred_type: None,
    };

    // Ensure no hardware features are enabled for this test to pass reliably in any environment
    // OR ensure OPENHTTPA_TEE_PROVIDER is not set.
    // SAFETY: ENV_MUTEX is held, ensuring exclusive env access for this test.
    unsafe { std::env::remove_var("OPENHTTPA_TEE_PROVIDER") };

    let res = detect_best_provider(&config);

    // If we are on real TEE hardware this might return Ok, but in standard CI it should return Err
    if !std::path::Path::new("/dev/tdx-guest").exists()
        && !std::path::Path::new("/dev/sev-guest").exists()
        && !std::path::Path::new("/dev/nvidia0").exists()
    {
        assert!(matches!(res, Err(TeeProviderError::NotAvailable(_))));
    }
}

/// Test composite provider orchestration.
#[test]
fn test_composite_provider() {
    let _guard = ENV_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // SAFETY: ENV_MUTEX is held, ensuring exclusive env access for this test.
    unsafe { std::env::remove_var("OPENHTTPA_MOCK_TEE_TYPE") };
    // SAFETY: ENV_MUTEX is held, ensuring exclusive env access for this test.
    unsafe { std::env::remove_var("OPENHTTPA_MOCK_FAILURE") };

    let p1 = Arc::new(MockTeeProvider::default());
    let p2 = Arc::new(MockTeeProvider::default());

    let composite = CompositeTeeProvider::new(vec![p1, p2]);
    assert!(composite.is_available());

    let req = QuoteRequest {
        report_data: [0xaa; 64],
    };

    let quotes = composite
        .generate_quotes(&req)
        .expect("Composite quotes failed");
    assert_eq!(quotes.len(), 2);
    assert_eq!(quotes[0].qudd.as_ref(), &[0xaa; 64]);
}

/// Test global impact analysis: Ensure TEE provider errors are properly classified.
#[test]
fn test_error_classification() {
    let err = TeeProviderError::Driver("low level error".to_owned());
    assert!(err.to_string().contains("hardware driver error"));

    let err = TeeProviderError::NotAvailable("no hardware".to_owned());
    assert!(err.to_string().contains("TEE SDK not available"));
}

/// Test edge case: preferred type mismatch.
#[test]
fn test_preferred_type_mismatch() {
    let _guard = ENV_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // SAFETY: ENV_MUTEX is held, ensuring exclusive env access for this test.
    unsafe { std::env::remove_var("OPENHTTPA_TEE_PROVIDER") };

    let config = TeeConfig {
        allow_mock: true,
        preferred_type: Some("nonexistent_tee".to_owned()),
    };

    let res = detect_best_provider(&config);
    assert!(res.is_err(), "Should fail on unknown preferred type");
}

/// Test ZK-Compressed TEE Provider (ZAA) if feature is enabled.
#[cfg(feature = "zaa")]
#[test]
fn test_zk_compressed_provider() {
    let p1 = Arc::new(MockTeeProvider::default());
    let compressed = crate::provider::ZkCompressedTeeProvider::new(p1);

    assert!(compressed.is_available());
    assert_eq!(compressed.quote_type(), QuoteType::ZkCompressed);

    let req = QuoteRequest {
        report_data: [0xbb; 64],
    };

    // Test the generation flow. In unit tests we rely on the Mock prover in openhttpa_zk
    // failing safely or producing a dummy receipt. However, since the prover requires
    // RISC Zero guest compilation which isn't available in standard `cargo test` unless
    // `testing` mock is forced, we just verify the type checking.
    // If the mock prover is enabled, this will succeed. Otherwise, it will fail cleanly.
    let result = compressed.generate_quote(&req);
    match result {
        Ok(quote) => {
            assert_eq!(quote.quote_type, QuoteType::ZkCompressed);
            assert_eq!(quote.qudd.as_ref(), &[0xbb; 64]);
        }
        Err(e) => {
            // If RISC Zero prover fails, that's expected without mock config
            assert!(e.to_string().contains("Enclave") || e.to_string().contains("ZK-proving"));
        }
    }
}

/// Test multi-vendor federation via `detect_all_providers`.
#[test]
fn test_detect_all_providers_federation() {
    let _guard = ENV_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // SAFETY: ENV_MUTEX is held.
    unsafe { std::env::remove_var("OPENHTTPA_TEE_PROVIDER") };

    let config = test_config(); // allows mock

    let composite =
        crate::provider::detect_all_providers(&config).expect("Federation detection failed");
    assert!(composite.is_available());

    let req = QuoteRequest {
        report_data: [0xcc; 64],
    };
    let quotes = composite
        .generate_quotes(&req)
        .expect("Failed to generate federated quotes");
    assert!(!quotes.is_empty(), "Must return at least one quote");
}
