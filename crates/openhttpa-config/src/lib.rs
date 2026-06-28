// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Global configuration and constants for the OpenHTTPA workspace.

// Protocol versions
pub const PROTOCOL_VERSION_V1: &str = "httpa/1";
pub const PROTOCOL_VERSION_V2: &str = "openhttpa";

// Cipher suites
pub const CIPHER_SUITE_X25519_ML_KEM768_AES256GCM_SHA384: &str =
    "X25519_ML_KEM768_AES256GCM_SHA384";
pub const CIPHER_SUITE_P384_ML_KEM1024_AES256GCM_SHA384: &str = "P384_ML_KEM1024_AES256GCM_SHA384";
pub const CIPHER_SUITE_X25519_AES256GCM_SHA384: &str = "X25519_AES256GCM_SHA384";
pub const CIPHER_SUITE_P256_AES256GCM_SHA256: &str = "P256_AES256GCM_SHA256";
pub const CIPHER_SUITE_X25519_CHACHA20POLY1305_SHA256: &str = "X25519_CHACHA20POLY1305_SHA256";

// TEE Quote types
pub const QUOTE_TYPE_SGX: &str = "sgx";
pub const QUOTE_TYPE_TDX: &str = "tdx";
pub const QUOTE_TYPE_SEV_SNP: &str = "sev_snp";
pub const QUOTE_TYPE_TRUSTZONE: &str = "trustzone";
pub const QUOTE_TYPE_TPM: &str = "tpm";
pub const QUOTE_TYPE_NVIDIA_GPU: &str = "nvidia_gpu";
pub const QUOTE_TYPE_AWS_NITRO: &str = "aws_nitro";
pub const QUOTE_TYPE_ZK_COMPRESSED: &str = "zk_compressed";
pub const QUOTE_TYPE_MOCK: &str = "mock";

// Environment variables
/// Environment variable to override the default TEE provider.
pub const ENV_TEE_PROVIDER: &str = "OPENHTTPA_TEE_PROVIDER";

/// Environment variable to specify the mock TEE type (e.g., "mock", "tdx", "tpm").
pub const ENV_MOCK_TEE_TYPE: &str = "OPENHTTPA_MOCK_TEE_TYPE";

/// Environment variable to induce mock failures for testing (e.g., "driver").
pub const ENV_MOCK_FAILURE: &str = "OPENHTTPA_MOCK_FAILURE";

/// Environment variable to allow mock hardware (1 or true).
pub const ENV_ALLOW_MOCK_HARDWARE: &str = "OPENHTTPA_ALLOW_MOCK_HARDWARE";

/// Environment variable to allow deprecated ciphers.
pub const ENV_ALLOW_DEPRECATED_CIPHERS: &str = "OPENHTTPA_ALLOW_DEPRECATED_CIPHERS";
