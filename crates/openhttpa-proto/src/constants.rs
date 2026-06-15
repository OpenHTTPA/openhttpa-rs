// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Protocol string constants.

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
