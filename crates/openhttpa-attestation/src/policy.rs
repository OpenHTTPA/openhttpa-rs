// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use crate::verifier::{PolicyEngine, VerificationError, VerificationResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// A simple rule-based policy for attestation.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SimplePolicy {
    /// List of allowed hardware models.
    pub allowed_hwmodels: Vec<String>,
    /// Minimum TCB version string.
    pub min_hwversion: Option<String>,
    /// Whether to allow debug builds.
    pub allow_debug: bool,
    /// Minimum Security Version.
    pub min_security_version: Option<u16>,
}

#[async_trait]
impl PolicyEngine for SimplePolicy {
    async fn evaluate(&self, result: &VerificationResult) -> Result<(), VerificationError> {
        // SEC-05: In non-debug (release) builds, `allow_debug = true` is never
        // legitimate.  Panic loudly rather than silently accepting a debug TEE
        // quote in production.
        #[cfg(not(debug_assertions))]
        if self.allow_debug {
            panic!(
                "SEC-05: SimplePolicy.allow_debug = true is forbidden in release builds. \
                 Set allow_debug = false or use a test/development build."
            );
        }

        // 1. Check debug status
        result.reject_debug_builds(self.allow_debug)?;

        // 2. Check hardware model
        if !self.allowed_hwmodels.is_empty() {
            if let Some(ref model) = result.claims.hwmodel {
                if !self.allowed_hwmodels.contains(model) {
                    return Err(VerificationError::PolicyViolation(format!(
                        "unauthorized hardware model: {model}"
                    )));
                }
            } else {
                return Err(VerificationError::PolicyViolation(
                    "hardware model claim missing".to_owned(),
                ));
            }
        }

        // 3. Check hardware version (TCB)
        if let Some(ref min_v) = self.min_hwversion {
            if let Some(ref v) = result.claims.hwversion {
                if !is_version_at_least(v, min_v) {
                    return Err(VerificationError::PolicyViolation(format!(
                        "hardware version {v} is below minimum {min_v}"
                    )));
                }
            }
        }

        // 4. Check Security Version
        if let Some(min_sv) = self.min_security_version {
            if let Some(sv) = result.claims.security_version {
                if sv < min_sv {
                    return Err(VerificationError::PolicyViolation(format!(
                        "security version {sv} is below minimum {min_sv}"
                    )));
                }
            } else {
                return Err(VerificationError::PolicyViolation(
                    "security version claim missing".to_owned(),
                ));
            }
        }

        Ok(())
    }
}

/// Helper to compare version strings (e.g. "1.10.1") numerically.
fn is_version_at_least(v: &str, min_v: &str) -> bool {
    let v_parts: Vec<u32> = v.split('.').filter_map(|s| s.parse().ok()).collect();
    let min_parts: Vec<u32> = min_v.split('.').filter_map(|s| s.parse().ok()).collect();

    for (a, b) in v_parts.iter().zip(min_parts.iter()) {
        if a > b {
            return true;
        }
        if a < b {
            return false;
        }
    }
    v_parts.len() >= min_parts.len()
}
