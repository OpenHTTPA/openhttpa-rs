// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Infrastructure for fetching and caching TEE attestation collateral.

use std::collections::HashMap;
use std::sync::RwLock;

/// Cache for attestation collateral (certificates, CRLs).
pub struct CollateralCache {
    // Maps URI to raw bytes.
    cache: RwLock<HashMap<String, Vec<u8>>>,
}

impl CollateralCache {
    /// Create a new evidence cache with an empty internal state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Retrieve collateral from cache or fetch it from the URI.
    /// Fetch collateral from a URI, using the cache if available.
    ///
    /// # Errors
    /// Returns an error string if fetching fails or the cache is poisoned.
    pub fn get(&self, uri: &str) -> Result<Vec<u8>, String> {
        {
            let read = self.cache.read().map_err(|e| e.to_string())?;
            if let Some(data) = read.get(uri) {
                return Ok(data.clone());
            }
        }

        // Simulating a remote fetch
        let data = Self::fetch_simulated(uri)?;

        self.cache
            .write()
            .map_err(|e| e.to_string())?
            .insert(uri.to_owned(), data.clone());
        Ok(data)
    }

    fn fetch_simulated(uri: &str) -> Result<Vec<u8>, String> {
        if uri.contains("mock") {
            Ok(vec![0xaa; 1024])
        } else {
            Err(format!("URI not supported in simulation: {uri}"))
        }
    }
}

impl Default for CollateralCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collateral_cache_miss_mock() {
        let cache = CollateralCache::new();
        let result = cache.get("mock://uri").unwrap();
        assert_eq!(result.len(), 1024);
        assert_eq!(result[0], 0xaa);
    }

    #[test]
    fn test_collateral_cache_miss_unsupported() {
        let cache = CollateralCache::default();
        let result = cache.get("https://unsupported");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "URI not supported in simulation: https://unsupported"
        );
    }

    #[test]
    fn test_collateral_cache_hit() {
        let cache = CollateralCache::new();
        let _ = cache.get("mock://first").unwrap();
        let result = cache.get("mock://first").unwrap();
        assert_eq!(result.len(), 1024);
    }
}
