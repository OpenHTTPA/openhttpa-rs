// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Hardened collateral fetcher for remote attestation.
//!
//! This module provides a secure mechanism to fetch attestation collateral
//! (PCK certs, VCEK certs, RIM reports) from remote URIs while protecting
//! the verifier against SSRF, `DoS`, and slow-loris attacks.

use reqwest::{Client, StatusCode};
use std::time::Duration;
use thiserror::Error;

/// Maximum allowed size for a single collateral artifact (1MB).
pub const MAX_COLLATERAL_SIZE: usize = 1024 * 1024;
/// Timeout for collateral fetching.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

#[non_exhaustive]
#[derive(Debug, Error)]
pub enum FetchError {
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("SSRF protection: unauthorized URI: {0}")]
    UnauthorizedUri(String),
    #[error("artifact too large: {0} bytes")]
    TooLarge(usize),
    #[error("fetch timed out")]
    Timeout,
    #[error("unexpected status code: {0}")]
    Status(StatusCode),
}

/// A hardened fetcher for attestation collateral.
pub struct CollateralFetcher {
    client: Client,
    /// List of allowed host domains for collateral (e.g. intel.com, amd.com, nvidia.com).
    allowed_domains: Vec<String>,
}

impl CollateralFetcher {
    /// Create a new fetcher with default security limits.
    ///
    /// # Panics
    /// Panics if the `reqwest` client cannot be built (e.g. due to TLS configuration errors).
    #[must_use]
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(FETCH_TIMEOUT)
            .user_agent("openhttpa-attestation/0.1.0")
            .use_rustls_tls()
            // SSRF-REDIRECT-01: Disable automatic HTTP redirects.  The allowlist
            // check validates only the initial URL; following a redirect to a
            // cloud metadata endpoint (169.254.169.254) or private network would
            // bypass that check entirely.  Attestation collateral endpoints are
            // well-known HTTPS APIs that never need to redirect.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to initialize hardened fetcher client");

        // SEC-08: The loopback address is only permitted in test/mock builds.
        // In production the fetcher must reach only known vendor endpoints over
        // HTTPS, never localhost (which could be a malicious local server).
        #[cfg(any(test, feature = "mock"))]
        let loopback = vec!["127.0.0.1".to_owned()];
        #[cfg(not(any(test, feature = "mock")))]
        let loopback: Vec<String> = vec![];

        Self {
            client,
            allowed_domains: [
                vec![
                    ".trustauthority.intel.com".to_owned(),
                    ".kdsintpk.amd.com".to_owned(),
                    ".nras.nvidia.com".to_owned(),
                ],
                loopback,
            ]
            .concat(),
        }
    }

    /// Fetch collateral from a URI with strict security checks.
    ///
    /// # Errors
    /// Returns [`FetchError`] if the URI is unauthorized, the artifact is too large,
    /// or a network error occurs.
    pub async fn fetch(&self, uri: &str) -> Result<Vec<u8>, FetchError> {
        // 1. SSRF Protection: Validate URI scheme and host
        let url =
            reqwest::Url::parse(uri).map_err(|_| FetchError::UnauthorizedUri(uri.to_owned()))?;

        if url.scheme() != "https" && url.host_str() != Some("127.0.0.1") {
            return Err(FetchError::UnauthorizedUri(
                "only HTTPS URIs are allowed".to_owned(),
            ));
        }

        if let Some(host) = url.host_str() {
            let is_allowed = self
                .allowed_domains
                .iter()
                .any(|d| host == d.trim_start_matches('.') || host.ends_with(d));
            if !is_allowed {
                return Err(FetchError::UnauthorizedUri(format!(
                    "domain {host} is not in allowlist"
                )));
            }
        }

        // 2. Perform the fetch with size limits
        let mut response = self.client.get(url).send().await?;

        if response.status() != StatusCode::OK {
            return Err(FetchError::Status(response.status()));
        }

        // Check Content-Length header early
        if let Some(len) = response.content_length()
            && len > MAX_COLLATERAL_SIZE as u64
        {
            #[allow(clippy::cast_possible_truncation)]
            return Err(FetchError::TooLarge(len as usize));
        }

        // 3. Accumulate bytes with size guard
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > MAX_COLLATERAL_SIZE {
                return Err(FetchError::TooLarge(body.len() + chunk.len()));
            }
            body.extend_from_slice(&chunk);
        }

        Ok(body)
    }
}

/// Thread-safe in-memory cache for attestation collateral.
pub struct CollateralCache {
    cache: dashmap::DashMap<String, (std::time::SystemTime, Vec<u8>)>,
    ttl: Duration,
}

impl CollateralCache {
    /// Create a new cache with a specific TTL (default 24h).
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: dashmap::DashMap::new(),
            ttl,
        }
    }

    /// Retrieve an artifact from the cache if it hasn't expired.
    #[must_use]
    pub fn get(&self, uri: &str) -> Option<Vec<u8>> {
        let entry = self.cache.get(uri)?;
        let (expiry, data) = entry.value();
        if *expiry > std::time::SystemTime::now() {
            Some(data.clone())
        } else {
            drop(entry);
            self.cache.remove(uri);
            None
        }
    }

    /// Store an artifact in the cache.
    pub fn insert(&self, uri: String, data: Vec<u8>) {
        let expiry = std::time::SystemTime::now() + self.ttl;
        self.cache.insert(uri, (expiry, data));
    }
}

impl Default for CollateralCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(86400))
    }
}

impl Default for CollateralFetcher {
    fn default() -> Self {
        Self::new()
    }
}
