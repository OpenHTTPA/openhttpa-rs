// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation

use alloy::providers::ProviderBuilder;
use alloy::transports::http::reqwest::Url;
use thiserror::Error;

/// Errors returned by [`IdentityResolver`].
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum IdentityResolverError {
    /// The URL provided to the constructor is not a valid HTTP URL.
    #[error("invalid RPC URL: {0}")]
    InvalidUrl(String),

    /// On-chain DID resolution is not yet implemented.
    ///
    /// The smart-contract interaction layer is still under development.
    /// Do **not** route real production traffic through this resolver until
    /// this variant is no longer returned.
    #[error(
        "on-chain DID resolution is not implemented — the smart-contract \
         integration is pending (DID: {did})"
    )]
    NotImplemented { did: String },

    /// The RPC call to the Ethereum node failed.
    #[error("RPC transport error: {0}")]
    RpcError(String),

    /// The resolved value was not a valid hex-encoded MRENCLAVE measurement.
    #[error("invalid MRENCLAVE returned for DID '{did}': {reason}")]
    InvalidMrenclave { did: String, reason: String },
}

/// Resolves DIDs to MRENCLAVE measurements via the OpenHTTPA on-chain registry.
///
/// # Production Readiness
///
/// The smart-contract interaction is **not yet implemented**.  `resolve_did`
/// currently returns [`IdentityResolverError::NotImplemented`] for every input.
/// Do not use this resolver to gate security decisions until the on-chain
/// call is wired up and audited.
pub struct IdentityResolver {
    rpc_url: Url,
}

impl IdentityResolver {
    /// Create a resolver pointing at the given Ethereum JSON-RPC endpoint.
    ///
    /// # Errors
    /// Returns [`IdentityResolverError::InvalidUrl`] if `rpc_url` cannot be parsed.
    pub fn new(rpc_url: &str) -> Result<Self, IdentityResolverError> {
        Ok(Self {
            rpc_url: rpc_url
                .parse()
                .map_err(|e: url::ParseError| IdentityResolverError::InvalidUrl(e.to_string()))?,
        })
    }

    /// Resolve a DID to its registered MRENCLAVE measurement.
    ///
    /// # Errors
    ///
    /// Currently always returns [`IdentityResolverError::NotImplemented`].
    /// Once the smart-contract call is implemented, this method will return
    /// [`IdentityResolverError::RpcError`] on network failures and
    /// [`IdentityResolverError::InvalidMrenclave`] on malformed chain data.
    pub async fn resolve_did(&self, did: &str) -> Result<String, IdentityResolverError> {
        // Construct the provider so the dependency is exercised and the URL
        // is reachable, but do NOT use any return value as a trusted MRENCLAVE.
        let _provider = ProviderBuilder::new().connect_http(self.rpc_url.clone());

        tracing::warn!(
            did = %did,
            rpc_url = %self.rpc_url,
            "resolve_did called but on-chain smart-contract integration is not \
             implemented — returning NotImplemented error to prevent silent \
             security bypass"
        );

        // SEC-01: Returning a hardcoded success value here would silently accept
        // any DID as valid, making the identity check a no-op.  We MUST fail
        // explicitly until the real contract call is implemented.
        Err(IdentityResolverError::NotImplemented {
            did: did.to_owned(),
        })
    }
}
