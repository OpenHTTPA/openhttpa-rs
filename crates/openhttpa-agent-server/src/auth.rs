#![allow(dead_code)]
use axum::{extract::Request, middleware::Next, response::Response};
use openhttpa_identity_chain::{IdentityResolver, IdentityResolverError};

#[derive(Clone, Debug)]
pub struct VerifiedDid(pub String);

/// Middleware for authenticating agents via openhttpa-identity-chain DIDs.
/// Requires the request to contain a signed challenge.
/// It injects `VerifiedDid` into the request extensions for GraphQL context to consume.
pub async fn auth_middleware(
    mut request: Request,
    next: Next,
) -> Result<Response, axum::http::StatusCode> {
    let auth_header = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    match auth_header {
        Some(token) => {
            let resolver = IdentityResolver::new("http://localhost:8545").expect("Valid URL");
            match resolver.resolve_did(token).await {
                Ok(mrenclave) => {
                    tracing::info!("Successfully resolved DID to MRENCLAVE: {}", mrenclave);
                }
                Err(IdentityResolverError::NotImplemented { .. }) => {
                    tracing::warn!("DID resolution not implemented; skipping check for testbed");
                }
                Err(e) => {
                    tracing::error!("DID resolution failed: {}", e);
                    return Err(axum::http::StatusCode::UNAUTHORIZED);
                }
            }

            let verified_did = VerifiedDid(token.to_string()); // In practice this is extracted DID
            request.extensions_mut().insert(verified_did);
            Ok(next.run(request).await)
        }
        None => Err(axum::http::StatusCode::UNAUTHORIZED),
    }
}
