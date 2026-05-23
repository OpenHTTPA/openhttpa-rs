// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! HTTP transport adapter using reqwest.

use async_trait::async_trait;
use tracing::debug;

use crate::connection::{AttestTransport, SendError, TransportRequest, TransportResponse};

/// HTTP transport adapter using reqwest.
#[derive(Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl Default for ReqwestTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl ReqwestTransport {
    /// Create a new `ReqwestTransport` with a default client.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    /// Create a new `ReqwestTransport` with a custom client.
    #[must_use]
    pub const fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl AttestTransport for ReqwestTransport {
    async fn send(&self, request: TransportRequest) -> Result<TransportResponse, SendError> {
        debug!(
            "ReqwestTransport::send — {} {}",
            request.method, request.uri
        );

        let mut req_builder = self
            .client
            .request(request.method, request.uri.to_string())
            .headers(request.headers)
            .body(reqwest::Body::wrap_stream(request.body.into_data_stream()));

        if let Some(trailers) = request.trailers {
            for (name, value) in trailers {
                if let Some(name) = name {
                    req_builder = req_builder.header(name, value);
                }
            }
        }

        let resp = req_builder
            .send()
            .await
            .map_err(|e| SendError::Connection(e.to_string()))?;

        let status = resp.status();
        let headers = resp.headers().clone();
        let body = axum::body::Body::from_stream(resp.bytes_stream());

        Ok(TransportResponse {
            status,
            headers,
            body,
            trailers: None,
        })
    }
}
