// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! HTTP transport adapter using reqwest.

use futures::stream::StreamExt;
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

impl AttestTransport for ReqwestTransport {
    fn send(
        &self,
        request: TransportRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TransportResponse, SendError>> + Send + '_>,
    > {
        Box::pin(async move {
            debug!(
                "ReqwestTransport::send — {} {}",
                request.method, request.uri
            );

            let body_stream = http_body_util::BodyStream::new(request.body).map(|res| {
                res.map(|frame| frame.into_data().unwrap_or_default())
                    .map_err(|e| std::io::Error::other(e.to_string()))
            });

            let mut req_builder = self
                .client
                .request(request.method, request.uri.to_string())
                .headers(request.headers)
                .body(reqwest::Body::wrap_stream(body_stream));

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

            let resp_stream = resp.bytes_stream().map(|res| {
                res.map(http_body::Frame::data)
                    .map_err(|e| std::io::Error::other(e.to_string()))
            });

            let body = http_body_util::BodyExt::boxed(http_body_util::StreamBody::new(resp_stream));

            Ok(TransportResponse {
                status,
                headers,
                body,
                trailers: None,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_reqwest_transport_fail() {
        let transport = ReqwestTransport::new();

        let req = TransportRequest {
            method: http::Method::POST,
            uri: "http://invalid-domain.test".parse().unwrap(),
            headers: http::HeaderMap::new(),
            body: crate::connection::empty_body(),
            trailers: None,
        };

        let result = transport.send(req).await;
        assert!(matches!(result, Err(SendError::Connection(_))));
    }
}
