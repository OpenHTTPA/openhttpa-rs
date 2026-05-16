// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! Transport abstraction types and [`AttestTransport`] trait.

use async_trait::async_trait;
use http::{HeaderMap, Method, StatusCode, Uri};
use thiserror::Error;

/// A transport-level error.
#[derive(Debug, Error)]
pub enum SendError {
    #[error("connection error: {0}")]
    Connection(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("request cancelled")]
    Cancelled,
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// A transport-level request.
pub struct TransportRequest {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: axum::body::Body,
    /// Trailing headers appended after the body (e.g. Attest-Ticket).
    pub trailers: Option<HeaderMap>,
}

/// A transport-level response.
pub struct TransportResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: axum::body::Body,
    /// Trailing headers received after the body (e.g. Attest-Binder).
    pub trailers: Option<HeaderMap>,
}

/// Common interface for all transport adapters.
#[async_trait]
pub trait AttestTransport: Send + Sync {
    /// Send a request and return the response.
    async fn send(&self, request: TransportRequest) -> Result<TransportResponse, SendError>;
}
