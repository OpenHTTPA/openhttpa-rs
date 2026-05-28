// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Transport abstraction types and [`AttestTransport`] trait.

use http::{HeaderMap, Method, StatusCode, Uri};
use thiserror::Error;

/// A transport-level error.
#[non_exhaustive]
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
pub trait AttestTransport: Send + Sync {
    /// Send a request and return the response.
    fn send(
        &self,
        request: TransportRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TransportResponse, SendError>> + Send + '_>,
    >;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_error_connection_display() {
        let e = SendError::Connection("host unreachable".to_owned());
        assert_eq!(e.to_string(), "connection error: host unreachable");
    }

    #[test]
    fn send_error_io_display() {
        let e = SendError::Io("broken pipe".to_owned());
        assert_eq!(e.to_string(), "I/O error: broken pipe");
    }

    #[test]
    fn send_error_cancelled_display() {
        let e = SendError::Cancelled;
        assert_eq!(e.to_string(), "request cancelled");
    }

    #[test]
    fn send_error_protocol_display() {
        let e = SendError::Protocol("h2 frame error".to_owned());
        assert_eq!(e.to_string(), "protocol error: h2 frame error");
    }

    #[test]
    fn transport_request_fields_accessible() {
        let req = TransportRequest {
            method: Method::GET,
            uri: "http://localhost/api".parse().unwrap(),
            headers: HeaderMap::new(),
            body: axum::body::Body::empty(),
            trailers: None,
        };
        assert_eq!(req.method, Method::GET);
        assert!(req.trailers.is_none());
    }

    #[test]
    fn transport_response_fields_accessible() {
        let resp = TransportResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: axum::body::Body::empty(),
            trailers: Some(HeaderMap::new()),
        };
        assert_eq!(resp.status, StatusCode::OK);
        assert!(resp.trailers.is_some());
    }

    #[test]
    fn transport_response_not_found() {
        let resp = TransportResponse {
            status: StatusCode::NOT_FOUND,
            headers: HeaderMap::new(),
            body: axum::body::Body::empty(),
            trailers: None,
        };
        assert!(!resp.status.is_success());
    }
}
