// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! HTTP/2 transport adapter using hyper + h2.

use async_trait::async_trait;
use http::Request;
use tracing::debug;

use crate::connection::{AttestTransport, SendError, TransportRequest, TransportResponse};

/// HTTP/2 transport adapter.
#[derive(Clone)]
pub struct H2Transport {
    base_uri: http::Uri,
}

impl H2Transport {
    #[must_use]
    pub const fn new(base_uri: http::Uri) -> Self {
        Self { base_uri }
    }
}

#[async_trait]
impl AttestTransport for H2Transport {
    async fn send(&self, request: TransportRequest) -> Result<TransportResponse, SendError> {
        let mut parts = self.base_uri.clone().into_parts();
        let req_parts = request.uri.into_parts();
        parts.path_and_query = req_parts.path_and_query;
        let _uri = http::Uri::from_parts(parts).map_err(|e| SendError::Protocol(e.to_string()))?;
        let _ = Request::builder().method(request.method);
        debug!("H2Transport::send — stub; wire a real connector in production");
        Err(SendError::Connection(
            "H2Transport stub — connect a TLS connector".to_owned(),
        ))
    }
}
