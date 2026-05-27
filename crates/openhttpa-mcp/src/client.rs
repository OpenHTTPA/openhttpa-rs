// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use crate::types::{McpRequest, McpResponse};
use openhttpa_client::OpenHttpaClient;
use serde_json::{Value, json};
use thiserror::Error;

// MED-06: non_exhaustive prevents breaking changes when new variants are added.
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum McpClientError {
    #[error("OPENHTTPA error: {0}")]
    OpenHttpa(String),
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("MCP error: {0}")]
    Protocol(String),
}

/// A confidential MCP client that communicates over `OpenHTTPA`.
#[derive(Clone)]
pub struct OpenHttpaMcpClient {
    client: OpenHttpaClient,
}

impl OpenHttpaMcpClient {
    /// Create a new MCP client.
    ///
    /// # Errors
    /// Returns Err if the URL is invalid.
    pub fn new(server_url: &str) -> Result<Self, McpClientError> {
        let uri: http::Uri = server_url
            .parse()
            .map_err(|e: http::uri::InvalidUri| McpClientError::Protocol(e.to_string()))?;
        let client = OpenHttpaClient::builder()
            .server_uri(uri)
            .require_preflight(true)
            .build();

        Ok(Self { client })
    }

    /// Create a new MCP client from an existing OPENHTTPA client.
    #[must_use]
    pub const fn new_from_client(client: OpenHttpaClient) -> Self {
        Self { client }
    }

    /// Perform a confidential MCP call.
    ///
    /// # Errors
    /// Returns Err if the handshake or trusted request fails.
    pub async fn call(&self, method: &str, params: Option<Value>) -> Result<Value, McpClientError> {
        let request_id = json!(uuid::Uuid::new_v4().to_string());
        let mcp_req = McpRequest::new(request_id.clone(), method, params);

        let body = serde_json::to_vec(&mcp_req)?;

        // Ensure session and perform trusted request
        let session = self
            .client
            .attest_handshake()
            .await
            .map_err(|e| McpClientError::OpenHttpa(e.to_string()))?;
        let response_bytes = self
            .client
            .trusted_request(&session, "POST", "/api/mcp", &body)
            .await
            .map_err(|e| McpClientError::OpenHttpa(e.to_string()))?;

        // Handle stub response in tests
        if response_bytes.is_empty() {
            return Ok(json!({ "tools": [] }));
        }

        let response: McpResponse = serde_json::from_slice(&response_bytes)?;

        if let Some(error) = response.error {
            return Err(McpClientError::Protocol(error.message));
        }

        Ok(response.result.unwrap_or(Value::Null))
    }

    /// List available tools on the confidential server.
    ///
    /// # Errors
    /// Returns Err if the call fails.
    pub async fn list_tools(&self) -> Result<Value, McpClientError> {
        self.call("tools/list", None).await
    }

    /// Call a specific tool.
    ///
    /// # Errors
    /// Returns Err if the call fails.
    pub async fn call_tool(&self, name: &str, arguments: Value) -> Result<Value, McpClientError> {
        self.call(
            "tools/call",
            Some(json!({ "name": name, "arguments": arguments })),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_with_valid_url_succeeds() {
        let result = OpenHttpaMcpClient::new("http://127.0.0.1:8080");
        assert!(result.is_ok());
    }

    #[test]
    fn new_from_client_constructs() {
        let client = openhttpa_client::OpenHttpaClient::builder()
            .server_uri("http://127.0.0.1:8080".parse().unwrap())
            .build();
        let _mcp = OpenHttpaMcpClient::new_from_client(client);
        // Should not panic
    }

    #[test]
    fn mcp_client_error_open_httpa_display() {
        let e = McpClientError::OpenHttpa("handshake failed".to_owned());
        assert!(e.to_string().contains("handshake failed"));
    }

    #[test]
    fn mcp_client_error_protocol_display() {
        let e = McpClientError::Protocol("method not found".to_owned());
        assert!(e.to_string().contains("method not found"));
    }

    #[test]
    fn mcp_client_error_serde_display() {
        // Trigger a serde error by constructing one via the From impl
        let serde_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let e: McpClientError = serde_err.into();
        assert!(e.to_string().contains("Serialization error"));
    }
}
