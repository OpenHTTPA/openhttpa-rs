// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! # openhttpa-mcp
//!
//! Confidential Model Context Protocol (MCP) implementation via `OpenHTTPA`.
//!
//! This crate enables AI models to interact with tools and data sources securely
//! within a TEE, ensuring that the context (tool definitions, resource data)
//! is never exposed to untrusted environments.

#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_code)]

pub mod client;
pub mod server;
pub mod types;

pub use client::OpenHttpaMcpClient;
pub use server::OpenHttpaMcpServer;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::server::McpTool;
    use super::*;
    use async_trait::async_trait;

    struct MockTool;
    #[async_trait]
    impl McpTool for MockTool {
        fn name(&self) -> &'static str {
            "test"
        }
        fn description(&self) -> Option<&str> {
            None
        }
        fn input_schema(&self) -> serde_json::Value {
            serde_json::json!({})
        }
        async fn call(&self, _args: serde_json::Value) -> Result<serde_json::Value, String> {
            Ok(serde_json::json!({ "ok": true }))
        }
    }

    #[tokio::test]
    async fn test_mcp_server_flow() {
        let server = OpenHttpaMcpServer::new();
        server.add_tool(Box::new(MockTool)).await;

        let req =
            serde_json::to_vec(&McpRequest::new(serde_json::json!(1), "tools/list", None)).unwrap();

        let res_bytes = server.handle_request(&req).await.unwrap();
        let res: McpResponse = serde_json::from_slice(&res_bytes).unwrap();

        assert!(res.result.is_some());
        let tools = res.result.unwrap();
        assert_eq!(tools["tools"][0]["name"], "test");
    }

    #[tokio::test]
    async fn test_mcp_invalid_json() {
        let server = OpenHttpaMcpServer::new();
        let res = server.handle_request(b"invalid json").await;
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Invalid JSON-RPC request"));
    }

    #[tokio::test]
    async fn test_mcp_unknown_method() {
        let server = OpenHttpaMcpServer::new();
        let req = serde_json::to_vec(&McpRequest::new(
            serde_json::json!(1),
            "unknown/method",
            None,
        ))
        .unwrap();
        let res_bytes = server.handle_request(&req).await.unwrap();
        let res: McpResponse = serde_json::from_slice(&res_bytes).unwrap();
        assert!(res.error.is_some());
        assert_eq!(res.error.unwrap().code, -32601);
    }

    #[tokio::test]
    async fn test_mcp_tool_not_found() {
        let server = OpenHttpaMcpServer::new();
        let req = serde_json::to_vec(&McpRequest::new(
            serde_json::json!(1),
            "tools/call",
            Some(serde_json::json!({ "name": "nonexistent", "arguments": {} })),
        ))
        .unwrap();
        let res_bytes = server.handle_request(&req).await.unwrap();
        let res: McpResponse = serde_json::from_slice(&res_bytes).unwrap();
        assert!(res.error.is_some());
        assert_eq!(res.error.unwrap().code, -32601);
    }

    struct ErrorTool;
    #[async_trait]
    impl McpTool for ErrorTool {
        fn name(&self) -> &'static str {
            "error_tool"
        }
        fn description(&self) -> Option<&str> {
            None
        }
        fn input_schema(&self) -> serde_json::Value {
            serde_json::json!({})
        }
        async fn call(&self, _args: serde_json::Value) -> Result<serde_json::Value, String> {
            Err("intentional error".to_owned())
        }
    }

    #[tokio::test]
    async fn test_mcp_tool_execution_error() {
        let server = OpenHttpaMcpServer::new();
        server.add_tool(Box::new(ErrorTool)).await;
        let req = serde_json::to_vec(&McpRequest::new(
            serde_json::json!(1),
            "tools/call",
            Some(serde_json::json!({ "name": "error_tool", "arguments": {} })),
        ))
        .unwrap();
        let res_bytes = server.handle_request(&req).await.unwrap();
        let res: McpResponse = serde_json::from_slice(&res_bytes).unwrap();
        assert!(res.error.is_some());
        assert_eq!(res.error.as_ref().unwrap().code, -32000);
        assert!(res.error.unwrap().message.contains("intentional error"));
    }
}
