// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use crate::types::{McpRequest, McpResponse};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Trait for implementing MCP tool logic.
#[async_trait]
pub trait McpTool: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> Option<&str>;
    fn input_schema(&self) -> Value;
    async fn call(&self, arguments: Value) -> Result<Value, String>;
}

/// A confidential MCP server that runs inside a TEE.
pub struct OpenHttpaMcpServer {
    tools: Arc<RwLock<HashMap<String, Arc<dyn McpTool>>>>,
}

impl OpenHttpaMcpServer {
    /// Create a new MCP server.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tools: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a tool to the server.
    pub async fn add_tool(&self, tool: Box<dyn McpTool>) {
        let mut tools = self.tools.write().await;
        tools.insert(tool.name().to_string(), Arc::from(tool));
    }

    /// Handle an incoming MCP request.
    ///
    /// # Errors
    ///
    /// Returns Err if the request is malformed or execution fails.
    pub async fn handle_request(&self, request_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let req: McpRequest = serde_json::from_slice(request_bytes)
            .map_err(|e| format!("Invalid JSON-RPC request: {e}"))?;

        let res = match req.method.as_str() {
            "tools/list" => {
                let tool_list: Vec<Value> = {
                    let tools = self.tools.read().await;
                    tools
                        .values()
                        .map(|t| {
                            json!({
                                "name": t.name(),
                                "description": t.description(),
                                "input_schema": t.input_schema(),
                            })
                        })
                        .collect()
                };
                McpResponse::success(req.id, json!({ "tools": tool_list }))
            }
            "tools/call" => {
                let params = req.params.ok_or("Missing params for tools/call")?;
                let name = params["name"].as_str().ok_or("Missing tool name")?;
                let arguments = params["arguments"].clone();

                let tool = {
                    let tools = self.tools.read().await;
                    tools.get(name).cloned()
                };

                if let Some(tool) = tool {
                    match tool.call(arguments).await {
                        Ok(result) => McpResponse::success(req.id, result),
                        Err(e) => McpResponse::error(req.id, -32000, &e),
                    }
                } else {
                    McpResponse::error(req.id, -32601, "Tool not found")
                }
            }
            _ => McpResponse::error(req.id, -32601, "Method not found"),
        };

        serde_json::to_vec(&res).map_err(|e| format!("Serialization error: {e}"))
    }
}

impl Default for OpenHttpaMcpServer {
    fn default() -> Self {
        Self::new()
    }
}
