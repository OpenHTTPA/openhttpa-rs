// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// MCP JSON-RPC Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// MCP JSON-RPC Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<McpError>,
}

/// MCP JSON-RPC Error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// MCP Tool definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    pub description: Option<String>,
    pub input_schema: Value,
}

/// MCP Resource definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub uri: String,
    pub name: String,
    pub description: Option<String>,
    pub mime_type: Option<String>,
}

impl McpRequest {
    #[must_use]
    pub fn new(id: Value, method: &str, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            method: method.to_string(),
            params,
        }
    }
}

impl McpResponse {
    #[must_use]
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    #[must_use]
    pub fn error(id: Value, code: i32, message: &str) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(McpError {
                code,
                message: message.to_string(),
                data: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_request_new_sets_jsonrpc_version() {
        let req = McpRequest::new(Value::from(42), "tools/list", None);
        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.method, "tools/list");
        assert_eq!(req.id, Value::from(42));
        assert!(req.params.is_none());
    }

    #[test]
    fn mcp_request_new_with_params() {
        let params = serde_json::json!({ "key": "value" });
        let req = McpRequest::new(Value::from("req-1"), "tools/call", Some(params.clone()));
        assert_eq!(req.method, "tools/call");
        assert_eq!(req.params, Some(params));
    }

    #[test]
    fn mcp_response_success_constructor() {
        let result = serde_json::json!({ "tools": [] });
        let resp = McpResponse::success(Value::from(1), result.clone());
        assert_eq!(resp.jsonrpc, "2.0");
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap(), result);
    }

    #[test]
    fn mcp_response_error_constructor() {
        let resp = McpResponse::error(Value::from(1), -32601, "Method not found");
        assert_eq!(resp.jsonrpc, "2.0");
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32601);
        assert_eq!(err.message, "Method not found");
        assert!(err.data.is_none());
    }

    #[test]
    fn mcp_error_serde_round_trip() {
        let err = McpError {
            code: -32700,
            message: "Parse error".to_owned(),
            data: Some(serde_json::json!({ "line": 1 })),
        };
        let json = serde_json::to_vec(&err).unwrap();
        let decoded: McpError = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.code, -32700);
        assert_eq!(decoded.message, "Parse error");
        assert!(decoded.data.is_some());
    }

    #[test]
    fn tool_serde_round_trip() {
        let tool = Tool {
            name: "calculator".to_owned(),
            description: Some("Adds two numbers".to_owned()),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "a": {"type": "number"}, "b": {"type": "number"} }
            }),
        };
        let json = serde_json::to_vec(&tool).unwrap();
        let decoded: Tool = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.name, "calculator");
        assert_eq!(decoded.description.as_deref(), Some("Adds two numbers"));
    }

    #[test]
    fn resource_serde_round_trip() {
        let res = Resource {
            uri: "file:///data/db.sqlite".to_owned(),
            name: "Database".to_owned(),
            description: Some("SQLite database".to_owned()),
            mime_type: Some("application/x-sqlite3".to_owned()),
        };
        let json = serde_json::to_vec(&res).unwrap();
        let decoded: Resource = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.uri, "file:///data/db.sqlite");
        assert_eq!(decoded.mime_type.as_deref(), Some("application/x-sqlite3"));
    }

    #[test]
    fn mcp_request_serde_round_trip() {
        let req = McpRequest::new(
            Value::from("abc"),
            "tools/list",
            Some(serde_json::json!({"cursor": null})),
        );
        let json = serde_json::to_vec(&req).unwrap();
        let decoded: McpRequest = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.id, Value::from("abc"));
        assert_eq!(decoded.method, "tools/list");
    }
}
