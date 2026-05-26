# openhttpa-mcp — API Specification

**Crate**: `openhttpa-mcp`  
**License**: Apache-2.0 OR MIT  
**Edition**: Rust 2024  
**Repository**: [openhttpa-rs](file:///home/ub/tmp/openhttpa-rs)

---

## Overview

`openhttpa-mcp` implements the **Model Context Protocol (MCP)** over OpenHTTPA. It allows AI models and autonomous agents running inside TEEs to interact with tools and external data sources through a confidential, attested, AEAD-encrypted channel.

MCP is a JSON-RPC 2.0-based protocol for tool use. This crate provides:

- An MCP **server** for hosting tools inside a TEE-attested service.
- An MCP **client** for calling tools on a remote TEE over an established `AttestSession`.
- Shared request/response message types.

---

## Table of Contents

1. [Message Types (`types`)](#1-message-types)
2. [MCP Server (`server`)](#2-mcp-server)
3. [MCP Client (`client`)](#3-mcp-client)

---

## 1. Message Types

Source: [types.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-mcp/src/types.rs)

### `McpRequest` (Struct)

A JSON-RPC 2.0 request.

```rust
pub struct McpRequest {
    pub jsonrpc: String,             // Always "2.0"
    pub id: serde_json::Value,       // Request identifier (number or string)
    pub method: String,              // RPC method (e.g. "tools/list", "tools/call")
    pub params: Option<serde_json::Value>, // Optional parameters
}
```

#### Constructor

```rust
pub fn new(id: serde_json::Value, method: impl Into<String>, params: Option<serde_json::Value>) -> Self
```

Creates a JSON-RPC 2.0 request with `jsonrpc = "2.0"`.

### `McpResponse` (Struct)

A JSON-RPC 2.0 response.

```rust
pub struct McpResponse {
    pub jsonrpc: String,                // Always "2.0"
    pub id: serde_json::Value,          // Echoed from the request
    pub result: Option<serde_json::Value>,
    pub error: Option<McpError>,
}
```

Exactly one of `result` or `error` must be present.

### `McpError` (Struct)

A JSON-RPC 2.0 error object.

```rust
pub struct McpError {
    pub code: i32,
    pub message: String,
    pub data: Option<serde_json::Value>,
}
```

#### Standard Error Codes

| Code     | Meaning                                |
| -------- | -------------------------------------- |
| `-32700` | Parse error — invalid JSON.            |
| `-32600` | Invalid request.                       |
| `-32601` | Method not found / tool not found.     |
| `-32602` | Invalid params.                        |
| `-32603` | Internal error.                        |
| `-32000` | Tool execution error (server-defined). |

---

## 2. MCP Server

Source: [server.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-mcp/src/server.rs)

### `McpTool` (Trait)

The extension point for hosting tools in the MCP server.

```rust
#[async_trait]
pub trait McpTool: Send + Sync {
    /// Unique name for this tool (used as the dispatch key).
    fn name(&self) -> &'static str;

    /// Optional human-readable description (returned in tools/list responses).
    fn description(&self) -> Option<&str>;

    /// JSON Schema describing the tool's input arguments.
    fn input_schema(&self) -> serde_json::Value;

    /// Execute the tool with the provided arguments.
    ///
    /// # Errors
    /// Returns `Err(String)` with a human-readable error message on failure.
    async fn call(&self, args: serde_json::Value) -> Result<serde_json::Value, String>;
}
```

Implementations must be `Send + Sync` for use in async handlers behind `Arc`.

### `OpenHttpaMcpServer` (Struct)

An MCP server capable of hosting multiple tools and dispatching JSON-RPC 2.0 calls.

```rust
pub struct OpenHttpaMcpServer { /* private: Arc<tokio::sync::RwLock<Vec<Box<dyn McpTool>>>> */ }
```

#### Methods

```rust
pub fn new() -> Self
```

Creates a new MCP server with no registered tools.

```rust
pub async fn add_tool(&self, tool: Box<dyn McpTool>)
```

Registers a tool. Tools are looked up by `McpTool::name`. If two tools share the same name, the later registration overwrites the earlier.

```rust
pub async fn handle_request(&self, raw: &[u8]) -> Result<Vec<u8>, String>
```

Processes a raw JSON-RPC 2.0 request and returns a serialised JSON-RPC 2.0 response.

**Dispatch logic**:

| Method         | Behaviour                                                                                                |
| -------------- | -------------------------------------------------------------------------------------------------------- |
| `"tools/list"` | Returns `{"tools": [{"name": ..., "description": ..., "inputSchema": ...}, ...]}`.                       |
| `"tools/call"` | Parses `params.name` and `params.arguments`, dispatches to the matching tool, returns the tool's result. |
| _(any other)_  | Returns `McpError { code: -32601, message: "Method not found: {method}" }`.                              |

**Errors**:

- Returns `Err(String)` with `"Invalid JSON-RPC request"` if the input is not valid JSON.
- Returns `Err(String)` with `"Invalid JSON-RPC format"` if the parsed value is not a valid JSON-RPC object.

For all successfully-parsed requests (even those that produce tool or method errors), returns `Ok(Vec<u8>)` containing a valid `McpResponse`.

**Integration with OpenHTTPA**: In a typical deployment, the raw bytes passed to `handle_request` are decrypted from a `TrR` body by the server middleware, and the returned bytes are AEAD-encrypted before being sent in the response. See `openhttpa-mesh::AgentNode::call_peer_tool` for an end-to-end example.

---

## 3. MCP Client

Source: [client.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-mcp/src/client.rs)

### `OpenHttpaMcpClient` (Struct)

An MCP client that performs the full `AtHS` handshake and tool call lifecycle internally. It does **not** accept a pre-existing `AttestSession` — a fresh handshake is performed on each `call()`.

> **Design note**: This client is intentionally simple (stateless between calls) for ease of integration. For session-reuse across multiple calls, use `OpenHttpaClient` directly and cache the `AttestSession`, then call `trusted_request_ext` with a serialised `McpRequest`.

```rust
pub use client::OpenHttpaMcpClient;
```

#### Constructors

```rust
/// Create a new MCP client targeting a server URL.
///
/// Errors if `server_url` is not a valid URI.
pub fn new(server_url: &str) -> Result<Self, McpClientError>
```

Builds an `OpenHttpaClient` internally with `require_preflight = true`.

```rust
/// Create a new MCP client from a pre-configured `OpenHttpaClient`.
#[must_use]
pub const fn new_from_client(client: OpenHttpaClient) -> Self
```

Use this variant when you need to customise attestation, verifier, or transport settings.

#### Methods

```rust
pub async fn call(
    &self,
    method: &str,
    params: Option<serde_json::Value>,
) -> Result<serde_json::Value, McpClientError>
```

Performs AtHS handshake + trusted request in one call. Sends the JSON-RPC method and returns the parsed result.

```rust
pub async fn list_tools(&self) -> Result<serde_json::Value, McpClientError>
```

Sends a `tools/list` request. Equivalent to `call("tools/list", None)`.

```rust
pub async fn call_tool(
    &self,
    name: &str,
    arguments: serde_json::Value,
) -> Result<serde_json::Value, McpClientError>
```

Sends a `tools/call` request. Equivalent to `call("tools/call", Some(json!({"name": name, "arguments": arguments})))`.

**Returns**:

- `Ok(serde_json::Value)` — the tool's successful result.
- `Err(McpClientError::Protocol(...))` — JSON-RPC error message from the server.
- `Err(McpClientError::OpenHttpa(...))` — handshake or transport failure.

---

## Public API Surface

```rust
pub use client::OpenHttpaMcpClient;
pub use server::OpenHttpaMcpServer;
pub use types::*;  // McpRequest, McpResponse, McpError
```

---

## Usage Example

### Server Side (Inside a TEE)

```rust
use openhttpa_mcp::{OpenHttpaMcpServer, McpTool};
use async_trait::async_trait;

struct CalculatorTool;

#[async_trait]
impl McpTool for CalculatorTool {
    fn name(&self) -> &'static str { "calculator" }
    fn description(&self) -> Option<&str> { Some("Performs arithmetic") }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "a": {"type": "number"},
                "b": {"type": "number"},
                "op": {"type": "string", "enum": ["add", "mul"]}
            }
        })
    }
    async fn call(&self, args: serde_json::Value) -> Result<serde_json::Value, String> {
        let a = args["a"].as_f64().unwrap_or(0.0);
        let b = args["b"].as_f64().unwrap_or(0.0);
        match args["op"].as_str().unwrap_or("add") {
            "mul" => Ok(serde_json::json!({"result": a * b})),
            _     => Ok(serde_json::json!({"result": a + b})),
        }
    }
}

let server = OpenHttpaMcpServer::new();
server.add_tool(Box::new(CalculatorTool)).await;
```

### Client Side

```rust
use openhttpa_mcp::OpenHttpaMcpClient;

// Simple form: supply only the server URL.
let mcp_client = OpenHttpaMcpClient::new("https://agent.example.com").unwrap();
let tools = mcp_client.list_tools().await.unwrap();
let result = mcp_client
    .call_tool("calculator", serde_json::json!({"a": 3, "b": 4, "op": "mul"}))
    .await
    .unwrap();
// result == {"result": 12.0}

// Advanced form: supply a pre-configured OpenHttpaClient.
use openhttpa_client::OpenHttpaClient;
use std::sync::Arc;
let custom_client = OpenHttpaClient::builder()
    .server_uri("https://agent.example.com".parse().unwrap())
    .strict_attestation(true)
    .max_response_size(4 * 1024 * 1024)
    .build();
let mcp_client = OpenHttpaMcpClient::new_from_client(custom_client);
```

---

## Dependency Graph Position

```
openhttpa-mcp
├── openhttpa-client     (OpenHttpaClient, AttestSession, trusted_request)
├── async-trait
├── serde + serde_json   (JSON-RPC 2.0 serialisation)
└── tokio                (async RwLock for tool registry)
```
