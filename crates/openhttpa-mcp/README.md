# `OpenHTTPA` Model Context Protocol (MCP) Documentation

The `openhttpa-mcp` crate integrates the Model Context Protocol with `OpenHTTPA`, allowing agents to expose and consume tools securely within a Trusted Execution Environment (TEE).

## Core Concepts

- **MCP Server**: Hosts tools that can be called by remote agents. It verifies the caller's attestation before executing any tool.
- **MCP Client**: Discovers and invokes tools on a remote server. It ensures the server is attested before sending any data.
- **Secure Tools**: Functions that run entirely within the TEE, protecting both the inputs and the processing logic.

## Usage Example

### Hosting a Tool (Server)

```rust
use openhttpa_mcp::{OpenHttpaMcpServer, McpTool};
use serde_json::json;
use async_trait::async_trait;

struct MyTool;
#[async_trait]
impl McpTool for MyTool {
    fn name(&self) -> &str { "calculate_risk" }
    fn description(&self) -> Option<&str> { Some("Calculates risk score") }
    fn input_schema(&self) -> serde_json::Value { json!({ "type": "object" }) }
    async fn call(&self, args: serde_json::Value) -> Result<serde_json::Value, String> {
        let score: f64 = args["score"].as_f64().unwrap_or(0.0);
        let risk = if score > 0.8 { "High" } else { "Low" };
        Ok(json!({ "risk": risk }))
    }
}

#[tokio::main]
async fn main() {
    let server = OpenHttpaMcpServer::new();
    server.add_tool(Box::new(MyTool)).await;
}
```

### Calling a Tool (Client)

```rust
use openhttpa_mcp::OpenHttpaMcpClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = OpenHttpaMcpClient::new("http://risk-agent.local")?;

    let args = serde_json::json!({ "score": 0.9 });
    let result = client.call_tool("calculate_risk", args).await?;

    println!("Risk result: {}", result);
    Ok(())
}
```

## Integration with A2A

In a typical swarm scenario, agents use `openhttpa-a2a` for discovery and `openhttpa-mcp` for functional task execution. The mutual attestation established during the A2A handshake is reused for all subsequent MCP tool calls.

## Error Handling

- `HandshakeError`: Failed to establish a secure session.
- `ToolNotFoundError`: The requested tool is not registered on the server.
- `ExecutionError`: The tool execution failed inside the TEE.
- `UnauthorizedError`: The caller's attestation quote was invalid or missing.
