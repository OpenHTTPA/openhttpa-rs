# `OpenHTTPA` Model Context Protocol (MCP) Documentation

The `openhttpa-mcp` crate integrates the Model Context Protocol with `OpenHTTPA`, allowing agents to expose and consume tools securely within a Trusted Execution Environment (TEE).

## Core Concepts

- **MCP Server**: Hosts tools that can be called by remote agents. It verifies the caller's attestation before executing any tool.
- **MCP Client**: Discovers and invokes tools on a remote server. It ensures the server is attested before sending any data.
- **Secure Tools**: Functions that run entirely within the TEE, protecting both the inputs and the processing logic.

## Usage Example

### Hosting a Tool (Server)

```rust
use openhttpa_mcp::McpTool;
use serde_json::Value;

struct MyCustomTool;

impl McpTool for MyCustomTool {
    fn name(&self) -> &str {
        "my_tool"
    }

    fn description(&self) -> Option<&str> {
        Some("A description of what my tool does.")
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "arg1": { "type": "string" }
            }
        })
    }

    fn call<'a>(&'a self, args: Value) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Value, String>> + Send + 'a>> {
        Box::pin(async move {
            let arg1 = args["arg1"].as_str().ok_or("Missing arg1")?;
            Ok(serde_json::json!({ "result": format!("Processed {}", arg1) }))
        })
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
