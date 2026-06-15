// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! # Verified AI Agentic Swarm Demo
//!
//! This demo showcases how to compose `openhttpa-llm` and `openhttpa-mcp` to
//! construct a secure, hardware-attested Agentic Swarm.
//!
//! In this architecture:
//! - The **LLM** resides in a Confidential Computing enclave.
//! - The **MCP Server** (providing tools to the LLM) resides in another enclave.
//! - All communication between them is fully attested, PQC-encrypted via `OpenHTTPA`,
//!   and governed by Policy-as-Code.

use openhttpa_mcp::{OpenHttpaMcpServer, server::McpTool};
use serde_json::{Value, json};
use tokio::time::{Duration, sleep};

/// A simulated Enterprise Database tool protected by the MCP server.
struct EnterpriseDbTool;

impl McpTool for EnterpriseDbTool {
    fn name(&self) -> &'static str {
        "query_enterprise_db"
    }

    fn description(&self) -> Option<&str> {
        Some(
            "Query the sensitive enterprise customer database. Input: JSON object with 'customer_id'.",
        )
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "customer_id": { "type": "string" }
            },
            "required": ["customer_id"]
        })
    }

    fn call<'a>(
        &'a self,
        args: Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Value, String>> + Send + 'a>>
    {
        Box::pin(async move {
            let customer_id = args
                .get("customer_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing customer_id".to_string())?;

            tracing::info!(
                "🛠️  [MCP Server] Executing database query for: {}",
                customer_id
            );

            // Simulated secure data retrieval
            Ok(json!({
                "status": "success",
                "data": {
                    "customer_id": customer_id,
                    "account_balance": "$10,000,000",
                    "risk_profile": "Low",
                    "clearance": "Top Secret"
                }
            }))
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    tracing::info!("🚀 Starting Verified AI Agentic Swarm over OpenHTTPA...");

    // 1. Initialize the MCP Server (Tool Provider)
    // In a real deployment, this server is hosted in a TEE and exposes an OpenHTTPA endpoint.
    let mcp_server = OpenHttpaMcpServer::new();
    mcp_server.add_tool(Box::new(EnterpriseDbTool)).await?;
    tracing::info!("✅ MCP Server initialized with 'query_enterprise_db' tool.");

    // 2. Initialize the Confidential LLM Client
    // We mock the LLM server endpoint for the demo since we don't have a live TEE LLM running.
    tracing::info!("✅ Connecting to Confidential LLM via OpenHTTPA session...");

    // In a real environment, we'd establish an OpenHTTPA session to `https://confidential-llm.example.com`.
    // For the demo, we'll simulate the interaction cycle directly.

    tracing::info!("🤖 [Agent] Received task: 'Analyze risk for customer 007'");

    // 3. The Agent requests the tool list via MCP client
    // We simulate the OpenHTTPA transport by directly passing the JSON-RPC bytes
    let list_req = openhttpa_mcp::McpRequest::new(json!(1), "tools/list", None);
    let list_req_bytes = serde_json::to_vec(&list_req)?;
    let list_res_bytes = mcp_server.handle_request(&list_req_bytes).await?;
    let list_res: openhttpa_mcp::McpResponse = serde_json::from_slice(&list_res_bytes)?;

    tracing::info!(
        "📋 [Agent] Discovered available tools: {:?}",
        list_res.result
    );

    // 4. The Agent decides to call the 'query_enterprise_db' tool
    let call_args = json!({
        "name": "query_enterprise_db",
        "arguments": {
            "customer_id": "007"
        }
    });
    let call_req = openhttpa_mcp::McpRequest::new(json!(2), "tools/call", Some(call_args));
    let call_req_bytes = serde_json::to_vec(&call_req)?;

    tracing::info!("🔒 [Agent] Attesting OpenHTTPA session to MCP server to invoke tool...");
    sleep(Duration::from_millis(500)).await; // Simulate AtHS Handshake & PQC key exchange

    let call_res_bytes = mcp_server.handle_request(&call_req_bytes).await?;
    let call_res: openhttpa_mcp::McpResponse = serde_json::from_slice(&call_res_bytes)?;

    tracing::info!(
        "🔓 [Agent] Received secure tool response: {}",
        serde_json::to_string_pretty(&call_res.result.unwrap())?
    );

    // 5. The Agent synthesizes the final answer
    tracing::info!(
        "🤖 [Agent] Final Answer: 'Customer 007 has a Low risk profile and $10,000,000 in assets.'"
    );

    tracing::info!("🎉 Agentic Swarm Demo completed successfully!");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_agentic_swarm_orchestration() {
        let mcp_server = OpenHttpaMcpServer::new();
        mcp_server
            .add_tool(Box::new(EnterpriseDbTool))
            .await
            .expect("Failed to add tool");

        // 1. Test tools/list
        let list_req = openhttpa_mcp::McpRequest::new(json!(1), "tools/list", None);
        let list_req_bytes = serde_json::to_vec(&list_req).unwrap();
        let list_res_bytes = mcp_server.handle_request(&list_req_bytes).await.unwrap();
        let list_res: openhttpa_mcp::McpResponse = serde_json::from_slice(&list_res_bytes).unwrap();

        let tools = list_res.result.expect("Missing result in tools/list");
        let tools_array = tools.get("tools").unwrap().as_array().unwrap();
        assert_eq!(tools_array.len(), 1);
        assert_eq!(
            tools_array[0].get("name").unwrap().as_str().unwrap(),
            "query_enterprise_db"
        );

        // 2. Test tools/call (Valid)
        let call_args = json!({
            "name": "query_enterprise_db",
            "arguments": {
                "customer_id": "007"
            }
        });
        let call_req = openhttpa_mcp::McpRequest::new(json!(2), "tools/call", Some(call_args));
        let call_req_bytes = serde_json::to_vec(&call_req).unwrap();
        let call_res_bytes = mcp_server.handle_request(&call_req_bytes).await.unwrap();
        let call_res: openhttpa_mcp::McpResponse = serde_json::from_slice(&call_res_bytes).unwrap();

        let result = call_res.result.expect("Missing result in tools/call");
        assert_eq!(result.get("status").unwrap().as_str().unwrap(), "success");
        let data = result.get("data").unwrap();
        assert_eq!(data.get("risk_profile").unwrap().as_str().unwrap(), "Low");

        // 3. Test tools/call (Missing args)
        let fail_args = json!({
            "name": "query_enterprise_db",
            "arguments": {} // Missing customer_id
        });
        let fail_req = openhttpa_mcp::McpRequest::new(json!(3), "tools/call", Some(fail_args));
        let fail_req_bytes = serde_json::to_vec(&fail_req).unwrap();
        let fail_res_bytes = mcp_server.handle_request(&fail_req_bytes).await.unwrap();
        let fail_res: openhttpa_mcp::McpResponse = serde_json::from_slice(&fail_res_bytes).unwrap();

        assert!(
            fail_res.error.is_some(),
            "Expected error for missing customer_id"
        );
    }
}
