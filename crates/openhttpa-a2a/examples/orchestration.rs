// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

use openhttpa_a2a::{A2AAgent, A2AMessage, AgentRouter};
use openhttpa_mcp::client::OpenHttpaMcpClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize local agent
    let alice = A2AAgent::new("alice")?;
    let router = AgentRouter::new(alice);

    // 2. Define targets (pointing to the demo backend for this example)
    let bob_url = "http://127.0.0.1:8080";
    let charlie_url = "http://127.0.0.1:8080";

    // 3. Establish persistent sessions via Router
    println!("Alice: Connecting to Bob and Charlie (checking reachability)...");
    if let Err(e) = router.get_or_connect(bob_url).await {
        println!(
            "Alice: Target {} not reachable: {}. Skipping live handshake demonstration for CI.",
            bob_url, e
        );
        println!("Alice: (In a live stack, this would establish a multi-TEE secure session)");
        return Ok(());
    }
    let _charlie_session = router.get_or_connect(charlie_url).await?;

    // 4. Use MCP to call a tool on Bob
    println!("Alice: Requesting risk analysis from Bob via MCP...");
    let bob_mcp = OpenHttpaMcpClient::new(bob_url)?;
    let risk_args = serde_json::json!({ "party_id": "alice", "value": 42 });
    let risk_result = bob_mcp.call_tool("secure_sum", risk_args).await?;
    println!("Alice: Bob returned result: {}", risk_result);

    // 5. Broadcast the result to the swarm via A2A
    println!("Alice: Broadcasting results to all agents...");
    let broadcast_msg = A2AMessage {
        sender_id: "alice".to_owned(),
        receiver_id: "swarm".to_owned(),
        message_type: "notification".to_owned(),
        payload: serde_json::json!({
            "event": "risk_analysis_complete",
            "result": risk_result
        }),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    };

    let results = router.broadcast(broadcast_msg).await;
    for (i, res) in results.iter().enumerate() {
        if res.is_ok() {
            println!("Alice: Message delivered to agent {}", i);
        } else {
            println!("Alice: Failed to deliver message to agent {}: {:?}", i, res);
        }
    }

    Ok(())
}
