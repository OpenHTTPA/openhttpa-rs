// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! A comprehensive integration example demonstrating a complete Zero-Trust
//! Messenger Swarm Agent using OpenHTTPA.
//!
//! This example shows how to:
//! 1. Initialize an `A2AAgent`.
//! 2. Bind the agent to an `AiqlEngine` to semantically filter incoming payloads.
//! 3. Use `MockTeeProvider` to simulate a physical TEE enclave environment.
//! 4. Mount a `MemoryStore` on RocksDB that utilizes PerTransaction enclave keys
//!    to seal and persist agent state directly into the Distributed Memory Fabric.

use openhttpa_a2a::A2AAgent;
use openhttpa_aiql::{AiqlConfig, AiqlEngine, AiqlPolicy, Condition, Context, PolicyAction};
use openhttpa_fabric::store::{KeyDerivationPolicy, MemoryStore, Topology};
use openhttpa_tee::mock::MockTeeProvider;
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- OpenHTTPA Swarm Agent Initialization ---");

    // =========================================================================
    // 1. EMULATE HARDWARE SECURITY (TEE / ENCLAVES)
    // =========================================================================
    // In a production Zero-Trust environment, this agent would be running inside
    // a physical "hardware enclave" (like Intel SGX or Intel TDX). An enclave is
    // a highly secure, isolated region of the CPU that prevents even the host OS
    // or hypervisor from reading its memory.
    //
    // For this example to compile and run on any laptop or CI/CD pipeline without
    // needing specialized Intel hardware, we use `MockTeeProvider`. This simulates
    // the cryptographic behavior of an enclave (like generating keys bound to the
    // code's identity) entirely in software.
    // =========================================================================
    let tee_provider = Arc::new(MockTeeProvider::default());
    println!("[1/4] Simulated TEE Enclave Bindings initialized.");

    // =========================================================================
    // 2. INITIALIZE THE SECURE DISTRIBUTED MEMORY FABRIC (SDMF)
    // =========================================================================
    // AI Agents generate state (like ledgers, memories, or internal ML parameters).
    // Because they run in untrusted clouds, we can't just save this state to disk
    // in plaintext. The SDMF solves this by automatically encrypting data before
    // it hits the database (RocksDB in this case).
    //
    // We use `KeyDerivationPolicy::PerTransaction`. This tells the CPU to generate
    // a brand new encryption key dynamically via a hardware instruction (e.g. EGETKEY)
    // for every single read/write operation, instead of keeping a key cached in memory.
    // =========================================================================
    let temp_dir = tempfile::tempdir()?;
    let db_path = temp_dir
        .path()
        .join("swarm_agent_db")
        .to_str()
        .unwrap()
        .to_string();
    let memory_store = MemoryStore::new_rocksdb(
        Topology::Global,
        tee_provider.clone(),
        &db_path,
        KeyDerivationPolicy::PerTransaction,
    )
    .expect("Failed to bind RocksDB to the SDMF");
    println!("[2/4] Distributed Memory Fabric (RocksDB) bound with PerTransaction security.");

    // =========================================================================
    // 3. MOUNT THE AGENT INTELLIGENCE QUERY LANGUAGE (AIQL) ENGINE
    // =========================================================================
    // AIQL acts as a "semantic firewall". Instead of blocking IP addresses or ports,
    // it blocks malicious *intents*. Before an agent processes a message, AIQL
    // inspects the payload's intent and the sender's identity.
    //
    // `strict_mode: true` means if a payload doesn't explicitly match an `Allow`
    // rule, it is immediately flagged for `Quarantine`.
    // =========================================================================
    let mut aiql = AiqlEngine::new(AiqlConfig {
        default_action: PolicyAction::Quarantine,
        strict_mode: true,
    });

    // Policy: Only allow 'sync_state' commands from other openhttpa-verified agents.
    aiql.load_policy(AiqlPolicy {
        name: "allow_verified_sync".to_string(),
        condition: Condition::And(vec![
            Condition::Equals {
                field: "intent".to_string(),
                value: "sync_state".to_string(),
            },
            Condition::Contains {
                field: "caller.did".to_string(),
                value: "did:openhttpa:".to_string(),
            },
        ]),
        action: PolicyAction::Allow,
        on_violation: None,
    });
    println!("[3/4] AIQL Semantic Router engaged. Strict constraints applied.");

    // 4. Connect the Agent:
    // In a real application, you would attach this to an OpenHttpaClient
    // to route messages across the physical mesh.
    let agent_alice = A2AAgent::new("alice_node_1")?;
    println!("[4/4] Agent '{}' booted and ready.", agent_alice.agent_id);

    println!("\n--- Simulating Incoming Swarm Payload ---");
    // Simulate an incoming valid payload from Bob
    let valid_payload_ctx = Context {
        caller_did: "did:openhttpa:bob_node_9".to_string(),
        caller_mrenclave: "SECURE_HASH".to_string(),
        intent: "sync_state".to_string(),
        namespace: "global_ledger".to_string(),
    };

    if aiql.evaluate_payload(&valid_payload_ctx) == PolicyAction::Allow {
        println!("  -> Payload Authorized by AIQL (valid DID and intent).");

        let payload_data = b"Ledger synchronization payload".to_vec();
        let mut version = HashMap::new();
        version.insert("alice_node_1".to_string(), 1);

        if memory_store.put(
            "global_ledger",
            "sync_packet",
            payload_data.clone(),
            version,
            None,
        ) {
            println!("  -> Successfully sealed and stored state in SDMF!");
        }

        // Verify retrieval unsealing
        if let Some(retrieved) = memory_store.get("global_ledger", "sync_packet") {
            assert_eq!(retrieved, payload_data);
            println!("  -> Verified successful retrieval and unsealing of state.");
        }
    }

    println!("\n--- Simulating Malicious Payload ---");
    let malicious_payload_ctx = Context {
        caller_did: "did:attacker:unknown".to_string(),
        caller_mrenclave: "UNTRUSTED_HASH".to_string(),
        intent: "sync_state".to_string(),
        namespace: "global_ledger".to_string(),
    };

    if aiql.evaluate_payload(&malicious_payload_ctx) == PolicyAction::Quarantine {
        println!("  -> AIQL successfully Quarantined unauthorized payload!");
    }

    println!("\nSwarm Agent workflow complete.");
    Ok(())
}
