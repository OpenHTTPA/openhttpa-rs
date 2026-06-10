// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use openhttpa_aiql::{AiqlConfig, AiqlEngine, AiqlPolicy, Condition, Context, PolicyAction};
use openhttpa_fabric::store::{KeyDerivationPolicy, MemoryStore, Topology};
use openhttpa_tee::mock::MockTeeProvider;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_e2e_swarm_sdmf_and_aiql() {
    // 1. Initialize our TEE Provider (simulates SGX/TDX)
    let tee_provider = Arc::new(MockTeeProvider::default());

    // 2. Initialize our Secure Distributed Memory Fabric (SDMF)
    // We use a temporary directory for RocksDB
    let dir = tempdir().unwrap();
    let db_path = dir
        .path()
        .join("swarm_fabric_db")
        .to_str()
        .unwrap()
        .to_string();

    // Use PerTransaction dynamic hardware key derivation for absolute security
    let memory_store = MemoryStore::new_rocksdb(
        Topology::Global,
        tee_provider.clone(),
        &db_path,
        KeyDerivationPolicy::PerTransaction,
    )
    .expect("Failed to initialize SDMF RocksDB store");

    // 3. Initialize our AIQL Semantic Policy Engine
    let mut aiql = AiqlEngine::new(AiqlConfig {
        default_action: PolicyAction::Quarantine,
        strict_mode: true,
    });

    // Add a policy to allow intent="negotiate" from valid DIDs
    aiql.load_policy(AiqlPolicy {
        name: "allow_negotiation".to_string(),
        condition: Condition::And(vec![
            Condition::Equals {
                field: "intent".to_string(),
                value: "negotiate".to_string(),
            },
            Condition::Contains {
                field: "caller.did".to_string(),
                value: "did:openhttpa:".to_string(),
            },
        ]),
        action: PolicyAction::Allow,
        on_violation: None,
    });

    // 4. Evaluate an incoming AI intent via AIQL
    let valid_ctx = Context {
        caller_did: "did:openhttpa:alice-agent".to_string(),
        caller_mrenclave: "hash123".to_string(),
        intent: "negotiate".to_string(),
        namespace: "trade".to_string(),
    };

    let invalid_ctx = Context {
        caller_did: "did:unknown:malicious".to_string(),
        caller_mrenclave: "hash999".to_string(),
        intent: "exfiltrate".to_string(),
        namespace: "core".to_string(),
    };

    assert_eq!(
        aiql.evaluate_payload(&valid_ctx).unwrap(),
        PolicyAction::Allow
    );
    assert_eq!(
        aiql.evaluate_payload(&invalid_ctx).unwrap(),
        PolicyAction::Quarantine
    );

    // 5. Simulate Agent Swarm Persisting State to SDMF
    let data = b"Agent Alice negotiation parameters".to_vec();
    let mut version = std::collections::HashMap::new();
    version.insert("alice_node".to_string(), 1);

    // Put data into the fabric
    let put_success = memory_store.put("trade", "alice_params", data.clone(), version, None);
    assert!(put_success, "Failed to persist sealed data into SDMF");

    // Retrieve and unseal data from the fabric
    let retrieved = memory_store.get("trade", "alice_params");
    if retrieved.is_none() {
        panic!(
            "Failed to fetch from SDMF. DB key trade:alice_params. Has put returned true? {}",
            put_success
        );
    }
    assert_eq!(
        retrieved.unwrap(),
        data,
        "Sealed data mismatch upon retrieval"
    );

    // ==========================================
    // EDGE CASE 1: Version Vector Dominance Conflict
    // ==========================================
    let mut old_version = std::collections::HashMap::new();
    old_version.insert("alice_node".to_string(), 0); // Older than the existing version 1
    let put_old = memory_store.put(
        "trade",
        "alice_params",
        b"Stale attacker data".to_vec(),
        old_version,
        None,
    );
    assert!(
        !put_old,
        "Fabric incorrectly accepted stale data violating version dominance"
    );

    // ==========================================
    // EDGE CASE 2: Complex Nested AIQL Logic Evaluation
    // ==========================================
    aiql.load_policy(AiqlPolicy {
        name: "complex_auth".to_string(),
        condition: Condition::Or(vec![
            Condition::And(vec![
                Condition::Equals {
                    field: "intent".to_string(),
                    value: "admin_override".to_string(),
                },
                Condition::Equals {
                    field: "caller.mrenclave".to_string(),
                    value: "AUTHORIZED_HASH_001".to_string(),
                },
            ]),
            Condition::Equals {
                field: "namespace".to_string(),
                value: "public".to_string(),
            },
        ]),
        action: PolicyAction::Allow,
        on_violation: None,
    });

    let admin_ctx = Context {
        caller_did: "did:openhttpa:sysadmin".to_string(),
        caller_mrenclave: "AUTHORIZED_HASH_001".to_string(),
        intent: "admin_override".to_string(),
        namespace: "restricted".to_string(),
    };
    let public_ctx = Context {
        caller_did: "did:openhttpa:anon".to_string(),
        caller_mrenclave: "UNTRUSTED".to_string(),
        intent: "read".to_string(),
        namespace: "public".to_string(),
    };
    let malicious_admin_ctx = Context {
        caller_did: "did:openhttpa:sysadmin".to_string(),
        caller_mrenclave: "HACKED_HASH_999".to_string(), // Correct intent but wrong enclave measurement
        intent: "admin_override".to_string(),
        namespace: "restricted".to_string(),
    };

    assert_eq!(
        aiql.evaluate_payload(&admin_ctx).unwrap(),
        PolicyAction::Allow,
        "Valid nested AND condition failed"
    );
    assert_eq!(
        aiql.evaluate_payload(&public_ctx).unwrap(),
        PolicyAction::Allow,
        "Valid OR branch failed"
    );
    assert_eq!(
        aiql.evaluate_payload(&malicious_admin_ctx).unwrap(),
        PolicyAction::Quarantine,
        "Malicious context bypassed strict MRENCLAVE check"
    );

    // We intentionally verify that requesting a non-existent key returns None cleanly without panicking.
    let nonexistent = memory_store.get("trade", "does_not_exist");
    assert!(
        nonexistent.is_none(),
        "Fetching non-existent key should return None safely"
    );
}
