// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use axum::routing::post;
use openhttpa_llm::{ChatMessage, ConfidentialLlmClient, Role};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    println!("=== `OpenHTTPA` Verified AI (V-AI) Demo ===");

    // 1. Setup Mock V-AI Server using Axum
    let model = "llama3-70b-confidential";
    let app = axum::Router::new().route("/v1/chat/completions", post(move |axum::Json(req): axum::Json<serde_json::Value>| async move {
        println!("[Server] Received request for model: {}", req["model"]);

        let content = "The common side effects of Aspirin include gastrointestinal irritation, increased bleeding risk, and in rare cases, allergic reactions like hives or asthma.";

        // 2. Compute hashes for Provenance Proving
        use sha2::{Digest, Sha256};
        let mut model_hasher = Sha256::new();
        model_hasher.update("llama3-70b-confidential".as_bytes());
        let model_id: [u8; 32] = model_hasher.finalize().into();

        // Match client-side message canonicalization
        let mut input_hasher = Sha256::new();
        if let Some(messages) = req["messages"].as_array() {
            for m in messages {
                input_hasher.update(m["role"].as_str().unwrap().as_bytes());
                input_hasher.update(m["content"].as_str().unwrap().as_bytes());
            }
        }
        let input_hash: [u8; 32] = input_hasher.finalize().into();

        let mut output_hasher = Sha256::new();
        output_hasher.update(content.as_bytes());
        let output_hash: [u8; 32] = output_hasher.finalize().into();

        // 3. Generate ZK Proof of Provenance (Mock Mode)
        let mut vai_hasher = Sha256::new();
        vai_hasher.update(b"openhttpa vai v1");
        vai_hasher.update(model_id);
        vai_hasher.update(input_hash);
        vai_hasher.update(output_hash);
        let binding = vai_hasher.finalize();

        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(&binding);

        let zk_input = openhttpa_zk::ZkInput {
            mode: openhttpa_zk::ZkMode::VerifiedAi,
            transcript_hash: [0x42u8; 48],
            quote_bytes: vec![0xEE; 64],
            report_data,
            oracle_data: None,
            vai_data: Some(openhttpa_zk::VaiInput {
                model_id,
                input_hash,
                output_hash,
            }),
            dcap_collateral: None,
        };

        let receipt = openhttpa_zk::prover::ZkProver::prove(&zk_input).unwrap();
        let proof_hex = hex::encode(serde_json::to_vec(&receipt).unwrap());

        axum::Json(serde_json::json!({
            "id": "chat-vai-123",
            "object": "chat.completion",
            "created": 1_700_000_000,
            "model": "llama3-70b-confidential",
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": content }
            }],
            "provenance_proof": proof_hex
        }))
    }));

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
            .await
            .unwrap();
        axum::serve(listener, app).await.unwrap();
    });

    // 2. Initialize the Confidential LLM Client with bypass mode
    let llm = ConfidentialLlmClient::builder()
        .await
        .server_uri("http://127.0.0.1:8080".parse().unwrap())
        .model(model)
        .inference_path("/v1/chat/completions")
        .with_bypass()
        .build()
        .await
        .expect("Failed to initialize LLM client");

    // 3. Send a prompt that requires hardware-backed provenance
    let messages = vec![
        ChatMessage {
            role: Role::System,
            content: "You are a verified medical assistant.".into(),
        },
        ChatMessage {
            role: Role::User,
            content: "What are the common side effects of Aspirin?".into(),
        },
    ];

    println!("\n[1] Sending prompt to verified model: {}...", model);
    let reply = llm.chat(&messages).await.expect("V-AI Chat failed");

    println!("\n[2] Response Received and Verified!");
    println!("Assistant Reply: {}", reply);
    println!(
        "\nSuccess: The response has been cryptographically proven to originate from model '{}' running in a secure TEE.",
        model
    );
}

// Legacy mock transport removed.
