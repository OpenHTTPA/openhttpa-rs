// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! # openhttpa-llm
//!
//! Confidential LLM inference via `OpenHTTPA` attested sessions.
//!
//! ## Overview
//!
//! This crate wraps an `OpenHttpaClient` and a confidential inference endpoint
//! (e.g. a TEE-hosted Llama-3 or GPT-4 compatible server) to provide
//! end-to-end attested, encrypted LLM calls.
//!
//! All request/response payloads are AEAD-encrypted under the `AtB` session
//! keys.  The TEE's attestation quote proves the model weights, runtime, and
//! inference code match a known measurement.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use openhttpa_llm::{ConfidentialLlmClient, ChatMessage, Role};
//!
//! #[tokio::main]
//! async fn main() {
//!     let llm = ConfidentialLlmClient::builder()
//!         .await
//!         .server_uri("https://confidential-llm.example.com".parse().unwrap())
//!         .build()
//!         .await
//!         .unwrap();
//!
//!     let messages = vec![
//!         ChatMessage { role: Role::System, content: "You are a secure assistant.".into() },
//!         ChatMessage { role: Role::User,   content: "What is TEE attestation?".into() },
//!     ];
//!
//!     let reply = llm.chat(&messages).await.unwrap();
//!     println!("{}", reply);
//! }
//! ```

#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_code)]

pub mod client;
pub mod types;

pub use client::ConfidentialLlmClient;
pub use types::{ChatMessage, ChatRequest, ChatResponse, Role};
