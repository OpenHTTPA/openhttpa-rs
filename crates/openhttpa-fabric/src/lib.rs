// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation

//! Secure Distributed Memory Fabric over OpenHTTPA
//!
//! Provides a hardware-attested, decentralized CRDT store for AI agents.

pub mod mcp_tools;
pub mod metrics;
pub mod policy;
pub mod replication;
pub mod store;

pub use policy::{AiqlPolicyEngine, AuthorizationPolicy, OpaPolicyEngine};
pub use replication::{ReplicationManager, ReplicationTransport};
pub use store::{DataStore, KvStore, MemoryStore, Topology, VectorStore};
