// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::AgentMetadata;

/// Trait for an agent registry that tracks attested peers.
#[async_trait]
pub trait AgentRegistry: Send + Sync {
    /// Register an agent in the mesh.
    async fn register(&self, metadata: AgentMetadata) -> Result<(), String>;
    /// Get an agent's metadata by ID.
    async fn get_agent(&self, id: Uuid) -> Result<Option<AgentMetadata>, String>;
    /// Search for agents with specific capabilities.
    async fn search(&self, capability: &str) -> Result<Vec<AgentMetadata>, String>;
    /// Report presence (heartbeat) to keep the registration active.
    async fn heartbeat(&self, id: Uuid) -> Result<(), String>;
}

/// A simple in-memory mock registry for testing.
pub struct MockRegistry {
    agents: DashMap<Uuid, AgentMetadata>,
}

impl MockRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            agents: DashMap::new(),
        }
    }
}

impl Default for MockRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AgentRegistry for MockRegistry {
    async fn register(&self, metadata: AgentMetadata) -> Result<(), String> {
        self.agents.insert(metadata.id, metadata);
        Ok(())
    }

    async fn get_agent(&self, id: Uuid) -> Result<Option<AgentMetadata>, String> {
        Ok(self.agents.get(&id).map(|a| a.clone()))
    }

    async fn search(&self, capability: &str) -> Result<Vec<AgentMetadata>, String> {
        Ok(self
            .agents
            .iter()
            .filter(|a| a.capabilities.contains(&capability.to_string()))
            .map(|a| a.clone())
            .collect())
    }

    async fn heartbeat(&self, _id: Uuid) -> Result<(), String> {
        // Mock registry doesn't implement TTL for now
        Ok(())
    }
}

/// A high-performance sharded registry with TTL-based eviction.
pub struct ShardedRegistry {
    shards: Vec<DashMap<Uuid, (AgentMetadata, std::time::Instant)>>,
    ttl: std::time::Duration,
}

impl ShardedRegistry {
    #[must_use]
    pub fn new(shard_count: usize, ttl: std::time::Duration) -> Arc<Self> {
        let mut shards = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            shards.push(DashMap::new());
        }
        let registry = Arc::new(Self { shards, ttl });

        // Spawn reaper task
        let registry_clone = Arc::downgrade(&registry);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                let Some(reg) = registry_clone.upgrade() else {
                    break;
                };
                reg.reap();
            }
        });

        registry
    }

    fn get_shard(&self, id: Uuid) -> &DashMap<Uuid, (AgentMetadata, std::time::Instant)> {
        let idx = (id.as_u128() % self.shards.len() as u128) as usize;
        &self.shards[idx]
    }

    fn reap(&self) {
        let now = std::time::Instant::now();
        for shard in &self.shards {
            shard.retain(|_, (_, last_seen)| now.duration_since(*last_seen) < self.ttl);
        }
    }
}

#[async_trait]
impl AgentRegistry for ShardedRegistry {
    async fn register(&self, metadata: AgentMetadata) -> Result<(), String> {
        let shard = self.get_shard(metadata.id);
        shard.insert(metadata.id, (metadata, std::time::Instant::now()));
        Ok(())
    }

    async fn get_agent(&self, id: Uuid) -> Result<Option<AgentMetadata>, String> {
        let shard = self.get_shard(id);
        Ok(shard.get(&id).map(|pair| pair.0.clone()))
    }

    async fn search(&self, capability: &str) -> Result<Vec<AgentMetadata>, String> {
        let mut results = Vec::new();
        for shard in &self.shards {
            for pair in shard {
                if pair.0.capabilities.contains(&capability.to_string()) {
                    results.push(pair.0.clone());
                }
            }
        }
        Ok(results)
    }

    async fn heartbeat(&self, id: Uuid) -> Result<(), String> {
        let shard = self.get_shard(id);
        if let Some(mut pair) = shard.get_mut(&id) {
            pair.1 = std::time::Instant::now();
            Ok(())
        } else {
            Err("Agent not found".to_string())
        }
    }
}
