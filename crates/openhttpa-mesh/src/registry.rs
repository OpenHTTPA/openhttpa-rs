// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use dashmap::DashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::AgentMetadata;

/// Trait for an agent registry that tracks attested peers.
pub trait AgentRegistry: Send + Sync {
    /// Register an agent in the mesh.
    fn register(
        &self,
        metadata: AgentMetadata,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>>;
    /// Get an agent's metadata by ID.
    fn get_agent(
        &self,
        id: Uuid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<AgentMetadata>, String>> + Send + '_>,
    >;
    /// Search for agents with specific capabilities.
    fn search(
        &self,
        capability: &str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<AgentMetadata>, String>> + Send + '_>,
    >;
    /// Report presence (heartbeat) to keep the registration active.
    fn heartbeat(
        &self,
        id: Uuid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>>;
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

impl AgentRegistry for MockRegistry {
    fn register(
        &self,
        metadata: AgentMetadata,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async move {
            self.agents.insert(metadata.id, metadata);
            Ok(())
        })
    }

    fn get_agent(
        &self,
        id: Uuid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<AgentMetadata>, String>> + Send + '_>,
    > {
        Box::pin(async move { Ok(self.agents.get(&id).map(|a| a.clone())) })
    }

    fn search(
        &self,
        capability: &str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<AgentMetadata>, String>> + Send + '_>,
    > {
        let capability = capability.to_owned();
        Box::pin(async move {
            Ok(self
                .agents
                .iter()
                .filter(|a| a.capabilities.contains(&capability))
                .map(|a| a.clone())
                .collect())
        })
    }

    fn heartbeat(
        &self,
        _id: Uuid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async move {
            // Mock registry doesn't implement TTL for now
            Ok(())
        })
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

impl AgentRegistry for ShardedRegistry {
    fn register(
        &self,
        metadata: AgentMetadata,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async move {
            let shard = self.get_shard(metadata.id);
            shard.insert(metadata.id, (metadata, std::time::Instant::now()));
            Ok(())
        })
    }

    fn get_agent(
        &self,
        id: Uuid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<AgentMetadata>, String>> + Send + '_>,
    > {
        Box::pin(async move {
            let shard = self.get_shard(id);
            Ok(shard.get(&id).map(|pair| pair.0.clone()))
        })
    }

    fn search(
        &self,
        capability: &str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<AgentMetadata>, String>> + Send + '_>,
    > {
        let capability = capability.to_owned();
        Box::pin(async move {
            let mut results = Vec::new();
            for shard in &self.shards {
                for pair in shard {
                    if pair.0.capabilities.contains(&capability) {
                        results.push(pair.0.clone());
                    }
                }
            }
            Ok(results)
        })
    }

    fn heartbeat(
        &self,
        id: Uuid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async move {
            let shard = self.get_shard(id);
            if let Some(mut pair) = shard.get_mut(&id) {
                pair.1 = std::time::Instant::now();
                Ok(())
            } else {
                Err("Agent not found".to_string())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_mock_registry() {
        let registry = MockRegistry::new();
        let agent = AgentMetadata {
            id: Uuid::new_v4(),
            name: "test_agent".to_owned(),
            capabilities: vec!["llm".to_owned()],
            endpoint: "http://localhost".to_owned(),
            public_key: vec![],
            last_quote: None,
            signature: vec![],
            prev_hash: None,
        };

        registry.register(agent.clone()).await.unwrap();
        let retrieved = registry.get_agent(agent.id).await.unwrap().unwrap();
        assert_eq!(retrieved.name, "test_agent");

        let search_res = registry.search("llm").await.unwrap();
        assert_eq!(search_res.len(), 1);

        registry.heartbeat(agent.id).await.unwrap();
    }

    #[tokio::test]
    async fn test_sharded_registry() {
        let registry = ShardedRegistry::new(2, std::time::Duration::from_secs(10));
        let agent = AgentMetadata {
            id: Uuid::new_v4(),
            name: "sharded_agent".to_owned(),
            capabilities: vec!["db".to_owned()],
            endpoint: "http://localhost".to_owned(),
            public_key: vec![],
            last_quote: None,
            signature: vec![],
            prev_hash: None,
        };

        registry.register(agent.clone()).await.unwrap();
        let retrieved = registry.get_agent(agent.id).await.unwrap().unwrap();
        assert_eq!(retrieved.name, "sharded_agent");

        let search_res = registry.search("db").await.unwrap();
        assert_eq!(search_res.len(), 1);

        registry.heartbeat(agent.id).await.unwrap();
    }
}
