// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation

use crate::metrics::FabricMetrics;
use crate::policy::LocalLlmEngine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Defines the topological scope of the memory fabric.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Topology {
    /// Memory is shared globally across the entire mesh.
    Global,
    /// Memory is partitioned to a specific sub-mesh or context channel.
    Partitioned(String),
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ZeroizedData {
    pub content: Vec<u8>,
}

pub type VersionVector = HashMap<String, u64>;

#[derive(Clone, Serialize, Deserialize)]
pub struct FabricEntry {
    pub version: VersionVector,
    pub data: ZeroizedData,
}

/// A trait for pluggable data storage engines.
pub trait DataStore: Send + Sync {
    fn get(&self, namespace: &str, key: &str) -> Option<Vec<u8>>;
    fn put(&self, namespace: &str, key: &str, data: Vec<u8>, version: VersionVector) -> bool;
    fn delete(&self, namespace: &str, key: &str);

    // For vector DB support
    fn vector_search(
        &self,
        namespace: &str,
        embedding: &[f32],
        top_k: usize,
    ) -> Vec<(String, f32, Vec<u8>)>;

    // Enclave Sealing (Persistent Backing)
    fn snapshot_to_disk(&self, path: &str) -> Result<(), String>;
    fn restore_from_disk(&self, path: &str) -> Result<(), String>;
}

/// The core in-memory CRDT key-value store.
#[derive(Default, Clone)]
pub struct KvStore {
    namespaces: Arc<RwLock<HashMap<String, HashMap<String, FabricEntry>>>>,
}

impl KvStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl DataStore for KvStore {
    fn get(&self, namespace: &str, key: &str) -> Option<Vec<u8>> {
        let guard = self.namespaces.read().unwrap();
        guard
            .get(namespace)
            .and_then(|ns| ns.get(key))
            .map(|entry| entry.data.content.clone())
    }

    fn put(&self, namespace: &str, key: &str, data: Vec<u8>, version: VersionVector) -> bool {
        let mut guard = self.namespaces.write().unwrap();
        let ns = guard.entry(namespace.to_string()).or_default();

        if let Some(existing) = ns.get(key) {
            // Check if existing version dominates the new version
            let mut dominates = true;
            for (node, v) in &version {
                if existing.version.get(node).copied().unwrap_or(0) < *v {
                    dominates = false;
                    break;
                }
            }
            if dominates {
                return false; // Reject older or concurrent-but-dominated updates
            }
        }

        if ns.len() >= 1000 {
            // Basic bound eviction (pseudo-random due to HashMap iteration order)
            if let Some(key_to_remove) = ns.keys().next().cloned() {
                ns.remove(&key_to_remove);
            }
        }

        ns.insert(
            key.to_string(),
            FabricEntry {
                version,
                data: ZeroizedData { content: data },
            },
        );
        true
    }

    fn delete(&self, namespace: &str, key: &str) {
        let mut guard = self.namespaces.write().unwrap();
        if let Some(ns) = guard.get_mut(namespace) {
            ns.remove(key);
        }
    }

    fn vector_search(
        &self,
        _namespace: &str,
        _embedding: &[f32],
        _top_k: usize,
    ) -> Vec<(String, f32, Vec<u8>)> {
        // KV store doesn't support vector search natively; return empty.
        vec![]
    }

    fn snapshot_to_disk(&self, path: &str) -> Result<(), String> {
        // Mock Enclave Sealing: encrypts memory using a hardware-derived AES-256-GCM key
        // and persists it to disk.
        let guard = self.namespaces.read().unwrap();
        let serialized = serde_json::to_vec(&*guard).map_err(|e| e.to_string())?;

        // Mock encryption step
        let sealed_data = format!("SEALED_ENCLAVE_BLOB:{}", hex::encode(&serialized));
        std::fs::write(path, sealed_data).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn restore_from_disk(&self, path: &str) -> Result<(), String> {
        let sealed_data = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        if !sealed_data.starts_with("SEALED_ENCLAVE_BLOB:") {
            return Err("Invalid sealed enclave format".to_string());
        }
        let hex_data = &sealed_data["SEALED_ENCLAVE_BLOB:".len()..];
        let serialized = hex::decode(hex_data).map_err(|e| e.to_string())?;

        let restored_namespaces: HashMap<String, HashMap<String, FabricEntry>> =
            serde_json::from_slice(&serialized).map_err(|e| e.to_string())?;

        let mut guard = self.namespaces.write().unwrap();
        *guard = restored_namespaces;
        Ok(())
    }
}

type VectorNamespaces = HashMap<String, HashMap<String, (Vec<f32>, FabricEntry)>>;

/// A mocked Vector Database for semantic similarity search.
#[derive(Default, Clone)]
pub struct VectorStore {
    // namespace -> (key -> (embedding, entry))
    namespaces: Arc<RwLock<VectorNamespaces>>,
}

impl VectorStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
        if a.len() != b.len() || a.is_empty() {
            return 0.0;
        }
        let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm_a == 0.0 || norm_b == 0.0 {
            0.0
        } else {
            dot / (norm_a * norm_b)
        }
    }
}

impl DataStore for VectorStore {
    fn get(&self, namespace: &str, key: &str) -> Option<Vec<u8>> {
        let guard = self.namespaces.read().unwrap();
        guard
            .get(namespace)
            .and_then(|ns| ns.get(key))
            .map(|(_, entry)| entry.data.content.clone())
    }

    fn put(&self, namespace: &str, key: &str, data: Vec<u8>, version: VersionVector) -> bool {
        let mut guard = self.namespaces.write().unwrap();
        let ns = guard.entry(namespace.to_string()).or_default();

        if let Some((_, existing)) = ns.get(key) {
            let mut dominates = true;
            for (node, v) in &version {
                if existing.version.get(node).copied().unwrap_or(0) < *v {
                    dominates = false;
                    break;
                }
            }
            if dominates {
                return false;
            }
        }

        if ns.len() >= 1000 {
            let key_to_remove = ns.keys().next().cloned();
            if let Some(k) = key_to_remove {
                ns.remove(&k);
            }
        }

        let embedding = vec![0.1f32; 128];
        ns.insert(
            key.to_string(),
            (
                embedding,
                FabricEntry {
                    version,
                    data: ZeroizedData { content: data },
                },
            ),
        );
        true
    }

    fn delete(&self, namespace: &str, key: &str) {
        let mut guard = self.namespaces.write().unwrap();
        if let Some(ns) = guard.get_mut(namespace) {
            ns.remove(key);
        }
    }

    fn vector_search(
        &self,
        namespace: &str,
        embedding: &[f32],
        top_k: usize,
    ) -> Vec<(String, f32, Vec<u8>)> {
        let guard = self.namespaces.read().unwrap();
        if let Some(ns) = guard.get(namespace) {
            let mut results: Vec<_> = ns
                .iter()
                .map(|(k, (emb, entry))| {
                    let score = Self::cosine_similarity(embedding, emb);
                    (k.clone(), score, entry.data.content.clone())
                })
                .collect();

            // Sort descending by score
            results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            results.truncate(top_k);
            results
        } else {
            vec![]
        }
    }

    fn snapshot_to_disk(&self, path: &str) -> Result<(), String> {
        // Mock Enclave Sealing for Vector Store
        let guard = self.namespaces.read().unwrap();
        let serialized = serde_json::to_vec(&*guard).map_err(|e| e.to_string())?;
        let sealed_data = format!("SEALED_ENCLAVE_BLOB:{}", hex::encode(&serialized));
        std::fs::write(path, sealed_data).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn restore_from_disk(&self, path: &str) -> Result<(), String> {
        let sealed_data = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        if !sealed_data.starts_with("SEALED_ENCLAVE_BLOB:") {
            return Err("Invalid sealed enclave format".to_string());
        }
        let hex_data = &sealed_data["SEALED_ENCLAVE_BLOB:".len()..];
        let serialized = hex::decode(hex_data).map_err(|e| e.to_string())?;

        let restored_namespaces: VectorNamespaces =
            serde_json::from_slice(&serialized).map_err(|e| e.to_string())?;

        let mut guard = self.namespaces.write().unwrap();
        *guard = restored_namespaces;
        Ok(())
    }
}

/// The MemoryStore wraps the topology configuration and the active data store backend.
#[derive(Clone)]
pub struct MemoryStore {
    pub topology: Topology,
    pub backend: Arc<dyn DataStore>,
}

impl MemoryStore {
    pub fn new_kv(topology: Topology) -> Self {
        Self {
            topology,
            backend: Arc::new(KvStore::new()),
        }
    }

    pub fn new_vector(topology: Topology) -> Self {
        Self {
            topology,
            backend: Arc::new(VectorStore::new()),
        }
    }

    pub fn get(&self, namespace: &str, key: &str) -> Option<Vec<u8>> {
        self.backend.get(namespace, key)
    }

    pub fn put(&self, namespace: &str, key: &str, data: Vec<u8>, version: VersionVector) -> bool {
        self.backend.put(namespace, key, data, version)
    }

    pub fn delete(&self, namespace: &str, key: &str) {
        self.backend.delete(namespace, key)
    }

    pub fn vector_search(
        &self,
        namespace: &str,
        embedding: &[f32],
        top_k: usize,
    ) -> Vec<(String, f32, Vec<u8>)> {
        self.backend.vector_search(namespace, embedding, top_k)
    }

    pub fn snapshot_to_disk(&self, path: &str) -> Result<(), String> {
        self.backend.snapshot_to_disk(path)
    }

    pub fn restore_from_disk(&self, path: &str) -> Result<(), String> {
        self.backend.restore_from_disk(path)
    }

    pub fn start_distillation_loop(self: Arc<Self>, metrics: Arc<FabricMetrics>) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(60));
            let llm = LocalLlmEngine::new("Llama-3-8B-Instruct-Q4");
            loop {
                ticker.tick().await;
                tracing::info!("Running autonomous memory distillation loop");
                // Mocking the semantic summarization of old context
                let _ = llm.evaluate_intent("distill_context").await;
                metrics.inc_memory_distillation();
            }
        });
    }
}
