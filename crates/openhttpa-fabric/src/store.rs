// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation

use crate::metrics::FabricMetrics;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use openhttpa_proto::ProvenanceChain;
use openhttpa_tee::provider::TeeProvider;
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
pub struct SealedData {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
}

pub type VersionVector = HashMap<String, u64>;

#[derive(Clone, Serialize, Deserialize)]
pub struct FabricEntry {
    pub version: VersionVector,
    pub data: SealedData,
    pub provenance: Option<ProvenanceChain>,
}

/// A trait for pluggable data storage engines.
pub trait DataStore: Send + Sync {
    fn get(&self, namespace: &str, key: &str, tee: &dyn TeeProvider) -> Option<Vec<u8>>;
    fn put(
        &self,
        namespace: &str,
        key: &str,
        data: Vec<u8>,
        version: VersionVector,
        provenance: Option<ProvenanceChain>,
        tee: &dyn TeeProvider,
    ) -> bool;
    fn delete(&self, namespace: &str, key: &str);

    // For vector DB support
    fn vector_search(
        &self,
        namespace: &str,
        embedding: &[f32],
        top_k: usize,
        tee: &dyn TeeProvider,
    ) -> Vec<(String, f32, Vec<u8>)>;

    // Enclave Sealing (Persistent Backing)
    fn snapshot_to_disk(&self, path: &str, tee: &dyn TeeProvider) -> Result<(), String>;
    fn restore_from_disk(&self, path: &str, tee: &dyn TeeProvider) -> Result<(), String>;
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
    fn get(&self, namespace: &str, key: &str, _tee: &dyn TeeProvider) -> Option<Vec<u8>> {
        let guard = self.namespaces.read().unwrap();
        guard
            .get(namespace)
            .and_then(|ns| ns.get(key))
            .and_then(|entry| {
                // Decrypt memory using mock fixed key for now since TeeProvider doesn't provide
                // an ephemeral AES key yet. In a real impl, we'd fetch an ephemeral key from the TEE.
                let key =
                    aes_gcm::Key::<Aes256Gcm>::from_slice(b"01234567890123456789012345678901");
                let cipher = Aes256Gcm::new(key);
                let nonce = Nonce::from_slice(&entry.data.nonce);
                cipher.decrypt(nonce, entry.data.ciphertext.as_ref()).ok()
            })
    }

    fn put(
        &self,
        namespace: &str,
        key: &str,
        data: Vec<u8>,
        version: VersionVector,
        provenance: Option<ProvenanceChain>,
        _tee: &dyn TeeProvider,
    ) -> bool {
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

        let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(b"01234567890123456789012345678901");
        let cipher = Aes256Gcm::new(aes_key);
        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, data.as_ref()).unwrap_or_default();

        ns.insert(
            key.to_string(),
            FabricEntry {
                version,
                data: SealedData {
                    ciphertext,
                    nonce: nonce_bytes,
                },
                provenance,
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
        _tee: &dyn TeeProvider,
    ) -> Vec<(String, f32, Vec<u8>)> {
        // KV store doesn't support vector search natively; return empty.
        vec![]
    }

    fn snapshot_to_disk(&self, path: &str, tee: &dyn TeeProvider) -> Result<(), String> {
        // Enclave Sealing: encrypts memory using a hardware-derived key
        let guard = self.namespaces.read().unwrap();
        let serialized = serde_json::to_vec(&*guard).map_err(|e| e.to_string())?;

        let sealed_data = tee.seal_data(&serialized).map_err(|e| e.to_string())?;
        std::fs::write(path, sealed_data).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn restore_from_disk(&self, path: &str, tee: &dyn TeeProvider) -> Result<(), String> {
        let sealed_data = std::fs::read(path).map_err(|e| e.to_string())?;

        let serialized = tee.unseal_data(&sealed_data).map_err(|e| e.to_string())?;

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
    fn get(&self, namespace: &str, key: &str, _tee: &dyn TeeProvider) -> Option<Vec<u8>> {
        let guard = self.namespaces.read().unwrap();
        guard
            .get(namespace)
            .and_then(|ns| ns.get(key))
            .and_then(|(_, entry)| {
                let key =
                    aes_gcm::Key::<Aes256Gcm>::from_slice(b"01234567890123456789012345678901");
                let cipher = Aes256Gcm::new(key);
                let nonce = Nonce::from_slice(&entry.data.nonce);
                cipher.decrypt(nonce, entry.data.ciphertext.as_ref()).ok()
            })
    }

    fn put(
        &self,
        namespace: &str,
        key: &str,
        data: Vec<u8>,
        version: VersionVector,
        provenance: Option<ProvenanceChain>,
        _tee: &dyn TeeProvider,
    ) -> bool {
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

        let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(b"01234567890123456789012345678901");
        let cipher = Aes256Gcm::new(aes_key);
        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, data.as_ref()).unwrap_or_default();

        let embedding = vec![0.1f32; 128];
        ns.insert(
            key.to_string(),
            (
                embedding,
                FabricEntry {
                    version,
                    data: SealedData {
                        ciphertext,
                        nonce: nonce_bytes,
                    },
                    provenance,
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
        _tee: &dyn TeeProvider,
    ) -> Vec<(String, f32, Vec<u8>)> {
        let guard = self.namespaces.read().unwrap();
        if let Some(ns) = guard.get(namespace) {
            let mut results: Vec<_> = ns
                .iter()
                .filter_map(|(k, (emb, entry))| {
                    let key_aes =
                        aes_gcm::Key::<Aes256Gcm>::from_slice(b"01234567890123456789012345678901");
                    let cipher = Aes256Gcm::new(key_aes);
                    let nonce = Nonce::from_slice(&entry.data.nonce);
                    cipher
                        .decrypt(nonce, entry.data.ciphertext.as_ref())
                        .ok()
                        .map(|pt| {
                            let score = Self::cosine_similarity(embedding, emb);
                            (k.clone(), score, pt)
                        })
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

    fn snapshot_to_disk(&self, path: &str, tee: &dyn TeeProvider) -> Result<(), String> {
        let guard = self.namespaces.read().unwrap();
        let serialized = serde_json::to_vec(&*guard).map_err(|e| e.to_string())?;
        let sealed_data = tee.seal_data(&serialized).map_err(|e| e.to_string())?;
        std::fs::write(path, sealed_data).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn restore_from_disk(&self, path: &str, tee: &dyn TeeProvider) -> Result<(), String> {
        let sealed_data = std::fs::read(path).map_err(|e| e.to_string())?;
        let serialized = tee.unseal_data(&sealed_data).map_err(|e| e.to_string())?;

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
    pub tee_provider: Arc<dyn TeeProvider>,
}

impl MemoryStore {
    pub fn new_kv(topology: Topology, tee_provider: Arc<dyn TeeProvider>) -> Self {
        Self {
            topology,
            backend: Arc::new(KvStore::new()),
            tee_provider,
        }
    }

    pub fn new_vector(topology: Topology, tee_provider: Arc<dyn TeeProvider>) -> Self {
        Self {
            topology,
            backend: Arc::new(VectorStore::new()),
            tee_provider,
        }
    }

    pub fn new_with_backend(
        topology: Topology,
        backend: Arc<dyn DataStore>,
        tee_provider: Arc<dyn TeeProvider>,
    ) -> Self {
        Self {
            topology,
            backend,
            tee_provider,
        }
    }

    pub fn get(&self, namespace: &str, key: &str) -> Option<Vec<u8>> {
        self.backend.get(namespace, key, self.tee_provider.as_ref())
    }

    pub fn put(
        &self,
        namespace: &str,
        key: &str,
        data: Vec<u8>,
        version: VersionVector,
        provenance: Option<ProvenanceChain>,
    ) -> bool {
        self.backend.put(
            namespace,
            key,
            data,
            version,
            provenance,
            self.tee_provider.as_ref(),
        )
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
        self.backend
            .vector_search(namespace, embedding, top_k, self.tee_provider.as_ref())
    }

    pub fn snapshot_to_disk(&self, path: &str) -> Result<(), String> {
        self.backend
            .snapshot_to_disk(path, self.tee_provider.as_ref())
    }

    pub fn restore_from_disk(&self, path: &str) -> Result<(), String> {
        self.backend
            .restore_from_disk(path, self.tee_provider.as_ref())
    }

    pub fn start_distillation_loop(self: Arc<Self>, metrics: Arc<FabricMetrics>) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(60));
            let llm = crate::policy::LocalLlmEngine::new("Llama-3-8B-Instruct-Q4");
            let dummy_measurement = crate::policy::IdentityMeasurement {
                mrenclave: "system_distiller".to_string(),
                mrsigner: "openhttpa".to_string(),
                is_debug: false,
            };
            loop {
                ticker.tick().await;
                tracing::info!("Running autonomous memory distillation loop");
                // Mocking the semantic summarization of old context
                let _ = llm
                    .evaluate_intent(&dummy_measurement, "system", "distill_context")
                    .await;
                metrics.inc_memory_distillation();
            }
        });
    }
}
