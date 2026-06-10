// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation

use crate::metrics::FabricMetrics;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use openhttpa_proto::ProvenanceChain;
use openhttpa_tee::provider::TeeProvider;
use rocksdb::{DB, Options};
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KeyDerivationPolicy {
    /// Derive the key once at startup and cache it.
    StartupCached,
    /// Derive the key dynamically on every cryptographic operation.
    PerTransaction,
}

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

// ── Cryptographic helpers ────────────────────────────────────────────────────

/// Derives a per-entry AES-256 key using HKDF-SHA384.
///
/// # Key Separation (SEC-07)
///
/// Using a single master key for all entries in a namespace means that
/// compromising one entry's key (e.g., via a side-channel attack or a key
/// oracle) compromises all entries.  Per-entry key derivation ensures that
/// each entry has an independent encryption key.
///
/// ## KDF construction
/// ```text
/// PRK  = HKDF-Extract(salt = nonce[0..12], IKM = master_key[0..32])
/// key  = HKDF-Expand(PRK, info = "sdmf_entry_v1" || u32be(ns_len) || ns
///                              || u32be(key_len) || key, len = 32)
/// ```
///
/// Using the random nonce as the HKDF salt ensures each `put()` operation
/// produces a distinct entry key even if the master key and namespace/key are
/// identical, providing forward secrecy at the entry level.
///
/// # Errors
///
/// Returns an error string if HKDF extraction or expansion fails.
fn derive_entry_key(
    master_key: &[u8; 32],
    namespace: &str,
    entry_key: &str,
    nonce: &[u8; 12],
) -> Result<[u8; 32], String> {
    use openhttpa_crypto::HkdfExpander;

    // HKDF-Extract: salt = nonce, IKM = master_key
    let expander = HkdfExpander::extract_sha384(nonce, master_key)
        .map_err(|e| format!("HKDF extract failed for SDMF entry key: {e}"))?;

    // Build a domain-separated info string:
    // "sdmf_entry_v1" || u32be(len(namespace)) || namespace || u32be(len(key)) || key
    let mut info: Vec<u8> =
        Vec::with_capacity(b"sdmf_entry_v1".len() + 4 + namespace.len() + 4 + entry_key.len());
    info.extend_from_slice(b"sdmf_entry_v1");
    info.extend_from_slice(&(namespace.len() as u32).to_be_bytes());
    info.extend_from_slice(namespace.as_bytes());
    info.extend_from_slice(&(entry_key.len() as u32).to_be_bytes());
    info.extend_from_slice(entry_key.as_bytes());

    let derived = expander
        .expand(&info, 32)
        .map_err(|e| format!("HKDF expand failed for SDMF entry key: {e}"))?;

    let mut out = [0u8; 32];
    out.copy_from_slice(derived.as_bytes());
    Ok(out)
}

/// Derive the namespace-level master key from the TEE.
///
/// # Errors
///
/// Returns an error if TEE key derivation fails.  **Never falls back to a
/// zero key** (SEC-07 / SEC-05): callers must propagate the error rather
/// than silently degrading to an all-zero key.
fn derive_master_key(tee: &dyn TeeProvider) -> Result<[u8; 32], String> {
    tee.derive_key(b"sdmf_rocksdb_master_key").map_err(|e| {
        tracing::error!(
            "TEE key derivation failed for SDMF master key — refusing operation to \
             prevent encryption with a predictable fallback key: {e}"
        );
        format!("TEE derive_key failed: {e}")
    })
}

/// Encrypt `data` for the given entry.  Returns `(ciphertext, nonce_bytes)`.
fn encrypt_entry(
    master_key: &[u8; 32],
    namespace: &str,
    key: &str,
    data: &[u8],
) -> Result<([u8; 12], Vec<u8>), String> {
    let mut nonce_bytes = [0u8; 12];
    {
        use rand::RngExt;
        rand::rng().fill(&mut nonce_bytes);
    }

    // SEC-07: derive a fresh per-entry key using the random nonce as HKDF salt.
    let entry_key = derive_entry_key(master_key, namespace, key, &nonce_bytes)?;
    let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&entry_key);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // SEC-05: propagate encryption failure instead of storing empty/corrupt data.
    let ciphertext = cipher.encrypt(nonce, data).map_err(|e| {
        tracing::error!(
            namespace = %namespace,
            key = %key,
            "AES-256-GCM encryption failed — refusing to store entry: {e}"
        );
        format!("AES-GCM encrypt failed: {e}")
    })?;

    Ok((nonce_bytes, ciphertext))
}

/// Decrypt `sealed` for the given entry.  Returns plaintext bytes.
fn decrypt_entry(
    master_key: &[u8; 32],
    namespace: &str,
    key: &str,
    sealed: &SealedData,
) -> Option<Vec<u8>> {
    let entry_key = derive_entry_key(master_key, namespace, key, &sealed.nonce)
        .map_err(|e| {
            tracing::error!(
                namespace = %namespace,
                key = %key,
                "SDMF entry key derivation failed during decrypt: {e}"
            );
        })
        .ok()?;
    let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&entry_key);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(&sealed.nonce);
    cipher.decrypt(nonce, sealed.ciphertext.as_ref()).ok()
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
    fn get(&self, namespace: &str, key: &str, tee: &dyn TeeProvider) -> Option<Vec<u8>> {
        let guard = self.namespaces.read().unwrap();
        guard
            .get(namespace)
            .and_then(|ns| ns.get(key))
            .and_then(|entry| {
                let master_key = derive_master_key(tee)
                    .map_err(|e| tracing::error!("KvStore::get key derivation failed: {e}"))
                    .ok()?;
                decrypt_entry(&master_key, namespace, key, &entry.data)
            })
    }

    fn put(
        &self,
        namespace: &str,
        key: &str,
        data: Vec<u8>,
        version: VersionVector,
        provenance: Option<ProvenanceChain>,
        tee: &dyn TeeProvider,
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
            // DES-05: Deterministic eviction — remove the lexicographically-smallest
            // key rather than relying on HashMap iteration order (which is
            // hash-dependent and can evict recently-inserted entries).
            if let Some(key_to_remove) = ns.keys().min().cloned() {
                ns.remove(&key_to_remove);
            }
        }

        let master_key = match derive_master_key(tee) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!(
                    "KvStore::put master key derivation failed — entry not stored: {e}"
                );
                return false;
            }
        };

        let (nonce_bytes, ciphertext) = match encrypt_entry(&master_key, namespace, key, &data) {
            Ok(pair) => pair,
            Err(_) => return false, // error already logged inside encrypt_entry
        };

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
    fn get(&self, namespace: &str, key: &str, tee: &dyn TeeProvider) -> Option<Vec<u8>> {
        let guard = self.namespaces.read().unwrap();
        guard
            .get(namespace)
            .and_then(|ns| ns.get(key))
            .and_then(|(_, entry)| {
                let master_key = derive_master_key(tee)
                    .map_err(|e| tracing::error!("VectorStore::get key derivation failed: {e}"))
                    .ok()?;
                decrypt_entry(&master_key, namespace, key, &entry.data)
            })
    }

    fn put(
        &self,
        namespace: &str,
        key: &str,
        data: Vec<u8>,
        version: VersionVector,
        provenance: Option<ProvenanceChain>,
        tee: &dyn TeeProvider,
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
            // DES-05: Deterministic eviction — remove the lexicographically-smallest
            // key (same policy as KvStore; avoids hash-order non-determinism).
            let key_to_remove = ns.keys().min().cloned();
            if let Some(k) = key_to_remove {
                ns.remove(&k);
            }
        }

        let master_key = match derive_master_key(tee) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!("VectorStore::put master key derivation failed: {e}");
                return false;
            }
        };

        let (nonce_bytes, ciphertext) = match encrypt_entry(&master_key, namespace, key, &data) {
            Ok(pair) => pair,
            Err(_) => return false,
        };

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
        tee: &dyn TeeProvider,
    ) -> Vec<(String, f32, Vec<u8>)> {
        let guard = self.namespaces.read().unwrap();
        if let Some(ns) = guard.get(namespace) {
            let master_key = match derive_master_key(tee) {
                Ok(k) => k,
                Err(e) => {
                    tracing::error!("VectorStore::vector_search key derivation failed: {e}");
                    return vec![];
                }
            };
            let mut results: Vec<_> = ns
                .iter()
                .filter_map(|(k, (emb, entry))| {
                    decrypt_entry(&master_key, namespace, k, &entry.data).map(|pt| {
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

/// A persistent DataStore using RocksDB.
pub struct RocksDbStore {
    db: DB,
    derivation_policy: KeyDerivationPolicy,
    cached_key: Option<[u8; 32]>,
}

impl RocksDbStore {
    pub fn new(
        path: &str,
        derivation_policy: KeyDerivationPolicy,
        tee: &dyn TeeProvider,
    ) -> Result<Self, String> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, path).map_err(|e| e.to_string())?;

        let cached_key = if let KeyDerivationPolicy::StartupCached = derivation_policy {
            // SEC-05/07: Do not fall back to all-zeros if TEE key derivation fails.
            // An all-zero master key would make all entries trivially decryptable.
            Some(derive_master_key(tee)?)
        } else {
            None
        };

        Ok(Self {
            db,
            derivation_policy,
            cached_key,
        })
    }
}

impl DataStore for RocksDbStore {
    fn get(&self, namespace: &str, key: &str, tee: &dyn TeeProvider) -> Option<Vec<u8>> {
        let db_key = format!("{}:{}", namespace, key);
        self.db
            .get(db_key.as_bytes())
            .unwrap_or(None)
            .and_then(|val| {
                let entry: FabricEntry = serde_json::from_slice(&val).ok()?;
                let master_key = match self.derivation_policy {
                    KeyDerivationPolicy::StartupCached => {
                        // cached_key is guaranteed Some(...) when StartupCached
                        // (set in RocksDbStore::new — would have errored if TEE failed).
                        self.cached_key?
                    }
                    KeyDerivationPolicy::PerTransaction => derive_master_key(tee)
                        .map_err(|e| {
                            tracing::error!("RocksDbStore::get key derivation failed: {e}");
                        })
                        .ok()?,
                };
                decrypt_entry(&master_key, namespace, key, &entry.data)
            })
    }

    fn put(
        &self,
        namespace: &str,
        key: &str,
        data: Vec<u8>,
        version: VersionVector,
        provenance: Option<ProvenanceChain>,
        tee: &dyn TeeProvider,
    ) -> bool {
        let db_key = format!("{}:{}", namespace, key);

        // Retrieve existing and check version vectors
        if let Some(existing_entry) = self
            .db
            .get(db_key.as_bytes())
            .ok()
            .flatten()
            .and_then(|val| serde_json::from_slice::<FabricEntry>(&val).ok())
        {
            let mut dominates = true;
            for (node, v) in &version {
                if existing_entry.version.get(node).copied().unwrap_or(0) < *v {
                    dominates = false;
                    break;
                }
            }
            if dominates {
                return false;
            }
        }

        let master_key = match self.derivation_policy {
            KeyDerivationPolicy::StartupCached => match self.cached_key {
                Some(k) => k,
                None => {
                    tracing::error!(
                        "RocksDbStore::put: cached key is None (StartupCached policy) — \
                             this indicates a bug in RocksDbStore::new"
                    );
                    return false;
                }
            },
            KeyDerivationPolicy::PerTransaction => match derive_master_key(tee) {
                Ok(k) => k,
                Err(e) => {
                    tracing::error!("RocksDbStore::put key derivation failed: {e}");
                    return false;
                }
            },
        };

        let (nonce_bytes, ciphertext) = match encrypt_entry(&master_key, namespace, key, &data) {
            Ok(pair) => pair,
            Err(_) => return false,
        };

        let entry = FabricEntry {
            version,
            data: SealedData {
                ciphertext,
                nonce: nonce_bytes,
            },
            provenance,
        };

        if let Ok(serialized) = serde_json::to_vec(&entry) {
            self.db.put(db_key.as_bytes(), serialized).is_ok()
        } else {
            false
        }
    }

    fn delete(&self, namespace: &str, key: &str) {
        let db_key = format!("{}:{}", namespace, key);
        let _ = self.db.delete(db_key.as_bytes());
    }

    fn vector_search(
        &self,
        _namespace: &str,
        _embedding: &[f32],
        _top_k: usize,
        _tee: &dyn TeeProvider,
    ) -> Vec<(String, f32, Vec<u8>)> {
        vec![]
    }

    fn snapshot_to_disk(&self, _path: &str, _tee: &dyn TeeProvider) -> Result<(), String> {
        Ok(()) // RocksDB is already persistent
    }

    fn restore_from_disk(&self, _path: &str, _tee: &dyn TeeProvider) -> Result<(), String> {
        Ok(()) // RocksDB is already persistent
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

    pub fn new_rocksdb(
        topology: Topology,
        tee_provider: Arc<dyn TeeProvider>,
        path: &str,
        derivation_policy: KeyDerivationPolicy,
    ) -> Result<Self, String> {
        Ok(Self {
            topology,
            backend: Arc::new(RocksDbStore::new(
                path,
                derivation_policy,
                tee_provider.as_ref(),
            )?),
            tee_provider,
        })
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
