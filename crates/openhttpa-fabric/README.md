# OpenHTTPA Fabric (Secure Distributed Memory Fabric)

The `openhttpa-fabric` crate powers the Secure Distributed Memory Fabric (SDMF), the persistence layer of the OpenHTTPA ecosystem.

## Architecture

The fabric abstracts key-value storage backends (e.g., `RocksDbStore`, `KvStore`, `VectorStore`) and automatically wraps them in cryptographic security bounds bound to the physical hardware.

### Key Derivation Policies

When writing data to the fabric, the data is encrypted via AES-256-GCM. The encryption key used is NOT hardcoded in the application layer. Instead, it is dynamically derived from the underlying CPU's secure enclave (Intel SGX or TDX).

You can configure the `KeyDerivationPolicy` when initializing the store:

1. **`StartupCached`**: The enclave is polled once at startup. The derived key is kept in memory and reused for all subsequent read/write operations. Fast, but leaves the key in the enclave's volatile memory pool.
2. **`PerTransaction`**: The enclave is polled and an instruction (`EGETKEY` on SGX or `TDCALL` on TDX) is fired for _every_ read/write operation. Extremely secure, as the key only exists transiently during the cryptographic operation, but incurs a performance hit due to context switching.

### Version Vectors and Conflict Resolution

The SDMF is built for distributed swarms. Every `put` operation requires a `VersionVector` (a `HashMap<String, u64>` mapping Agent IDs to their respective logical clocks).

If two agents try to write to the same namespace/key concurrently, the fabric evaluates the version vector. A write is only committed if the incoming version vector strictly dominates the existing version vector. If it is stale or a concurrent fork, the write is rejected.
