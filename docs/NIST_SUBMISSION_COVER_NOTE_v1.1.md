# NIST PQC Profile & SP Submission Cover Note (v1.1)

- **Document Package:** OpenHTTPA Post-Quantum Cryptographic Profile & OHMP Transparency Architecture (Revision v1.1)
- **Reference Specifications:** `draft-openhttpa-protocol-02`, `draft-openhttpa-ohmp-00`, `nist/OPENHTTPA-NIST-Technical-Report.md`, `nist/OPENHTTPA-NIST-SP-Security-Guidelines.md` (OHMP profile: `ohmp-rs/docs/nist-ohmp-submission-v1.1.md`)
- **Author:** Gordon King (Valsee LLC / Apache Software Foundation) — `garyw@apache.org`

## Summary of Revision v1.1 Updates

Revision v1.1 of the OpenHTTPA and OHMP NIST cryptographic profile updates our post-quantum attestation-bound transport and transparency log specifications with production security hardenings and empirical multi-architecture silicon test vectors:

### 1. Normative FIPS 204 (ML-DSA-65) Context String Registry

Enforces non-empty, protocol-bound FIPS 204 `ctx` parameters across all six protocol signing operations to eliminate cross-protocol signature replay and transcript confusion between the transport layer and the measurement authority layer:

- **Transport Handshake Transcript:** `"openhttpa/v1/hs-server-transcript"` (33 bytes)
- **Epoch Session Re-binding:** `"openhttpa/v1/epoch-session-binding"` (34 bytes)
- **OHMP Signed Tree Head (STH):** `"openhttpa-ohmp/v1/sth"` (21 bytes)
- **OHMP Delegate Certificate:** `"openhttpa-ohmp/v1/delegate-cert"` (31 bytes)
- **OHMP Workload Endorsement:** `"openhttpa-ohmp/v1/workload-endorsement"` (38 bytes)
- **OHMP Co-Sign Request Envelope:** `"openhttpa-ohmp/v1/cosign-req"` (28 bytes)

### 2. Authenticated Transparency Log Co-Signing & Canonical Merkle Hashing

- All Delegate-MA co-signing requests (`POST /v1/ohmp/tl/cosign-sth`) are wrapped in an `OhmpCosignRequest` signed with ML-DSA-65 under `"openhttpa-ohmp/v1/cosign-req"`, and Root-MAs verify that the Delegate-MA's `OhmpDelegateCert` is already committed in `OHMP-TL` prior to co-signing any workload endorsement.
- Merkle tree leaf hashing is standardized on deterministic UTF-8 Canonical JSON (`SHA256(0x00 || canonical_json_bytes)` per RFC 8785) with interior node prefix `0x01`, preventing leaf/interior second-preimage attacks.
- Client verification latches permanent `EquivocationDetected` states strictly upon verifying valid $M$-of-$N$ (`2M > N`) Root-MA quorum signatures over conflicting STHs, isolating true split-view attacks from transient network errors.

### 3. vTPM-Sealed Post-Quantum Authority Keys & Full Hardware TCB Floors

- Both Root-MA and Delegate-MA ML-DSA-65 signing keys are generated inside the Confidential VM and sealed directly to the hardware vTPM (`/dev/tpmrm0`) bound to Unified Kernel Image (UKI) measurement registers (PCRs 4 and 11 by default, with optional PCR 7 binding), preventing plaintext key extraction from disk.
- Appraisal policies enforce the complete hardware Trusted Computing Base (TCB) vector on AMD SEV-SNP (`min_bootloader`, `min_tee`, `min_snp`, `min_microcode`, `min_abi_major`, `min_abi_minor`) verified against AMD VCEK X.509 extension OIDs (`1.3.6.1.4.1.3704.1.3.{1,2,3,8}` plus `.9` for FMC on Turin), as well as Intel TDX `min_tee_tcb_svn`.

### 4. Cross-Silicon Live Verification & Reproducible Test Vectors (§10a & Appendix A)

- Adds complete wire and transparency log test vectors captured from a live 5-CVM deployment spanning **Intel TDX (`westus3`)** for the 3 Root-MAs (`root-r1`, `root-r2`, `root-r3`) and Delegate-MA and **AMD SEV-SNP (`eastus2`)** for the self-endorsing workload server.
- Documents the verified 4-leaf `OHMP-TL` Signed Tree Head (`tree_size: 4`, SHA-256 root `3f3b1c5743309d7440eeb7f0d81c8f19e6b04d194c1942cfcdff1a3c65e6358b`, leaf index `3`) alongside a comparative analysis of two live AMD SEV-SNP captures sharing the identical paravisor launch measurement (`6587d41e...7f48`) and guest policy (`0x3001f`, ABI `0.31`) across distinct physical EPYC host patch rings (`12/0/28/88` vs. `10/0/23/84`), providing actionable operational guidance for fleet-wide TCB floor management.
- All captured artifacts are verified independently via both the Rust `verify-artifacts` harness and a standalone Python verifier (`dilithium-py` + `cryptography`).
