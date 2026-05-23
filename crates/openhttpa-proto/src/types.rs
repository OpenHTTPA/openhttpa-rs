// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Core protocol data types for `OpenHTTPA`.
//!
//! Every type that crosses the wire or is persisted in session state lives
//! here. Secret-bearing types implement [`zeroize::ZeroizeOnDrop`] so that
//! key material is wiped from memory when the value is dropped.

use std::time::{Duration, SystemTime};

use base64ct::{Base64, Encoding as _};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ─── Protocol version ────────────────────────────────────────────────────────

/// HTTPA version advertised in `Attest-Versions` / `Attest-Version` headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ProtocolVersion {
    /// HTTPA/1 — TLS-backed, legacy. Not implemented by this library; present
    /// for negotiation rejection purposes only.
    V1,
    /// `OpenHTTPA` — L7 message-level protection, SIGMA key exchange.
    V2,
}

impl ProtocolVersion {
    /// Returns a unique numeric identifier for this version (used in transcript binding).
    #[must_use]
    pub const fn numeric_id(self) -> u8 {
        match self {
            Self::V1 => 0x01,
            Self::V2 => 0x02,
        }
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V1 => f.write_str("httpa/1"),
            Self::V2 => f.write_str("openhttpa"),
        }
    }
}

impl std::str::FromStr for ProtocolVersion {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "httpa/1" => Ok(Self::V1),
            "openhttpa" => Ok(Self::V2),
            _ => Err(()),
        }
    }
}

// ─── Cipher suites ───────────────────────────────────────────────────────────

/// A cipher suite fully describes the key-exchange, AEAD algorithm, and HKDF
/// hash to use for an `OpenHTTPA` session.
///
/// Suites are listed from strongest to weakest; the server picks the highest
/// mutually-supported suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CipherSuite {
    /// Hybrid post-quantum + classical: X25519 + ML-KEM-768, AES-256-GCM,
    /// SHA-384. The **recommended default** suite.
    X25519MlKem768Aes256GcmSha384,
    /// Hybrid post-quantum + classical: P-384 + ML-KEM-1024, AES-256-GCM,
    /// SHA-384.
    P384MlKem1024Aes256GcmSha384,
    /// Classical-only: X25519, AES-256-GCM, SHA-384.
    X25519Aes256GcmSha384,
    /// Classical-only: P-256, AES-256-GCM, SHA-256.
    ///
    /// # Deprecated
    ///
    /// S-04: P-256 provides only 128-bit classical security paired with
    /// AES-256-GCM (256-bit symmetric key) — an asymmetric security-level
    /// mismatch. Prefer [`Self::X25519Aes256GcmSha384`] for classical-only
    /// deployments. This variant is retained only for backward-wire compatibility
    /// and will be removed in a future major version.
    #[deprecated(
        note = "S-04: P-256 provides 128-bit classical security; pair with AES-128-GCM for \
                symmetric parity, or upgrade to X25519Aes256GcmSha384."
    )]
    P256Aes256GcmSha256,
    /// Classical-only: X25519, ChaCha20-Poly1305, SHA-256.
    X25519ChaCha20Poly1305Sha256,
}

impl CipherSuite {
    /// Returns a slice of all suites ordered from most preferred to least
    /// preferred, suitable for inclusion in `Attest-Cipher-Suites`.
    #[must_use]
    pub const fn preferred_list() -> &'static [Self] {
        &[
            Self::X25519MlKem768Aes256GcmSha384,
            Self::P384MlKem1024Aes256GcmSha384,
            Self::X25519Aes256GcmSha384,
            Self::X25519ChaCha20Poly1305Sha256,
            // S-04: P256Aes256GcmSha256 intentionally omitted — P-256 is 128-bit
            // classical security; the mismatch with AES-256-GCM makes it
            // a weaker choice. Retained in the enum for wire compatibility only.
        ]
    }

    /// Returns `true` if this suite uses a post-quantum key-encapsulation
    /// mechanism.
    #[must_use]
    pub const fn is_post_quantum(&self) -> bool {
        matches!(
            self,
            Self::X25519MlKem768Aes256GcmSha384 | Self::P384MlKem1024Aes256GcmSha384
        )
    }

    /// Returns a unique 16-bit numeric identifier for this suite (used in transcript binding).
    #[must_use]
    #[allow(deprecated)] // P256Aes256GcmSha256 retained for wire-format compatibility (S-04)
    pub const fn numeric_id(self) -> u16 {
        match self {
            Self::X25519MlKem768Aes256GcmSha384 => 0x0001,
            Self::P384MlKem1024Aes256GcmSha384 => 0x0002,
            Self::X25519Aes256GcmSha384 => 0x0101,
            Self::P256Aes256GcmSha256 => 0x0102,
            Self::X25519ChaCha20Poly1305Sha256 => 0x0103,
        }
    }
}

impl std::fmt::Display for CipherSuite {
    #[allow(deprecated)] // P256Aes256GcmSha256 retained for wire-format compatibility (S-04)
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::X25519MlKem768Aes256GcmSha384 => "X25519_ML_KEM768_AES256GCM_SHA384",
            Self::P384MlKem1024Aes256GcmSha384 => "P384_ML_KEM1024_AES256GCM_SHA384",
            Self::X25519Aes256GcmSha384 => "X25519_AES256GCM_SHA384",
            Self::P256Aes256GcmSha256 => "P256_AES256GCM_SHA256",
            Self::X25519ChaCha20Poly1305Sha256 => "X25519_CHACHA20POLY1305_SHA256",
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for CipherSuite {
    type Err = ();
    #[allow(deprecated)] // P256Aes256GcmSha256 retained for wire-format compatibility (S-04)
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "X25519_ML_KEM768_AES256GCM_SHA384" => Ok(Self::X25519MlKem768Aes256GcmSha384),
            "P384_ML_KEM1024_AES256GCM_SHA384" => Ok(Self::P384MlKem1024Aes256GcmSha384),
            "X25519_AES256GCM_SHA384" => Ok(Self::X25519Aes256GcmSha384),
            "P256_AES256GCM_SHA256" => Ok(Self::P256Aes256GcmSha256),
            "X25519_CHACHA20POLY1305_SHA256" => Ok(Self::X25519ChaCha20Poly1305Sha256),
            _ => Err(()),
        }
    }
}

// ─── TEE quote type ──────────────────────────────────────────────────────────

/// Identifies the TEE technology that generated an [`AttestQuote`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum QuoteType {
    /// Intel® SGX ECDSA-256 DCAP quote.
    Sgx,
    /// Intel® TDX DCAP quote.
    Tdx,
    /// AMD SEV-SNP attestation report.
    SevSnp,
    /// Arm `TrustZone` / `OP-TEE` attestation.
    TrustZone,
    /// TPM 2.0 PCR quote.
    Tpm,
    /// NVIDIA Hopper GPU attestation (Confidential Computing).
    NvidiaGpu,
    /// AWS Nitro Enclaves attestation document.
    AwsNitro,
    /// ZK-SNARK compressed hardware quote (ZAA).
    ZkCompressed,
    /// Simulated/mock quote — **never trust in production**.
    Mock,
    /// An unrecognised TEE type.
    Unknown(String),
}

impl std::fmt::Display for QuoteType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Sgx => "sgx",
            Self::Tdx => "tdx",
            Self::SevSnp => "sev_snp",
            Self::TrustZone => "trustzone",
            Self::Tpm => "tpm",
            Self::NvidiaGpu => "nvidia_gpu",
            Self::AwsNitro => "aws_nitro",
            Self::ZkCompressed => "zk_compressed",
            Self::Mock => "mock",
            Self::Unknown(s) => s,
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for QuoteType {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "sgx" => Self::Sgx,
            "tdx" => Self::Tdx,
            "sev_snp" => Self::SevSnp,
            "trustzone" => Self::TrustZone,
            "tpm" => Self::Tpm,
            "nvidia_gpu" => Self::NvidiaGpu,
            "aws_nitro" => Self::AwsNitro,
            "zk_compressed" => Self::ZkCompressed,
            "mock" => Self::Mock,
            _ => Self::Unknown(s.to_owned()),
        })
    }
}

// ─── AtB (Attest Base) policy and termination ────────────────────────────────

/// How the client requests an Attest Base to be created or acquired.
///
/// S-05: Explicit discriminant values are assigned so the wire encoding is
/// stable across enum reorderings and additions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AtbCreation {
    /// The `AtB` must be freshly allocated; no residual state from prior clients.
    New = 0,
    /// Reuse an existing clean `AtB` (the TEE must guarantee erasure of prior
    /// state — rarely supportable in practice).
    Reuse = 1,
    /// Accept a shared `AtB`. Use with caution; residual data may be present.
    Shared = 2,
}

/// Selects the security policy for a particular `AtB`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AtbPolicy {
    /// Whether every instance in the `AtB` must be directly attested by the
    /// client (`true`) or only the contact `TService` (`false`, indirect).
    pub direct_attestation: bool,
    /// Whether the `AtB` will accept un-trusted requests (`UtR`).
    /// Disabled by default; enabling weakens the security posture.
    pub allow_untrusted_requests: bool,
}

impl Default for AtbPolicy {
    fn default() -> Self {
        Self {
            direct_attestation: true,
            allow_untrusted_requests: false,
        }
    }
}

/// How the client requests an `AtB` to be terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AtbTermination {
    /// The `AtB` is wiped and may be reused by other clients.
    Cleanup,
    /// The `AtB` is permanently destroyed; cannot be reused or shared.
    Destroy,
    /// The `AtB` is left alive and may be shared. Use with caution.
    Keep,
}

// ─── Attest Base identifier ──────────────────────────────────────────────────

/// An opaque, server-assigned identifier for an allocated Attest Base.
///
/// Included in `Attest-Base-ID` header on all subsequent `OpenHTTPA` requests so
/// that the network infrastructure can route requests to the correct `AtB`
/// without being able to forge or modify it (integrity is verified by the
/// receiving `TService`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AtbId(Uuid);

impl AtbId {
    /// Generate a new random `AtbId`.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Return the inner UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for AtbId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for AtbId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for AtbId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}

// ─── Attest Quote (AtQ) ──────────────────────────────────────────────────────

/// An opaque attestation quote produced by a TEE's quoting service.
///
/// The quote encapsulates: TEE identity, code measurement, security version
/// number, and a user-defined data field (QUDD) that binds the quote to the
/// `OpenHTTPA` handshake AHLs.
///
/// The raw bytes are base64-encoded when placed in `Attest-Quotes` headers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestQuote {
    /// The TEE technology that generated this quote.
    pub quote_type: QuoteType,
    /// Raw quote bytes as returned by the quoting service.
    pub raw: Bytes,
    /// The QUDD embedded in the quote. For `OpenHTTPA` this is `SHA-384(all AHLs
    /// of the current handshake request/response)`.
    pub qudd: Bytes,
    /// Optional URIs to attestation collateral (certificates, CRLs, etc).
    /// Used when collateral is too large to inline.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collateral_uris: Vec<String>,
}

impl AttestQuote {
    /// Encode `raw` as unpadded Base64.
    #[must_use]
    pub fn raw_base64(&self) -> String {
        Base64::encode_string(&self.raw)
    }
}

// ─── Quote user-defined data (QUDD) ─────────────────────────────────────────

/// A 64-byte buffer used as QUDD input to the TEE quoting service.
///
/// For `OpenHTTPA`, this is set to `SHA-384(serialised AHLs)` padded to 64 bytes.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct ReportData([u8; 64]);

impl ReportData {
    /// Construct from a 48-byte SHA-384 digest (zero-padded to 64 bytes).
    #[must_use]
    pub fn from_sha384(digest: &[u8; 48]) -> Self {
        let mut buf = [0u8; 64];
        buf[..48].copy_from_slice(digest);
        Self(buf)
    }

    /// Return a reference to the underlying 64-byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

// ─── Session Ticket (AtST) ──────────────────────────────────────────────────
/// A session ticket allows a client to resume a previous session without a full
/// hybrid KEM handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTicket {
    /// Opaque ticket data (encrypted by the server).
    /// Contains: [Master Secret, Client Identity, Expiry, Nonce Window State].
    pub ticket: Vec<u8>,
    /// Lifetime of the ticket in seconds.
    pub lifetime: u32,
    /// Cipher suite associated with this ticket.
    pub cipher_suite: CipherSuite,
    /// Whether this ticket is eligible for 0-RTT data.
    pub rtt0_eligible: bool,
}

// ─── Attest Ticket (AtT) ─────────────────────────────────────────────────────

/// An Attest Ticket is placed as the **last trailer** of every `OpenHTTPA` request
/// (except `AtHS`) to authenticate the `AHLs` and prevent replay.
///
/// In 0-RTT flights, this is sent in the headers.
///
/// The MAC is computed over all AHLs of the current request with the session
/// key.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct AttestTicket {
    /// Monotonically-increasing nonce for this session.
    pub nonce: u64,
    /// AEAD authentication tag / MAC over the request AHLs.
    pub mac: Vec<u8>,
    /// Optional 0-RTT indicator and binding.
    pub rtt0_salt: Option<[u8; 16]>,
}

// ─── Attest Binder (AtBr) ────────────────────────────────────────────────────

/// Placed as the **last trailer** of every `OpenHTTPA` response (except `AtHS`
/// response) to bind the response to its corresponding request.
///
/// Protects all response `AHLs` and the request `AtT.nonce`.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct AttestBinder {
    /// Echo of the request's `AtT.nonce`.
    pub request_nonce: u64,
    /// MAC over all response AHLs concatenated with `request_nonce`.
    pub mac: Vec<u8>,
}

// ─── Trusted Cargo (TrC) ─────────────────────────────────────────────────────

/// Trusted Cargo carries encrypted metadata (data type, size, key index,
/// ciphertext location) about sensitive payload bytes in the message body.
///
/// `TrC` is placed in a trailer and is itself AEAD-encrypted.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct TrustedCargo {
    /// Key index identifying which derived session key was used.
    pub key_index: u8,
    /// AEAD-encrypted metadata blob. Application-defined format.
    pub encrypted_metadata: Vec<u8>,
    /// AEAD tag for `encrypted_metadata`.
    pub tag: Vec<u8>,
}

// ─── Attest Secret ───────────────────────────────────────────────────────────

/// A single wrapped secret provisioned via `Attest-Secrets`.
///
/// The plaintext secret is AEAD-encrypted with the session key derived during
/// `AtHS`. The index is used to refer to the secret in subsequent `TrR` requests.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct AttestSecret {
    /// Index for later reference.
    pub index: u8,
    /// AEAD-encrypted secret bytes.
    pub ciphertext: Vec<u8>,
    /// AEAD authentication tag.
    pub tag: Vec<u8>,
}

// ─── Attest Base record ──────────────────────────────────────────────────────

/// Server-side record of an allocated Attest Base.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestBaseRecord {
    /// Unique identifier assigned by `TService`.
    pub id: AtbId,
    /// Client identity — URI of the service.
    pub service_uri: String,
    /// When this `AtB` was allocated.
    pub created_at: SystemTime,
    /// How long this `AtB` stays valid.
    pub max_age: Duration,
    /// Security policy in effect for this `AtB`.
    pub policy: AtbPolicy,
    /// Whether this `AtB` has been terminated.
    pub terminated: bool,
}

impl AttestBaseRecord {
    /// Returns `true` if this `AtB` has expired or been terminated.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.terminated
            || SystemTime::now()
                .duration_since(self.created_at)
                .map_or(true, |age| age > self.max_age)
    }
}

// ─── Session-level derived key material ──────────────────────────────────────

/// The symmetric key material derived after a successful `AtHS`.
///
/// Uses `ZeroizeOnDrop` to erase key bytes from memory when the session ends.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeyMaterial {
    /// Master secret from which all other keys are derived.
    pub master_secret: Vec<u8>,
    /// Key used to encrypt/authenticate client-to-server payloads.
    pub client_write_key: Vec<u8>,
    /// Key used to encrypt/authenticate server-to-client payloads.
    pub server_write_key: Vec<u8>,
    /// IV for client-to-server AEAD operations.
    pub client_write_iv: Vec<u8>,
    /// IV for server-to-client AEAD operations.
    pub server_write_iv: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atb_id_round_trip() {
        let id = AtbId::new();
        let s = id.to_string();
        let id2: AtbId = s.parse().unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn cipher_suite_display() {
        assert_eq!(
            CipherSuite::X25519MlKem768Aes256GcmSha384.to_string(),
            "X25519_ML_KEM768_AES256GCM_SHA384"
        );
    }

    #[test]
    fn preferred_list_starts_with_pqc() {
        let list = CipherSuite::preferred_list();
        assert!(list[0].is_post_quantum());
    }

    #[test]
    fn report_data_from_sha384() {
        let digest = [0xabu8; 48];
        let rd = ReportData::from_sha384(&digest);
        assert_eq!(&rd.as_bytes()[..48], &digest[..]);
        assert_eq!(&rd.as_bytes()[48..], &[0u8; 16][..]);
    }

    #[test]
    fn attest_quote_base64() {
        let quote = AttestQuote {
            quote_type: QuoteType::Mock,
            raw: Bytes::from_static(b"hello"),
            qudd: Bytes::new(),
            collateral_uris: vec![],
        };
        assert!(!quote.raw_base64().is_empty());
    }

    #[test]
    fn attest_base_record_expiry() {
        let rec = AttestBaseRecord {
            id: AtbId::new(),
            service_uri: "https://example.com/api".to_owned(),
            created_at: SystemTime::now() - Duration::from_secs(3600),
            max_age: Duration::from_secs(60),
            policy: AtbPolicy::default(),
            terminated: false,
        };
        assert!(rec.is_expired());
    }
}

/// Metadata for an agent in the mesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMetadata {
    pub id: Uuid,
    pub name: String,
    pub capabilities: Vec<String>,
    pub endpoint: String,
    pub public_key: Vec<u8>,
    pub last_quote: Option<AttestQuote>,
}

/// A chain of agents that have handled a request.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProvenanceChain {
    /// Ordered list of agents.
    pub hops: Vec<AgentMetadata>,
}

impl ProvenanceChain {
    /// Append a new agent to the provenance chain.
    pub fn append(&mut self, agent: AgentMetadata) {
        self.hops.push(agent);
    }

    /// Verify that the chain contains the expected agents.
    #[must_use]
    pub fn contains_agent(&self, agent_name: &str) -> bool {
        self.hops.iter().any(|h| h.name == agent_name)
    }

    /// Return the originating agent (first hop).
    #[must_use]
    pub fn origin(&self) -> Option<&AgentMetadata> {
        self.hops.first()
    }

    /// Return the previous agent (last hop before current).
    #[must_use]
    pub fn previous(&self) -> Option<&AgentMetadata> {
        self.hops.last()
    }
}

// ─── Attestation Results (EAT-aligned) ──────────────────────────────────────

/// Standard EAT (Entity Attestation Token) claims as per RFC 9334.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EatClaims {
    /// Unique Entity ID (e.g. MRENCLAVE + MRSIGNER).
    pub ueid: Option<Vec<u8>>,
    /// Hardware Model (e.g. "Intel SGX", "NVIDIA H100").
    pub hwmodel: Option<String>,
    /// Hardware Version / TCB Level.
    pub hwversion: Option<String>,
    /// OEM ID (e.g. "Intel", "NVIDIA").
    pub oemid: Option<String>,
    /// Debug Status (0 = production, 1 = debug/test).
    pub dbgstat: Option<u8>,
    /// Boot Progress / Measurement.
    pub boot_progress: Option<String>,
    /// Security Version of the TCB (maps to platform-specific SVN).
    pub security_version: Option<u16>,
    /// Issued At (Unix timestamp).
    pub iat: Option<u64>,
}

/// The result of a successful quote verification, now EAT-aligned.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VerificationResult {
    /// Raw EAT token (CBOR/COSE), if available.
    pub eat_token: Option<Vec<u8>>,
    /// Structured EAT claims.
    pub claims: EatClaims,
    /// Backward compatibility: TCB status string.
    pub tcb_status: String,
    /// Backward compatibility: Measurement string.
    pub measurement: Option<String>,
    /// Backward compatibility: Signer ID string.
    pub signer_id: Option<String>,
    /// Secondary results for composite TEEs (e.g. GPU, TPM).
    pub secondary: Vec<Self>,
}

impl VerificationResult {
    /// Enforce that production environments do not accept debug builds.
    ///
    /// # Errors
    /// Returns [`Err`] if `dbgstat` indicates a debug build and `allow_debug` is `false`.
    pub fn reject_debug_builds(&self, allow_debug: bool) -> Result<(), crate::error::AttestError> {
        let is_debug = self.claims.dbgstat.unwrap_or(0) != 0;
        if is_debug && !allow_debug {
            return Err(crate::error::AttestError::PolicyViolation(
                "debug-mode enclave quotes are not accepted in production".to_owned(),
            ));
        }
        Ok(())
    }
}
