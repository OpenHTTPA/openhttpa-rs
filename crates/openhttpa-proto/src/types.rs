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
            Self::V1 => f.write_str(crate::constants::PROTOCOL_VERSION_V1),
            Self::V2 => f.write_str(crate::constants::PROTOCOL_VERSION_V2),
        }
    }
}

impl std::str::FromStr for ProtocolVersion {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            crate::constants::PROTOCOL_VERSION_V1 => Ok(Self::V1),
            crate::constants::PROTOCOL_VERSION_V2 => Ok(Self::V2),
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

    /// Returns `true` if this suite is deprecated and should no longer be
    /// negotiated in new sessions (INFO-01).
    ///
    /// Callers should emit a diagnostic (e.g. `tracing::warn!`) and consider
    /// rejecting the suite depending on their security policy.
    #[must_use]
    #[allow(deprecated)] // P256Aes256GcmSha256 retained for wire-format compatibility (S-04)
    pub const fn is_legacy(&self) -> bool {
        matches!(self, Self::P256Aes256GcmSha256)
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
            Self::X25519MlKem768Aes256GcmSha384 => {
                crate::constants::CIPHER_SUITE_X25519_ML_KEM768_AES256GCM_SHA384
            }
            Self::P384MlKem1024Aes256GcmSha384 => {
                crate::constants::CIPHER_SUITE_P384_ML_KEM1024_AES256GCM_SHA384
            }
            Self::X25519Aes256GcmSha384 => crate::constants::CIPHER_SUITE_X25519_AES256GCM_SHA384,
            Self::P256Aes256GcmSha256 => crate::constants::CIPHER_SUITE_P256_AES256GCM_SHA256,
            Self::X25519ChaCha20Poly1305Sha256 => {
                crate::constants::CIPHER_SUITE_X25519_CHACHA20POLY1305_SHA256
            }
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for CipherSuite {
    type Err = ();
    #[allow(deprecated)] // P256Aes256GcmSha256 retained for wire-format compatibility (S-04)
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            crate::constants::CIPHER_SUITE_X25519_ML_KEM768_AES256GCM_SHA384 => {
                Ok(Self::X25519MlKem768Aes256GcmSha384)
            }
            crate::constants::CIPHER_SUITE_P384_ML_KEM1024_AES256GCM_SHA384 => {
                Ok(Self::P384MlKem1024Aes256GcmSha384)
            }
            crate::constants::CIPHER_SUITE_X25519_AES256GCM_SHA384 => {
                Ok(Self::X25519Aes256GcmSha384)
            }
            crate::constants::CIPHER_SUITE_P256_AES256GCM_SHA256 => {
                // INFO-01: Wire-level deny for deprecated cipher suite after configurable cutoff.
                if std::env::var("OPENHTTPA_ALLOW_DEPRECATED_CIPHERS").unwrap_or_default() == "1" {
                    Ok(Self::P256Aes256GcmSha256)
                } else {
                    Err(())
                }
            }
            crate::constants::CIPHER_SUITE_X25519_CHACHA20POLY1305_SHA256 => {
                Ok(Self::X25519ChaCha20Poly1305Sha256)
            }
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
            Self::Sgx => crate::constants::QUOTE_TYPE_SGX,
            Self::Tdx => crate::constants::QUOTE_TYPE_TDX,
            Self::SevSnp => crate::constants::QUOTE_TYPE_SEV_SNP,
            Self::TrustZone => crate::constants::QUOTE_TYPE_TRUSTZONE,
            Self::Tpm => crate::constants::QUOTE_TYPE_TPM,
            Self::NvidiaGpu => crate::constants::QUOTE_TYPE_NVIDIA_GPU,
            Self::AwsNitro => crate::constants::QUOTE_TYPE_AWS_NITRO,
            Self::ZkCompressed => crate::constants::QUOTE_TYPE_ZK_COMPRESSED,
            Self::Mock => crate::constants::QUOTE_TYPE_MOCK,
            Self::Unknown(s) => s,
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for QuoteType {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            crate::constants::QUOTE_TYPE_SGX => Self::Sgx,
            crate::constants::QUOTE_TYPE_TDX => Self::Tdx,
            crate::constants::QUOTE_TYPE_SEV_SNP => Self::SevSnp,
            crate::constants::QUOTE_TYPE_TRUSTZONE => Self::TrustZone,
            crate::constants::QUOTE_TYPE_TPM => Self::Tpm,
            crate::constants::QUOTE_TYPE_NVIDIA_GPU => Self::NvidiaGpu,
            crate::constants::QUOTE_TYPE_AWS_NITRO => Self::AwsNitro,
            crate::constants::QUOTE_TYPE_ZK_COMPRESSED => Self::ZkCompressed,
            crate::constants::QUOTE_TYPE_MOCK => Self::Mock,
            _ => Self::Unknown(s.to_owned()),
        })
    }
}

/// The format of the attestation quote.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub enum QuoteFormat {
    /// Raw binary quote from the TEE.
    #[default]
    Raw,
    /// Entity Attestation Token (EAT) profile.
    Eat,
    /// An unrecognised format.
    Unknown(String),
}

impl std::fmt::Display for QuoteFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Raw => "raw",
            Self::Eat => "eat",
            Self::Unknown(s) => s.as_str(),
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for QuoteFormat {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "raw" => Self::Raw,
            "eat" => Self::Eat,
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
    /// The format of the quote (e.g., "raw", "eat").
    #[serde(default)]
    pub format: QuoteFormat,
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
    /// Configured padding length to thwart traffic analysis.
    pub padding_length: u16,
}

// ─── Padding & Metadata Protection ───────────────────────────────────────────

/// Configuration for constant-size or block-size padding of encrypted payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PaddingConfig {
    /// No padding applied.
    None,
    /// Pad to the next multiple of the given block size (e.g., 256 or 512).
    BlockSize(usize),
    /// Pad to a constant maximum size.
    ConstantSize(usize),
}

impl Default for PaddingConfig {
    fn default() -> Self {
        Self::BlockSize(256)
    }
}

/// Encapsulated metadata payload for the initial `AtHS` handshake (Encrypted Client Hello).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedHelloPayload {
    /// The actual inner headers (JSON or SFV serialized).
    pub inner_headers: Vec<u8>,
    /// Flag indicating whether this is a dummy cover traffic request.
    pub is_cover_traffic: bool,
}

/// Configuration for Oblivious HTTPA (OHTTPA) relays.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OhttpRelayConfig {
    /// The relay endpoint URI.
    pub relay_uri: String,
    /// Whether to enforce IP address stripping.
    pub enforce_ip_stripping: bool,
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
    fn atb_id_uniqueness() {
        // Each call to AtbId::new() must produce a unique ID.
        let ids: Vec<AtbId> = (0..10).map(|_| AtbId::new()).collect();
        let unique: std::collections::HashSet<String> =
            ids.iter().map(std::string::ToString::to_string).collect();
        assert_eq!(unique.len(), 10, "All generated AtbIds must be unique");
    }

    #[test]
    fn atb_id_as_uuid() {
        let id = AtbId::new();
        let uuid = id.as_uuid();
        assert_eq!(id.to_string(), uuid.to_string());
    }

    #[test]
    fn cipher_suite_display() {
        assert_eq!(
            CipherSuite::X25519MlKem768Aes256GcmSha384.to_string(),
            "X25519_ML_KEM768_AES256GCM_SHA384"
        );
    }

    #[test]
    fn cipher_suite_from_str_round_trips() {
        let suites = [
            CipherSuite::X25519MlKem768Aes256GcmSha384,
            CipherSuite::P384MlKem1024Aes256GcmSha384,
            CipherSuite::X25519Aes256GcmSha384,
            CipherSuite::X25519ChaCha20Poly1305Sha256,
        ];
        for suite in &suites {
            let s = suite.to_string();
            let parsed: CipherSuite = s.parse().expect("should parse");
            assert_eq!(*suite, parsed);
        }
    }

    #[test]
    fn cipher_suite_from_str_denies_deprecated() {
        // No env override → deprecated cipher must be rejected.
        // temp_env handles the unsafe env mutation internally.
        temp_env::with_var_unset("OPENHTTPA_ALLOW_DEPRECATED_CIPHERS", || {
            let result: Result<CipherSuite, _> = "P256_AES256GCM_SHA256".parse();
            assert!(result.is_err());
        });

        // With the opt-in env var set, deprecated cipher must be accepted.
        temp_env::with_var("OPENHTTPA_ALLOW_DEPRECATED_CIPHERS", Some("1"), || {
            let result: Result<CipherSuite, _> = "P256_AES256GCM_SHA256".parse();
            assert!(result.is_ok());
        });
    }

    #[test]
    fn cipher_suite_numeric_ids_unique() {
        // Each cipher suite must have a unique numeric ID.
        let suites = CipherSuite::preferred_list();
        let ids: Vec<u16> = suites.iter().map(|s| s.numeric_id()).collect();
        let unique: std::collections::HashSet<u16> = ids.iter().copied().collect();
        assert_eq!(
            ids.len(),
            unique.len(),
            "All cipher suite IDs must be unique"
        );
    }

    #[test]
    fn preferred_list_starts_with_pqc() {
        let list = CipherSuite::preferred_list();
        assert!(list[0].is_post_quantum());
    }

    #[test]
    fn protocol_version_from_str_round_trip() {
        let versions = [
            (ProtocolVersion::V1, "httpa/1"),
            (ProtocolVersion::V2, "openhttpa"),
        ];
        for (ver, s) in &versions {
            let parsed: ProtocolVersion = s.parse().expect("should parse");
            assert_eq!(*ver, parsed);
            assert_eq!(ver.to_string(), *s);
        }
    }

    #[test]
    fn protocol_version_from_str_unknown_returns_err() {
        let result: Result<ProtocolVersion, _> = "unknown/v99".parse();
        assert!(result.is_err());
    }

    #[test]
    fn atb_creation_serde_round_trip() {
        let variants = [AtbCreation::New, AtbCreation::Reuse, AtbCreation::Shared];
        for v in &variants {
            let json = serde_json::to_vec(v).unwrap();
            let decoded: AtbCreation = serde_json::from_slice(&json).unwrap();
            assert_eq!(*v, decoded);
        }
    }

    #[test]
    fn atb_termination_serde_round_trip() {
        let variants = [
            AtbTermination::Cleanup,
            AtbTermination::Destroy,
            AtbTermination::Keep,
        ];
        for v in &variants {
            let json = serde_json::to_vec(v).unwrap();
            let decoded: AtbTermination = serde_json::from_slice(&json).unwrap();
            assert_eq!(*v, decoded);
        }
    }

    #[test]
    fn session_ticket_serde_round_trip() {
        let ticket = SessionTicket {
            ticket: vec![0x01, 0x02, 0x03],
            lifetime: 3600,
            cipher_suite: CipherSuite::X25519MlKem768Aes256GcmSha384,
            rtt0_eligible: true,
        };
        let json = serde_json::to_vec(&ticket).unwrap();
        let decoded: SessionTicket = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.lifetime, 3600);
        assert!(decoded.rtt0_eligible);
        assert_eq!(decoded.ticket, vec![0x01, 0x02, 0x03]);
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
            format: QuoteFormat::Raw,
            raw: Bytes::from_static(b"hello"),
            qudd: Bytes::new(),
            collateral_uris: vec![],
        };
        assert!(!quote.raw_base64().is_empty());
    }

    #[test]
    fn attest_quote_serde_with_collateral_uris() {
        let quote = AttestQuote {
            quote_type: QuoteType::Tdx,
            format: QuoteFormat::Raw,
            raw: Bytes::from_static(b"raw"),
            qudd: Bytes::from_static(b"qudd"),
            collateral_uris: vec!["https://collateral.intel.com/crl.pem".to_owned()],
        };
        let json = serde_json::to_vec(&quote).unwrap();
        let decoded: AttestQuote = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.quote_type, QuoteType::Tdx);
        assert_eq!(decoded.collateral_uris.len(), 1);
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

    #[test]
    fn attest_base_record_not_expired() {
        let rec = AttestBaseRecord {
            id: AtbId::new(),
            service_uri: "https://example.com/api".to_owned(),
            created_at: SystemTime::now(),
            max_age: Duration::from_secs(3600),
            policy: AtbPolicy::default(),
            terminated: false,
        };
        assert!(!rec.is_expired());
    }

    #[test]
    fn atb_policy_default_values() {
        let policy = AtbPolicy::default();
        assert!(policy.direct_attestation);
        assert!(!policy.allow_untrusted_requests);
    }

    #[test]
    fn provenance_chain_append_and_query() {
        let mut chain = ProvenanceChain::default();
        assert!(chain.origin().is_none());
        assert!(chain.previous().is_none());

        let agent = AgentMetadata {
            id: uuid::Uuid::new_v4(),
            name: "agent-alpha".to_owned(),
            capabilities: vec!["compute".to_owned()],
            endpoint: "https://alpha.example.com".to_owned(),
            public_key: vec![],
            last_quote: None,
            signature: vec![],
            prev_hash: None,
        };
        chain.append(agent);

        assert!(chain.contains_agent("agent-alpha"));
        assert!(!chain.contains_agent("agent-beta"));
        assert!(chain.origin().is_some());
        assert_eq!(chain.origin().unwrap().name, "agent-alpha");
    }

    #[test]
    fn federation_manifest_validity() {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let valid_manifest = FederationManifest {
            version: 1,
            issued_at: now_secs - 60,
            expires_at: now_secs + 3600,
            entries: vec![],
            signature: ManifestSignature::default(),
        };
        assert!(valid_manifest.is_valid());

        let expired_manifest = FederationManifest {
            version: 1,
            issued_at: now_secs - 7200,
            expires_at: now_secs - 3600,
            entries: vec![],
            signature: ManifestSignature::default(),
        };
        assert!(!expired_manifest.is_valid());
    }

    #[test]
    fn quote_type_from_str_round_trip() {
        let types = [
            ("sgx", QuoteType::Sgx),
            ("tdx", QuoteType::Tdx),
            ("sev_snp", QuoteType::SevSnp),
            ("mock", QuoteType::Mock),
        ];
        for (s, qt) in &types {
            let parsed: QuoteType = s.parse().unwrap();
            assert_eq!(parsed, *qt);
            assert_eq!(qt.to_string(), *s);
        }
    }

    #[test]
    fn quote_type_unknown_fallback() {
        let qt: QuoteType = "custom_tee".parse().unwrap();
        assert!(matches!(qt, QuoteType::Unknown(_)));
        assert_eq!(qt.to_string(), "custom_tee");
    }

    #[test]
    fn tee_class_from_quote_type() {
        assert_eq!(TeeClass::from(&QuoteType::Tdx), TeeClass::IntelTdx);
        assert_eq!(TeeClass::from(&QuoteType::SevSnp), TeeClass::AmdSevSnp);
        assert_eq!(TeeClass::from(&QuoteType::Mock), TeeClass::Mock);
        assert_eq!(
            TeeClass::from(&QuoteType::Unknown("foo".to_owned())),
            TeeClass::Unknown
        );
    }
}

/// Metadata for an agent in the mesh.
///
/// # Provenance signing (P-01)
///
/// When appended to a [`ProvenanceChain`], each agent MUST sign the entry
/// with its identity key (the secret corresponding to `public_key`).  The
/// signature covers `SHA-384(transcript_hash ‖ prev_hash_or_zeros)` using
/// ML-DSA-44 (ML-DSA post-quantum signature scheme):
///
/// ```text
/// sig = ML-DSA-Sign(identity_secret, SHA-384(transcript_hash ‖ prev_hash))
/// ```
///
/// Receivers MUST verify `signature` over that input before trusting
/// any claim in this entry.  An empty `signature` is valid only for the
/// first hop in a chain that was not yet signed (e.g. in unit tests with
/// `MockTeeProvider`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMetadata {
    pub id: Uuid,
    pub name: String,
    pub capabilities: Vec<String>,
    pub endpoint: String,
    /// Agent's ML-DSA post-quantum public key (raw bytes).  Used to verify
    /// `signature` in the provenance chain.
    pub public_key: Vec<u8>,
    /// Most recent TEE attestation quote.
    pub last_quote: Option<AttestQuote>,
    /// ML-DSA signature over `SHA-384(transcript_hash ‖ prev_hash)`,
    /// produced by this agent's identity key.  Empty for unsigned entries
    /// (e.g. mock/test environments).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signature: Vec<u8>,
    /// SHA-384 hash (48 bytes) of the previous provenance entry, or all-zeros
    /// for the first hop.  Chains entries together to prevent insertion/reordering.
    /// Serialised as a base64url byte string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<Vec<u8>>,
}

impl AgentMetadata {
    /// Returns an anonymized version of this metadata to prevent mesh topology leakage.
    /// This strips identifiable information and replaces the UUID with an ephemeral one.
    #[must_use]
    pub fn anonymize(&self) -> Self {
        Self {
            id: Uuid::new_v4(), // Ephemeral ID
            name: "anonymous_agent".to_owned(),
            capabilities: self.capabilities.clone(),
            endpoint: String::new(),
            public_key: self.public_key.clone(), // Keep public key for signature verification
            last_quote: None, // Strip quote to prevent hardware tracking (P-01/P-03)
            signature: self.signature.clone(),
            prev_hash: self.prev_hash.clone(),
        }
    }
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

    /// Returns a new `ProvenanceChain` where all agent metadata has been anonymized.
    #[must_use]
    pub fn anonymize(&self) -> Self {
        Self {
            hops: self.hops.iter().map(AgentMetadata::anonymize).collect(),
        }
    }
}

// ─── TEE class (vendor-neutral) ──────────────────────────────────────────────

/// A vendor-neutral classification of the TEE hardware type.
///
/// Used in [`EatClaims`] to allow federation policies to match across vendors
/// without requiring quote-type-specific logic in the policy layer.
///
/// This is the M4 **Multi-Vendor TEE Federation** extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TeeClass {
    /// Intel® SGX (Software Guard Extensions).
    IntelSgx,
    /// Intel® TDX (Trust Domain Extensions).
    IntelTdx,
    /// AMD SEV-SNP (Secure Encrypted Virtualization — Secure Nested Paging).
    AmdSevSnp,
    /// Arm `TrustZone` / OP-TEE.
    ArmTrustZone,
    /// NVIDIA Confidential Computing GPU (H100/H200 Hopper).
    NvidiaGpu,
    /// AWS Nitro Enclaves.
    AwsNitro,
    /// TPM 2.0.
    Tpm,
    /// Simulated/mock — **never trust in production**.
    Mock,
    /// An unrecognised TEE class.
    Unknown,
}

impl std::fmt::Display for TeeClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::IntelSgx => "intel_sgx",
            Self::IntelTdx => "intel_tdx",
            Self::AmdSevSnp => "amd_sev_snp",
            Self::ArmTrustZone => "arm_trustzone",
            Self::NvidiaGpu => "nvidia_gpu",
            Self::AwsNitro => "aws_nitro",
            Self::Tpm => "tpm",
            Self::Mock => "mock",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

impl From<&QuoteType> for TeeClass {
    fn from(qt: &QuoteType) -> Self {
        match qt {
            QuoteType::Sgx => Self::IntelSgx,
            QuoteType::Tdx => Self::IntelTdx,
            QuoteType::SevSnp => Self::AmdSevSnp,
            QuoteType::TrustZone => Self::ArmTrustZone,
            QuoteType::NvidiaGpu => Self::NvidiaGpu,
            QuoteType::AwsNitro => Self::AwsNitro,
            QuoteType::Tpm => Self::Tpm,
            QuoteType::Mock => Self::Mock,
            QuoteType::ZkCompressed | QuoteType::Unknown(_) => Self::Unknown,
        }
    }
}

// ─── Federation manifest (M4) ─────────────────────────────────────────────────

/// A single entry in a [`FederationManifest`].
///
/// Declares that a specific TEE class with a particular measurement hash is
/// trusted within this federation.  Measurements are vendor-specific:
/// - Intel TDX: MRTD (48-byte SHA-384)
/// - AMD SEV-SNP: measurement (48 bytes from the SNP attestation report)
/// - Intel SGX: MRENCLAVE (32 bytes)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationEntry {
    /// The TEE class this entry applies to.
    pub tee_class: TeeClass,
    /// Expected measurement hash (hex-encoded).  An empty string acts as a
    /// wildcard — use with extreme caution in production.
    pub measurement_hex: String,
    /// Human-readable label (e.g. "prod-tdx-west").
    pub label: String,
    /// Minimum Security Version Number acceptable for this entry.
    pub min_svn: Option<u16>,
    /// Whether debug-mode enclaves are permitted for this entry.
    pub allow_debug: bool,
}

/// The signature on a [`FederationManifest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ManifestSignature {
    /// A single operator offline signature.
    Operator {
        /// Operator's ML-DSA-44 or Ed25519 public key (raw bytes).
        public_key: Vec<u8>,
        /// Signature over `SHA-384(canonical_json(entries ‖ version ‖ issued_at))`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        signature: Vec<u8>,
    },
    /// A quorum of mesh nodes counter-signing the manifest.
    Quorum {
        /// The M-of-N threshold required.
        threshold: u32,
        /// List of (`public_key`, `signature`) pairs.
        signatures: Vec<(Vec<u8>, Vec<u8>)>,
    },
}

impl Default for ManifestSignature {
    fn default() -> Self {
        Self::Operator {
            public_key: vec![],
            signature: vec![],
        }
    }
}

/// A signed cross-vendor trust policy.
///
/// The manifest is produced by a human operator and signed offline with an
/// Ed25519 or ML-DSA key.  Mesh nodes load it at startup (or hot-reload it)
/// and pass it to [`FederatedVerifier`] via [`FederationTrustBundle`].
///
/// # Wire format
///
/// Serialised as JSON for human readability; the `signature` covers
/// `SHA-384(canonical_json(entries ‖ version ‖ issued_at))` produced by the
/// operator's identity key, or a quorum of mesh node keys.
///
/// [`FederatedVerifier`]: (openhttpa_attestation::federation::FederatedVerifier)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationManifest {
    /// Manifest format version (currently `1`).
    pub version: u32,
    /// Unix timestamp when this manifest was issued.
    pub issued_at: u64,
    /// Unix timestamp after which this manifest must not be trusted.
    pub expires_at: u64,
    /// Ordered list of trusted TEE entries.
    pub entries: Vec<FederationEntry>,
    /// The signature(s) authenticating this manifest.
    #[serde(default)]
    pub signature: ManifestSignature,
}

impl FederationManifest {
    /// Returns `true` if this manifest has not yet expired.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now < self.expires_at
    }

    /// Look up all entries matching a given [`TeeClass`].
    #[must_use]
    pub fn entries_for(&self, class: TeeClass) -> Vec<&FederationEntry> {
        self.entries
            .iter()
            .filter(|e| e.tee_class == class)
            .collect()
    }

    /// Return `true` if the manifest contains at least one entry for `class`
    /// whose `measurement_hex` matches `measurement_hex` (case-insensitive)
    /// or is a wildcard (empty string).
    #[must_use]
    pub fn allows(
        &self,
        class: TeeClass,
        measurement_hex: &str,
        svn: Option<u16>,
        is_debug: bool,
    ) -> bool {
        self.entries_for(class).iter().any(|e| {
            // Wildcard entry allows any measurement.
            let measurement_ok = e.measurement_hex.is_empty()
                || e.measurement_hex.eq_ignore_ascii_case(measurement_hex);
            let svn_ok = match (e.min_svn, svn) {
                (Some(min), Some(actual)) => actual >= min,
                (Some(_), None) => false, // policy requires SVN but none present
                (None, _) => true,
            };
            let debug_ok = !is_debug || e.allow_debug;
            measurement_ok && svn_ok && debug_ok
        })
    }
}

/// Bundles the per-vendor root CA certificates together with the signed
/// [`FederationManifest`] for use by [`FederatedVerifier`].
///
/// [`FederatedVerifier`]: (openhttpa_attestation::federation::FederatedVerifier)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FederationTrustBundle {
    /// Intel PCK/DCAP root CA (DER-encoded X.509).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub intel_root_ca: Vec<u8>,
    /// AMD ARK (AMD Root Key) root CA (DER-encoded X.509).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub amd_root_ca: Vec<u8>,
    /// NVIDIA GPU root CA (DER-encoded X.509).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nvidia_root_ca: Vec<u8>,
    /// The signed federation manifest.
    pub manifest: Option<FederationManifest>,
}

// ─── Attestation Results (EAT-aligned) ──────────────────────────────────────

/// Standard EAT (Entity Attestation Token) claims as per RFC 9334.
///
/// All fields are optional to allow partial claims from diverse TEE backends.
/// Verifiers SHOULD enforce `exp` when token lifetime is bounded.
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
    /// Issued At (Unix timestamp). RFC 9334 §4.2.1.
    pub iat: Option<u64>,
    /// Expiry (Unix timestamp). RFC 9334 §4.2.1 — REQUIRED when token
    /// lifetime is bounded. Verifiers MUST reject tokens where
    /// `exp <= now()` unless operating in a time-insensitive context.
    pub exp: Option<u64>,
    /// Vendor-neutral TEE class (M4 Multi-Vendor Federation extension).
    ///
    /// Set by each verifier after a successful verification so that
    /// downstream consumers (e.g. `FederatedVerifier`, `AgentNode`) can act
    /// on the TEE type without inspecting raw quote bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tee_class: Option<TeeClass>,
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

/// Describes the detected security posture of the client after handshake negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientSecurityPosture {
    /// Client provided a genuine hardware TEE quote (Mutual Attestation).
    MutualTee(TeeClass),
    /// Client provided a Mock/Simulated quote for testing/demo.
    SimulatedTee,
    /// Client provided no quote, operating in a non-TEE environment (One-directional from Server).
    OneDirectional,
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
