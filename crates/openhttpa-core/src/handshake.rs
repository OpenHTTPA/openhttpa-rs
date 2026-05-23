// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! `AtHS` (Attest Handshake) executor — SIGMA-I model.
//!
//! ## SIGMA-I flow
//!
//! ```text
//! Client                           TService
//! ──────                           ────────
//! ← OPTIONS (preflight)
//!                                  → preflight response
//! ← ATTEST (AtHS request)
//!   Attest-Cipher-Suites, Attest-Key-Shares,
//!   Attest-Versions, Attest-Random, ...
//!                                  → 200 OK (AtHS response)
//!                                    Attest-Cipher-Suite, Attest-Key-Share,
//!                                    Attest-Base-ID, Attest-Quotes, ...
//! (both sides derive session keys from hybrid shared secret + transcript)
//! ```

use openhttpa_attestation::{PolicyEngine, QuoteVerifier, RevocationProvider};
pub use openhttpa_crypto::{hkdf::SessionKeys, key_exchange::HybridKemPair};
use openhttpa_proto::{
    AtbId, AttestQuote, CipherSuite, OpenHttpaError, ProtocolVersion, ProvenanceChain,
};
use openhttpa_tee::provider::{QuoteRequest, TeeProvider};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, instrument};

/// Errors that can occur during the `AtHS` phase.
// MED-06: non_exhaustive prevents breaking changes when new variants are added.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("no mutually supported cipher suite")]
    NoCipherSuiteOverlap,
    #[error("no mutually supported protocol version")]
    NoVersionOverlap,
    #[error("key exchange error: {0}")]
    KeyExchange(String),
    #[error("key derivation error: {0}")]
    KeyDerivation(String),
    #[error("serialisation error: {0}")]
    Serialisation(String),
    #[error("attestation required but not provided")]
    AttestationRequired,
    #[error("client attestation verification failed: {0}")]
    Attestation(String),
    #[error("revocation check failed: {0}")]
    Revoked(String),
    #[error("policy violation: {0}")]
    Policy(String),
    #[error("internal protocol error: {0}")]
    Internal(String),
}

impl From<HandshakeError> for OpenHttpaError {
    fn from(e: HandshakeError) -> Self {
        match e {
            HandshakeError::NoCipherSuiteOverlap => Self::NegotiationFailed,
            HandshakeError::NoVersionOverlap => Self::UnsupportedVersion {
                version: String::new(),
            },
            HandshakeError::KeyDerivation(_) => Self::KeyDerivationFailed,
            _ => Self::HandshakeIntegrityFailed,
        }
    }
}

/// Key material that survives a successful `AtHS`.
pub struct AtHsResult {
    pub atb_id: AtbId,
    pub session_keys: SessionKeys,
    pub expires_at: std::time::Instant,
    /// TEE attestation quotes binding the transcript hash, if a provider was
    /// supplied.
    pub server_quotes: Vec<AttestQuote>,
    /// Server random used in the transcript hash.
    pub server_random: [u8; 32],
    /// The computed transcript hash (SHA-384).
    pub transcript_hash: [u8; 48],
    /// Optional ML-DSA signatures.
    pub server_signatures: Vec<Vec<u8>>,
    /// Verified attestation result from the client, if quotes were provided.
    pub client_attestation_result: Option<openhttpa_proto::VerificationResult>,
    /// Optional ZK proof (succinct receipt).
    #[cfg(feature = "zk")]
    pub server_zk_proof: Option<Vec<u8>>,
}

/// JSON-serialisable client key share sent in `Attest-Key-Shares`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientKeyShare {
    pub ecdhe_public: Vec<u8>,
    pub mlkem_public: Vec<u8>,
}

/// JSON-serialisable server key share returned in `Attest-Key-Share`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerKeyShare {
    pub ecdhe_public: Vec<u8>,
    /// ML-KEM public key bytes (encapsulation key).
    pub mlkem_public: Vec<u8>,
    /// ML-KEM ciphertext (encapsulation result targeting client's public key).
    pub mlkem_ciphertext: Vec<u8>,
}

// AttestationPolicy is now replaced by PolicyEngine

/// Request parameters for the server-side `AtHS` execution.
pub struct AtHsRequest<'a> {
    pub client_suites: &'a [CipherSuite],
    pub client_versions: &'a [ProtocolVersion],
    pub client_random: &'a [u8; 32],
    pub client_challenge: &'a [u8; 48], // Hardened: full 48-byte challenge
    pub client_share: &'a ClientKeyShare,
    pub client_quotes: &'a [AttestQuote],
    pub atb_ttl_secs: u64,
    /// Optional provenance chain (Phase 4).
    pub provenance: Option<&'a ProvenanceChain>,
}

/// Server-side `AtHS` executor.
pub struct AtHsExecutor {
    supported_suites: Vec<CipherSuite>,
    supported_versions: Vec<ProtocolVersion>,
    strict_attestation: bool,
    allow_debug: bool,
    policy_engine: Option<Arc<dyn PolicyEngine>>,
    revocation_provider: Option<Arc<dyn RevocationProvider>>,
    #[cfg(feature = "zk")]
    zk_config: Option<openhttpa_zk::ZkConfig>,
}

impl AtHsExecutor {
    /// Create a new executor.  If `supported_suites` is empty, all suites are
    /// accepted.
    #[must_use]
    pub fn new(
        supported_suites: Vec<CipherSuite>,
        supported_versions: Vec<ProtocolVersion>,
    ) -> Self {
        Self::with_config(supported_suites, supported_versions, false, false)
    }

    /// Create a new executor with explicit control over attestation strictness.
    #[must_use]
    pub fn with_strict_mode(
        supported_suites: Vec<CipherSuite>,
        supported_versions: Vec<ProtocolVersion>,
        strict_attestation: bool,
    ) -> Self {
        Self::with_config(
            supported_suites,
            supported_versions,
            strict_attestation,
            false,
        )
    }

    /// Create a new executor with full configuration.
    #[must_use]
    pub fn with_config(
        supported_suites: Vec<CipherSuite>,
        supported_versions: Vec<ProtocolVersion>,
        strict_attestation: bool,
        allow_debug: bool,
    ) -> Self {
        Self::with_all(
            supported_suites,
            supported_versions,
            strict_attestation,
            allow_debug,
            None,
            None,
        )
    }

    /// Create a new executor with full configuration including policy and revocation.
    #[must_use]
    pub fn with_all(
        supported_suites: Vec<CipherSuite>,
        supported_versions: Vec<ProtocolVersion>,
        strict_attestation: bool,
        allow_debug: bool,
        policy_engine: Option<Arc<dyn PolicyEngine>>,
        revocation_provider: Option<Arc<dyn RevocationProvider>>,
    ) -> Self {
        let suites = if supported_suites.is_empty() {
            CipherSuite::preferred_list().to_vec()
        } else {
            supported_suites
        };
        let versions = if supported_versions.is_empty() {
            vec![ProtocolVersion::V2, ProtocolVersion::V1]
        } else {
            supported_versions
        };
        Self {
            supported_suites: suites,
            supported_versions: versions,
            strict_attestation,
            allow_debug,
            policy_engine,
            revocation_provider,
            #[cfg(feature = "zk")]
            zk_config: None,
        }
    }

    /// Enable ZK-proving for this executor.
    #[cfg(feature = "zk")]
    #[must_use]
    pub const fn with_zk(mut self, config: openhttpa_zk::ZkConfig) -> Self {
        self.zk_config = Some(config);
        self
    }

    /// Execute the server side of `AtHS`.
    ///
    /// This function orchestrates the Server-side `AtHS` phase of the SIGMA-I handshake.
    /// It performs the following steps:
    /// 1. **Negotiation**: Picks the first mutually-supported cipher suite and
    ///    protocol version from the client's preferences.
    /// 2. **Key Generation**: Generates a fresh [`HybridKemPair`] (X25519 + ML-KEM).
    /// 3. **Encapsulation**: Encapsulates a shared secret targeting the client's
    ///    provided ML-KEM public key.
    /// 4. **Transcript Binding**: Computes a SHA-384 hash over all public
    ///    parameters of the handshake to ensure integrity.
    /// 5. **Attestation**: If a [`TeeProvider`] is present, generates a quote
    ///    binding the transcript hash (C-TEE-1).
    /// 6. **Key Derivation**: Derives session keys from the hybrid secret and
    ///    the transcript hash.
    ///
    /// # Errors
    /// Returns [`HandshakeError`] if cipher suite negotiation fails, cryptographic
    /// operations fail, or attestation verification rejects the client.
    ///
    /// # Normal Cases
    /// - **Valid Client Preferences**: The client provides valid `Attest-Cipher-Suites` and
    ///   `Attest-Versions`, allowing the server to find a secure overlap.
    /// - **Valid Attestation**: The client's quotes (if provided) are verified against the policy engine
    ///   and revocation lists successfully. The server generates its own quote and returns it.
    /// - **Successful Execution**: The handshake completes, returning the negotiated suite, version,
    ///   the server's key share, and the derived `AtHsResult` containing session keys.
    ///
    /// # Edge Cases
    /// - **No Client Quotes Provided**: If `req.client_quotes` is empty, verification is skipped unless
    ///   the protocol mandates mutual attestation at the transport layer.
    /// - **Strict Attestation Enabled without Provider**: If `strict_attestation` is true but no
    ///   `TeeProvider` is available on the server, the handshake aborts early.
    /// - **Unsupported Cipher Suites**: The client provides strong suites, but the server only supports
    ///   older or mismatched suites, resulting in a negotiation failure.
    ///
    /// # Failure Cases
    /// - **Cryptographic Failures (`KeyExchange`, `KeyDerivation`)**: Errors from `aws-lc-rs` or
    ///   ML-KEM during pair generation or encapsulation will fail the handshake immediately.
    /// - **Attestation Failures (`Attestation`, `Revoked`, `Policy`)**: If the client quote fails verification
    ///   (e.g., unauthorized hardware model, revoked AK, signature mismatch), the connection is rejected.
    /// - **No Overlap (`NoCipherSuiteOverlap`, `NoVersionOverlap`)**: Fails when the client and server
    ///   cannot agree on protocol parameters.
    ///
    /// # Global Impact Cases
    /// - **Session Security Root**: A successful execution establishes the master `SessionKeys` which provide
    ///   confidentiality, integrity, and authenticity for the remainder of the session.
    /// - **Mesh Integrity**: A single bypassed attestation check or leaked transcript hash here could allow
    ///   a rogue node to enter the Attested Agent Mesh, compromising the entire swarm. This function serves
    ///   as the primary ingress firewall for the TEE application.
    ///
    /// # Panics
    ///
    /// Panics if the internal transcript hash does not match the expected SHA-384
    /// output size (48 bytes).
    #[instrument(skip_all)]
    #[allow(clippy::too_many_lines)]
    pub async fn execute_server(
        &self,
        req: &AtHsRequest<'_>,
        tee_provider: Option<&dyn TeeProvider>,
        verifier: Option<&dyn QuoteVerifier>,
        identity_key: Option<&openhttpa_crypto::pqc::MlDsaKeyPair>,
    ) -> Result<(CipherSuite, ProtocolVersion, ServerKeyShare, AtHsResult), HandshakeError> {
        // Negotiate cipher suite (first client preference we support).
        let suite = req
            .client_suites
            .iter()
            .find(|cs| self.supported_suites.contains(cs))
            .copied()
            .ok_or(HandshakeError::NoCipherSuiteOverlap)?;

        // Negotiate version.
        let version = req
            .client_versions
            .iter()
            .find(|v| self.supported_versions.contains(v))
            .copied()
            .ok_or(HandshakeError::NoVersionOverlap)?;

        debug!(suite = ?suite, version = ?version, "negotiated parameters");

        // Generate server KEM pair.
        let server_pair =
            HybridKemPair::generate().map_err(|e| HandshakeError::KeyExchange(e.to_string()))?;
        let server_pub_share = server_pair.public_key_share();

        // Encapsulate against client's ML-KEM public key.
        let client_key_share = openhttpa_crypto::key_exchange::KeyShare {
            ecdhe_public: req.client_share.ecdhe_public.clone(),
            mlkem_public: req.client_share.mlkem_public.clone(),
        };
        let (hybrid_ss, ct_bytes) = server_pair
            .server_combine(&client_key_share)
            .map_err(|e| HandshakeError::KeyExchange(e.to_string()))?;

        // Generate server random (O-03: unified to aws_lc_rs::rand::SystemRandom).
        let mut server_random = [0u8; 32];
        let rng = openhttpa_crypto::rand::SystemRandom::new();
        openhttpa_crypto::rand::SecureRandom::fill(&rng, &mut server_random)
            .map_err(|_| HandshakeError::Internal("entropy source failure".to_string()))?;

        let transcript_bytes = Self::compute_transcript_hash(
            req,
            suite,
            version,
            server_random,
            &server_pub_share,
            &ct_bytes,
        );
        // If client quotes are provided, verify all of them.
        let client_attestation_result = self.verify_client_quotes(req, verifier).await?;

        // Derive session keys.
        let session_keys = SessionKeys::derive(hybrid_ss.as_bytes(), &transcript_bytes)
            .map_err(|e| HandshakeError::KeyDerivation(e.to_string()))?;

        let atb_id = AtbId::new();
        let expires_at =
            std::time::Instant::now() + std::time::Duration::from_secs(req.atb_ttl_secs);

        // Bind the transcript hash into TEE quotes so the client can verify
        // the server's attestation covers this specific session (C-TEE-1).
        // T-10 Hardening: Prepend a domain-separated prefix to the report_data
        // to prevent cross-role quote re-use.
        let server_quotes = if let Some(tee) = tee_provider {
            let mut report_data = [0u8; 64];
            let prefix = b"openhttpa hs server";
            let plen = prefix.len().min(32);
            report_data[..plen].copy_from_slice(&prefix[..plen]);
            let hash_bytes = &transcript_bytes[..transcript_bytes.len().min(48)];
            report_data[32..32 + hash_bytes.len().min(32)]
                .copy_from_slice(&hash_bytes[..hash_bytes.len().min(32)]);
            let req = QuoteRequest { report_data };

            match tee.generate_quotes(&req) {
                Ok(qs) => qs,
                Err(e) if self.strict_attestation => {
                    return Err(HandshakeError::Attestation(e.to_string()))
                }
                Err(_) => vec![],
            }
        } else {
            if self.strict_attestation {
                return Err(HandshakeError::AttestationRequired);
            }
            vec![]
        };

        let mut server_signatures = Vec::new();
        if let Some(key) = identity_key {
            let sig = key
                .sign(&transcript_bytes)
                .map_err(|e| HandshakeError::Internal(format!("ML-DSA sign failed: {e}")))?;
            server_signatures.push(sig);
        }

        #[cfg(feature = "zk")]
        let server_zk_proof =
            if let (Some(ref cfg), Some(quote)) = (&self.zk_config, server_quotes.first()) {
                if cfg.enabled {
                    let input = openhttpa_zk::ZkInput {
                        transcript_hash: transcript_bytes,
                        quote_bytes: quote.raw.to_vec(),
                        report_data: {
                            let mut rd = [0u8; 64];
                            let prefix = b"openhttpa hs server";
                            let plen = prefix.len().min(32);
                            rd[..plen].copy_from_slice(&prefix[..plen]);
                            let hash_bytes = &transcript_bytes[..transcript_bytes.len().min(48)];
                            rd[32..32 + hash_bytes.len().min(32)]
                                .copy_from_slice(&hash_bytes[..hash_bytes.len().min(32)]);
                            rd
                        },
                        oracle_data: None,
                    };
                    match openhttpa_zk::prover::ZkProver::prove(&input) {
                        Ok(receipt) => Some(
                            serde_json::to_vec(&receipt)
                                .map_err(|e| HandshakeError::Serialisation(e.to_string()))?,
                        ),
                        Err(e) => {
                            tracing::error!("ZK-proving failed: {e}");
                            None
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            };

        let result = AtHsResult {
            atb_id,
            session_keys,
            expires_at,
            server_quotes,
            server_random,
            transcript_hash: transcript_bytes,
            server_signatures,
            client_attestation_result,
            #[cfg(feature = "zk")]
            server_zk_proof,
        };
        let server_share = ServerKeyShare {
            ecdhe_public: server_pub_share.ecdhe_public,
            mlkem_public: server_pub_share.mlkem_public,
            mlkem_ciphertext: ct_bytes,
        };

        Ok((suite, version, server_share, result))
    }

    #[allow(clippy::too_many_lines)]
    fn compute_transcript_hash(
        req: &AtHsRequest<'_>,
        suite: CipherSuite,
        version: ProtocolVersion,
        server_random: [u8; 32],
        server_pub_share: &openhttpa_crypto::key_exchange::KeyShare,
        ct_bytes: &[u8],
    ) -> [u8; 48] {
        let mut hasher = Sha384::new();
        hasher.update((req.client_random.len() as u64).to_be_bytes());
        hasher.update(req.client_random);
        hasher.update((req.client_challenge.len() as u64).to_be_bytes());
        hasher.update(req.client_challenge);
        hasher.update((req.client_share.ecdhe_public.len() as u64).to_be_bytes());
        hasher.update(&req.client_share.ecdhe_public);
        hasher.update((req.client_share.mlkem_public.len() as u64).to_be_bytes());
        hasher.update(&req.client_share.mlkem_public);
        hasher.update((server_random.len() as u64).to_be_bytes());
        hasher.update(server_random);
        hasher.update((server_pub_share.ecdhe_public.len() as u64).to_be_bytes());
        hasher.update(&server_pub_share.ecdhe_public);
        hasher.update((ct_bytes.len() as u64).to_be_bytes());
        hasher.update(ct_bytes);
        hasher.update((server_pub_share.mlkem_public.len() as u64).to_be_bytes());
        hasher.update(&server_pub_share.mlkem_public);
        hasher.update(suite.numeric_id().to_be_bytes());
        hasher.update([version.numeric_id()]);

        let transcript_hash = hasher.finalize();
        transcript_hash
            .as_slice()
            .try_into()
            .expect("SHA-384 is 48 bytes")
    }

    async fn verify_client_quotes(
        &self,
        req: &AtHsRequest<'_>,
        verifier: Option<&dyn QuoteVerifier>,
    ) -> Result<Option<openhttpa_proto::VerificationResult>, HandshakeError> {
        let mut composite_result: Option<openhttpa_proto::VerificationResult> = None;
        // Early-exit when no quotes were submitted.
        if req.client_quotes.is_empty() {
            return Ok(None);
        }

        // SA-03: a client that submits attestation quotes MUST have a verifier
        // available on the server side.  Silently skipping verification when
        // `verifier` is `None` would accept any unauthenticated quote, defeating
        // the mutual-attestation guarantee entirely.  This is an unconditional
        // error regardless of `strict_attestation`.
        let v = verifier.ok_or(HandshakeError::AttestationRequired)?;

        for quote in req.client_quotes {
            // Compute the client-side binding hash that the client was expected
            // to embed in its TEE report_data field.  The binding covers all
            // client-contributed public material from the handshake.
            let mut hasher = Sha384::new();
            hasher.update((req.client_random.len() as u64).to_be_bytes());
            hasher.update(req.client_random);
            hasher.update((req.client_challenge.len() as u64).to_be_bytes());
            hasher.update(req.client_challenge);
            hasher.update((req.client_share.ecdhe_public.len() as u64).to_be_bytes());
            hasher.update(&req.client_share.ecdhe_public);
            hasher.update((req.client_share.mlkem_public.len() as u64).to_be_bytes());
            hasher.update(&req.client_share.mlkem_public);

            let client_binding = hasher.finalize();
            let mut report_data = [0u8; 64];
            // T-10 Hardening: Prepend "openhttpa hs client" prefix.
            let prefix = b"openhttpa hs client";
            let plen = prefix.len().min(32);
            report_data[..plen].copy_from_slice(&prefix[..plen]);
            report_data[32..32 + client_binding.len().min(32)]
                .copy_from_slice(&client_binding[..client_binding.len().min(32)]);

            let res = v
                .verify(quote, &report_data)
                .await
                .map_err(|e| HandshakeError::Attestation(e.to_string()))?;

            if let Some(ref mut primary) = composite_result {
                primary.secondary.push(res.clone());
            } else {
                composite_result = Some(res.clone());
            }

            // T-09 Hardening: Verify Freshness (ARL Rollback protection).
            // Reject quotes older than 24 hours to ensure the ARLs used during
            // verification were reasonably current.
            if let Some(iat) = res.claims.iat {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if now > iat && now - iat > 86400 {
                    return Err(HandshakeError::Attestation(
                        "attestation quote has expired (older than 24h)".to_owned(),
                    ));
                }
            }

            res.reject_debug_builds(self.allow_debug)
                .map_err(|e| HandshakeError::Attestation(e.to_string()))?;

            if let Some(ref pe) = self.policy_engine {
                pe.evaluate(&res)
                    .await
                    .map_err(|e| HandshakeError::Policy(e.to_string()))?;
            }

            if let Some(ref provider) = self.revocation_provider {
                provider
                    .check_revocation(&res)
                    .await
                    .map_err(|e| HandshakeError::Revoked(e.to_string()))?;
            }
        }
        Ok(composite_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openhttpa_attestation::{EatClaims, SimplePolicy, VerificationResult};

    fn setup_client() -> (ClientKeyShare, [u8; 32], [u8; 48]) {
        let client_random = [1u8; 32];
        let client_challenge = [2u8; 48];
        let client_pair = HybridKemPair::generate().unwrap();
        let client_pub = client_pair.public_key_share();
        let share = ClientKeyShare {
            ecdhe_public: client_pub.ecdhe_public,
            mlkem_public: client_pub.mlkem_public,
        };
        (share, client_random, client_challenge)
    }

    #[tokio::test]
    async fn executor_derives_session_keys() {
        let executor = AtHsExecutor::new(vec![], vec![]);
        let (client_share, client_random, client_challenge) = setup_client();
        let (suite, ver, _server_share, result) = executor
            .execute_server(
                &AtHsRequest {
                    client_suites: &[CipherSuite::X25519MlKem768Aes256GcmSha384],
                    client_versions: &[ProtocolVersion::V2],
                    client_random: &client_random,
                    client_challenge: &client_challenge,
                    client_share: &client_share,
                    client_quotes: &[],
                    atb_ttl_secs: 3600,
                    provenance: None,
                },
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(suite, CipherSuite::X25519MlKem768Aes256GcmSha384);
        assert_eq!(ver, ProtocolVersion::V2);
        assert_eq!(result.session_keys.client_write_key.len(), 32);
    }

    #[tokio::test]
    #[allow(deprecated)] // S-04: test verifies no-overlap error path; P256 suite intentional
    async fn no_suite_overlap_errors() {
        let executor = AtHsExecutor::new(vec![CipherSuite::P256Aes256GcmSha256], vec![]);
        let (client_share, client_random, client_challenge) = setup_client();
        let result = executor
            .execute_server(
                &AtHsRequest {
                    client_suites: &[CipherSuite::X25519MlKem768Aes256GcmSha384],
                    client_versions: &[ProtocolVersion::V2],
                    client_random: &client_random,
                    client_challenge: &client_challenge,
                    client_share: &client_share,
                    client_quotes: &[],
                    atb_ttl_secs: 3600,
                    provenance: None,
                },
                None,
                None,
                None,
            )
            .await;
        assert!(matches!(result, Err(HandshakeError::NoCipherSuiteOverlap)));
    }

    #[tokio::test]
    async fn no_version_overlap_errors() {
        let executor = AtHsExecutor::new(vec![], vec![ProtocolVersion::V2]);
        let (client_share, client_random, client_challenge) = setup_client();
        let result = executor
            .execute_server(
                &AtHsRequest {
                    client_suites: &[CipherSuite::X25519MlKem768Aes256GcmSha384],
                    client_versions: &[ProtocolVersion::V1],
                    client_random: &client_random,
                    client_challenge: &client_challenge,
                    client_share: &client_share,
                    client_quotes: &[],
                    atb_ttl_secs: 3600,
                    provenance: None,
                },
                None,
                None,
                None,
            )
            .await;
        assert!(matches!(result, Err(HandshakeError::NoVersionOverlap)));
    }

    #[tokio::test]
    async fn strict_attestation_fails_without_provider() {
        let executor = AtHsExecutor::with_strict_mode(vec![], vec![], true);
        let (client_share, client_random, client_challenge) = setup_client();
        let result = executor
            .execute_server(
                &AtHsRequest {
                    client_suites: &[CipherSuite::X25519MlKem768Aes256GcmSha384],
                    client_versions: &[ProtocolVersion::V2],
                    client_random: &client_random,
                    client_challenge: &client_challenge,
                    client_share: &client_share,
                    client_quotes: &[],
                    atb_ttl_secs: 3600,
                    provenance: None,
                },
                None,
                None,
                None,
            )
            .await;
        assert!(matches!(result, Err(HandshakeError::AttestationRequired)));
    }

    #[tokio::test]
    async fn execute_with_mock_tee_produces_quote() {
        use openhttpa_tee::mock::MockTeeProvider;

        let executor = AtHsExecutor::new(vec![], vec![]);
        let (client_share, client_random, client_challenge) = setup_client();
        let tee = MockTeeProvider::default();
        let (_, _, _, result) = executor
            .execute_server(
                &AtHsRequest {
                    client_suites: &[CipherSuite::X25519MlKem768Aes256GcmSha384],
                    client_versions: &[ProtocolVersion::V2],
                    client_random: &client_random,
                    client_challenge: &client_challenge,
                    client_share: &client_share,
                    client_quotes: &[],
                    atb_ttl_secs: 3600,
                    provenance: None,
                },
                Some(&tee),
                None,
                None,
            )
            .await
            .unwrap();
        // A mock TEE provider should return a quote.
        assert!(!result.server_quotes.is_empty());
    }

    #[tokio::test]
    async fn policy_measurement_mismatch_fails() {
        use openhttpa_attestation::MockVerifier;
        use openhttpa_tee::mock::MockTeeProvider;
        use openhttpa_tee::provider::{QuoteRequest, TeeProvider};
        use sha2::{Digest, Sha384};

        let policy = Arc::new(SimplePolicy {
            allowed_hwmodels: vec!["correct-measurement".to_owned()],
            ..Default::default()
        });
        let executor = AtHsExecutor::with_all(vec![], vec![], false, false, Some(policy), None);

        let (client_share, client_random, client_challenge) = setup_client();

        // Compute report data as the executor expects (H-01/M-01 length-prefixed).
        let mut hasher = Sha384::new();
        hasher.update((client_random.len() as u64).to_be_bytes());
        hasher.update(client_random);
        hasher.update((client_challenge.len() as u64).to_be_bytes());
        hasher.update(client_challenge);
        hasher.update((client_share.ecdhe_public.len() as u64).to_be_bytes());
        hasher.update(&client_share.ecdhe_public);
        hasher.update((client_share.mlkem_public.len() as u64).to_be_bytes());
        hasher.update(&client_share.mlkem_public);
        let client_binding = hasher.finalize();
        let mut report_data = [0u8; 64];
        let prefix = b"openhttpa hs client";
        let plen = prefix.len().min(32);
        report_data[..plen].copy_from_slice(&prefix[..plen]);
        report_data[32..32 + client_binding.len().min(32)]
            .copy_from_slice(&client_binding[..client_binding.len().min(32)]);

        let tee = MockTeeProvider::default();
        let quote = tee.generate_quote(&QuoteRequest { report_data }).unwrap();

        let verifier = MockVerifier::new(VerificationResult {
            claims: EatClaims {
                hwmodel: Some("wrong-measurement".to_owned()),
                ..Default::default()
            },
            ..Default::default()
        });

        let result = executor
            .execute_server(
                &AtHsRequest {
                    client_suites: &[CipherSuite::X25519MlKem768Aes256GcmSha384],
                    client_versions: &[ProtocolVersion::V2],
                    client_random: &client_random,
                    client_challenge: &client_challenge,
                    client_share: &client_share,
                    client_quotes: &[quote],
                    atb_ttl_secs: 3600,
                    provenance: None,
                },
                None,
                Some(&verifier),
                None,
            )
            .await;

        assert!(
            matches!(result, Err(HandshakeError::Policy(m)) if m.contains("unauthorized hardware model"))
        );
    }

    /// SA-03 regression: submitting a client TEE quote without providing a
    /// `QuoteVerifier` must be rejected, not silently accepted.
    ///
    /// Previously the inner `if let Some(v) = verifier` guard skipped all
    /// verification, meaning ANY client-supplied quote would pass when no
    /// verifier was configured — a silent mutual-attestation bypass.
    #[tokio::test]
    async fn client_quotes_without_verifier_rejected() {
        use openhttpa_tee::mock::MockTeeProvider;
        use openhttpa_tee::provider::{QuoteRequest, TeeProvider};

        let executor = AtHsExecutor::new(vec![], vec![]);
        let (client_share, client_random, client_challenge) = setup_client();

        // Build a realistic mock quote bound to this client's public material.
        let mut hasher = Sha384::new();
        hasher.update((client_random.len() as u64).to_be_bytes());
        hasher.update(client_random);
        hasher.update((client_challenge.len() as u64).to_be_bytes());
        hasher.update(client_challenge);
        hasher.update((client_share.ecdhe_public.len() as u64).to_be_bytes());
        hasher.update(&client_share.ecdhe_public);
        hasher.update((client_share.mlkem_public.len() as u64).to_be_bytes());
        hasher.update(&client_share.mlkem_public);
        let client_binding = hasher.finalize();
        let mut report_data = [0u8; 64];
        let prefix = b"openhttpa hs client";
        let plen = prefix.len().min(32);
        report_data[..plen].copy_from_slice(&prefix[..plen]);
        report_data[32..32 + client_binding.len().min(32)]
            .copy_from_slice(&client_binding[..client_binding.len().min(32)]);

        let tee = MockTeeProvider::default();
        let quote = tee.generate_quote(&QuoteRequest { report_data }).unwrap();

        // Execute with a non-empty quote slice but verifier = None.
        // Must return AttestationRequired, NOT Ok(…).
        let result = executor
            .execute_server(
                &AtHsRequest {
                    client_suites: &[CipherSuite::X25519MlKem768Aes256GcmSha384],
                    client_versions: &[ProtocolVersion::V2],
                    client_random: &client_random,
                    client_challenge: &client_challenge,
                    client_share: &client_share,
                    client_quotes: &[quote],
                    atb_ttl_secs: 3600,
                    provenance: None,
                },
                None,
                None, // ← no verifier: must be rejected
                None,
            )
            .await;

        assert!(
            matches!(result, Err(HandshakeError::AttestationRequired)),
            "expected AttestationRequired when quotes submitted but no verifier provided"
        );
    }
}
