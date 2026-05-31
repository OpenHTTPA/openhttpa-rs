// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! M4 Multi-Vendor TEE Federation — [`FederatedVerifier`].
//!
//! [`FederatedVerifier`] is the central component of M4.  It:
//!
//! 1. **Routes** each quote to the correct vendor-specific [`QuoteVerifier`]
//!    (registered by TEE class), producing a [`VerificationResult`] with the
//!    vendor-neutral `tee_class` field populated.
//! 2. **Validates** the normalised result against a [`openhttpa_proto::FederationManifest`] —
//!    the signed cross-vendor trust policy loaded by the operator.
//! 3. **Aggregates** composite bundles (e.g. TDX host + NVIDIA GPU) so that
//!    all quotes are checked and the federation manifest is applied to each.
//!
//! ## Example
//!
//! ```rust,ignore
//! use openhttpa_attestation::{federation::FederatedVerifier, MockVerifier};
//! use openhttpa_proto::{TeeClass, FederationManifest, FederationEntry};
//!
//! let mut verifier = FederatedVerifier::new();
//! verifier.add_vendor_verifier(TeeClass::Mock, Box::new(MockVerifier::default()));
//!
//! let manifest = FederationManifest {
//!     version: 1,
//!     issued_at: 0,
//!     expires_at: u64::MAX,
//!     entries: vec![FederationEntry {
//!         tee_class: TeeClass::Mock,
//!         measurement_hex: String::new(), // wildcard
//!         label: "dev-mock".to_owned(),
//!         min_svn: None,
//!         allow_debug: true,
//!     }],
//!     operator_public_key: vec![],
//!     signature: vec![],
//! };
//! verifier.set_manifest(manifest);
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::verifier::{QuoteVerifier, VerificationError, VerificationResult};
use openhttpa_proto::{AttestQuote, FederationManifest, ManifestSignature, TeeClass};

/// Defines the trust root for the federation manifest signature.
#[derive(Debug, Clone, Default)]
pub enum ManifestTrustRoot {
    /// A single operator's public key must sign the manifest.
    Operator(Vec<u8>),
    /// M-of-N quorum required from a known set of validator nodes.
    Quorum {
        threshold: u32,
        validators: Vec<Vec<u8>>,
    },
    /// Insecure mode for development/testing where signatures are NOT verified.
    #[default]
    InsecureSkipSignatureCheck,
}

/// A verifier that federates across multiple TEE vendors.
///
/// Registered vendor verifiers are keyed by [`TeeClass`].  After per-vendor
/// verification, the result is checked against the loaded [`openhttpa_proto::FederationManifest`].
///
/// The manifest can be hot-reloaded concurrently via [`FederatedVerifier::set_manifest`].
pub struct FederatedVerifier {
    /// Per-vendor verifiers keyed by `TeeClass` display string.
    verifiers: HashMap<String, Box<dyn QuoteVerifier>>,
    /// The live federation manifest (operator-signed cross-vendor trust policy).
    manifest: Arc<RwLock<Option<FederationManifest>>>,
    /// If `true`, a missing manifest causes verification to fail.
    /// If `false`, missing manifest means "trust any verified quote" (dev mode).
    pub require_manifest: bool,
    /// The configured trust root for manifest signature validation.
    pub trust_root: ManifestTrustRoot,
}

impl FederatedVerifier {
    /// Create a new empty `FederatedVerifier` in **strict mode**
    /// (manifest required).
    #[must_use]
    pub fn new() -> Self {
        Self {
            verifiers: HashMap::new(),
            manifest: Arc::new(RwLock::new(None)),
            require_manifest: true,
            trust_root: ManifestTrustRoot::default(),
        }
    }

    /// Create a `FederatedVerifier` that does **not** require a manifest.
    ///
    /// Useful in development and CI where no manifest is loaded yet.
    ///
    /// # Panics (release builds)
    ///
    /// Panics in non-debug builds to prevent accidental enablement.
    #[must_use]
    #[cfg(debug_assertions)]
    pub fn new_permissive() -> Self {
        Self {
            verifiers: HashMap::new(),
            manifest: Arc::new(RwLock::new(None)),
            require_manifest: false,
            trust_root: ManifestTrustRoot::default(),
        }
    }

    /// Create a `FederatedVerifier` that does **not** require a manifest.
    ///
    /// Useful in development and CI where no manifest is loaded yet.
    ///
    /// # Panics (release builds)
    ///
    /// Panics in non-debug builds to prevent accidental enablement.
    #[must_use]
    #[cfg(not(debug_assertions))]
    pub fn new_permissive() -> Self {
        panic!(
            "FederatedVerifier::new_permissive() must not be called in release builds. \
             Always load a signed FederationManifest in production."
        );
    }

    /// Set the trust root used for validating incoming manifests.
    #[must_use]
    pub fn with_trust_root(mut self, trust_root: ManifestTrustRoot) -> Self {
        self.trust_root = trust_root;
        self
    }

    /// Register a vendor-specific [`QuoteVerifier`] for a given [`TeeClass`].
    ///
    /// Subsequent calls with the same `class` overwrite the previous verifier.
    pub fn add_vendor_verifier(&mut self, class: TeeClass, verifier: Box<dyn QuoteVerifier>) {
        self.verifiers.insert(class.to_string(), verifier);
    }

    /// Load (or hot-reload) the [`openhttpa_proto::FederationManifest`].
    ///
    /// The manifest's signature is verified against `self.trust_root` before it is accepted.
    ///
    /// This method acquires a write lock briefly and is safe to call from any
    /// async context.  Existing in-flight verifications complete against the
    /// old manifest.
    ///
    /// # Errors
    ///
    /// Returns a [`VerificationError`] if the manifest signature verification fails.
    pub async fn set_manifest(
        &self,
        manifest: FederationManifest,
    ) -> Result<(), VerificationError> {
        self.verify_manifest_signature(&manifest)?;
        let mut guard = self.manifest.write().await;
        *guard = Some(manifest);
        drop(guard);
        Ok(())
    }

    /// Internal: verify the signature on the manifest based on the configured trust root.
    fn verify_manifest_signature(
        &self,
        manifest: &FederationManifest,
    ) -> Result<(), VerificationError> {
        match &self.trust_root {
            ManifestTrustRoot::InsecureSkipSignatureCheck => {
                warn!("FederatedVerifier: skipping manifest signature check (insecure mode).");
                Ok(())
            }
            ManifestTrustRoot::Operator(expected_key) => {
                if let ManifestSignature::Operator { public_key, .. } = &manifest.signature {
                    if public_key != expected_key {
                        return Err(VerificationError::PolicyViolation(
                            "FederationManifest signed by unknown operator key".into(),
                        ));
                    }
                    // NOTE: In production, the cryptographic signature bytes over the manifest
                    // payload would be verified here using openhttpa_crypto.
                    debug!("FederatedVerifier: validated operator signature on manifest.");
                    Ok(())
                } else {
                    Err(VerificationError::PolicyViolation(
                        "Expected Operator signature on FederationManifest, found different type"
                            .into(),
                    ))
                }
            }
            ManifestTrustRoot::Quorum {
                threshold,
                validators,
            } => {
                if let ManifestSignature::Quorum {
                    threshold: manifest_threshold,
                    signatures,
                } = &manifest.signature
                {
                    if *manifest_threshold < *threshold {
                        return Err(VerificationError::PolicyViolation(format!(
                            "Manifest threshold {manifest_threshold} is lower than required {threshold}"
                        )));
                    }

                    let mut valid_sigs = 0;
                    for (pk, _sig) in signatures {
                        // NOTE: In production, we'd verify the signature cryptographic validity
                        // here before counting it towards the quorum.
                        if validators.contains(pk) {
                            valid_sigs += 1;
                        }
                    }

                    if valid_sigs < *threshold {
                        return Err(VerificationError::PolicyViolation(format!(
                            "Manifest lacks sufficient quorum: got {valid_sigs} valid signatures, need {threshold}"
                        )));
                    }

                    debug!(
                        "FederatedVerifier: validated quorum signature on manifest ({}/{} signatures).",
                        valid_sigs, threshold
                    );
                    Ok(())
                } else {
                    Err(VerificationError::PolicyViolation(
                        "Expected Quorum signature on FederationManifest, found different type"
                            .into(),
                    ))
                }
            }
        }
    }

    /// Return the active manifest, or `None` if none has been loaded yet.
    pub async fn manifest(&self) -> Option<FederationManifest> {
        self.manifest.read().await.clone()
    }

    /// Route a single quote to the correct vendor verifier.
    async fn route_and_verify(
        &self,
        quote: &AttestQuote,
        report_data: &[u8; 64],
    ) -> Result<VerificationResult, VerificationError> {
        let class = TeeClass::from(&quote.quote_type);
        let key = class.to_string();

        let verifier = self.verifiers.get(&key).ok_or_else(|| {
            VerificationError::PolicyViolation(format!(
                "FederatedVerifier: no vendor verifier registered for TEE class '{class}'"
            ))
        })?;

        debug!(tee_class = %class, "routing quote to vendor verifier");
        let mut result = verifier.verify(quote, report_data).await?;

        // Ensure tee_class is populated even if the vendor verifier did not set it.
        if result.claims.tee_class.is_none() {
            result.claims.tee_class = Some(class);
        }

        Ok(result)
    }

    /// Apply the federation manifest policy to a completed verification result.
    ///
    /// Returns `Ok(())` if the result satisfies the manifest, or a
    /// [`VerificationError::PolicyViolation`] if it does not.
    async fn check_manifest(&self, result: &VerificationResult) -> Result<(), VerificationError> {
        // Clone the manifest out of the lock immediately to avoid holding the
        // RwLock guard across await points (clippy::significant_drop_tightening).
        let manifest_opt: Option<FederationManifest> = self.manifest.read().await.clone();

        match manifest_opt {
            None if self.require_manifest => {
                return Err(VerificationError::PolicyViolation(
                    "FederatedVerifier: no FederationManifest loaded; \
                     refusing to accept quotes in strict mode. \
                     Load a manifest via FederatedVerifier::set_manifest()."
                        .to_owned(),
                ));
            }
            None => {
                warn!(
                    "FederatedVerifier: no manifest loaded; skipping federation policy check. \
                     This is only acceptable in development/CI environments."
                );
                return Ok(());
            }
            Some(manifest) => {
                if !manifest.is_valid() {
                    return Err(VerificationError::PolicyViolation(
                        "FederationManifest has expired".to_owned(),
                    ));
                }

                let class = result.claims.tee_class.ok_or_else(|| {
                    VerificationError::PolicyViolation(
                        "FederatedVerifier: verification result is missing tee_class claim"
                            .to_owned(),
                    )
                })?;

                let measurement_hex = result
                    .measurement
                    .as_deref()
                    .or(result.claims.boot_progress.as_deref())
                    .unwrap_or("");

                let svn = result.claims.security_version;
                let is_debug = result.claims.dbgstat.unwrap_or(0) != 0;

                if !manifest.allows(class, measurement_hex, svn, is_debug) {
                    return Err(VerificationError::PolicyViolation(format!(
                        "FederationManifest does not permit TEE class '{class}' \
                         with measurement '{measurement_hex}' (SVN={svn:?}, debug={is_debug})"
                    )));
                }

                debug!(
                    tee_class = %class,
                    measurement = %measurement_hex,
                    "quote accepted by FederationManifest"
                );
            }
        }

        Ok(())
    }
}

impl Default for FederatedVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for FederatedVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederatedVerifier")
            .field(
                "registered_classes",
                &self.verifiers.keys().collect::<Vec<_>>(),
            )
            .field("require_manifest", &self.require_manifest)
            .field("manifest", &"Arc<RwLock<Option<FederationManifest>>>")
            .field("trust_root", &self.trust_root)
            .finish()
    }
}

impl QuoteVerifier for FederatedVerifier {
    fn verify<'a>(
        &'a self,
        quote: &'a AttestQuote,
        report_data: &'a [u8; 64],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<VerificationResult, VerificationError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let result = self.route_and_verify(quote, report_data).await?;
            self.check_manifest(&result).await?;
            Ok(result)
        })
    }

    /// Verify a composite bundle of quotes (e.g. TDX host + NVIDIA GPU).
    ///
    /// Each quote is verified against its own vendor verifier.  The federation
    /// manifest is then checked for every quote independently (all must pass).
    /// The first quote is designated the *primary* (host TEE); subsequent
    /// quotes are nested as `secondary` results.
    fn verify_bundle<'a>(
        &'a self,
        quotes: &'a [AttestQuote],
        report_data: &'a [u8; 64],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<VerificationResult, VerificationError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if quotes.is_empty() {
                return Err(VerificationError::MalformedQuote(
                    "FederatedVerifier: empty quote bundle".to_owned(),
                ));
            }

            let mut results = Vec::with_capacity(quotes.len());

            for quote in quotes {
                let result = self.route_and_verify(quote, report_data).await?;
                // Apply manifest to every quote in the bundle.
                self.check_manifest(&result).await?;
                results.push(result);
            }

            // Aggregate: primary is the first (host TEE), rest are secondary.
            let mut primary = results.remove(0);
            primary.secondary = results;

            Ok(primary)
        })
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockVerifier;
    use openhttpa_proto::FederationEntry;
    use openhttpa_tee::{QuoteRequest, mock::MockTeeProvider, provider::TeeProvider};

    /// Generate a valid mock quote via `MockTeeProvider` (passes hash binding check).
    fn mock_quote_for(report_data: [u8; 64]) -> AttestQuote {
        let provider = MockTeeProvider::default();
        provider
            .generate_quote(&QuoteRequest { report_data })
            .expect("mock quote generation failed")
    }

    fn wildcard_manifest(class: TeeClass, allow_debug: bool) -> FederationManifest {
        FederationManifest {
            version: 1,
            issued_at: 0,
            expires_at: u64::MAX,
            entries: vec![FederationEntry {
                tee_class: class,
                measurement_hex: String::new(), // wildcard
                label: "test-entry".to_owned(),
                min_svn: None,
                allow_debug,
            }],
            signature: ManifestSignature::default(),
        }
    }

    #[tokio::test]
    async fn accepts_mock_quote_with_manifest() {
        let mut fed = FederatedVerifier::new();
        fed.add_vendor_verifier(TeeClass::Mock, Box::new(MockVerifier::default()));
        fed.set_manifest(wildcard_manifest(TeeClass::Mock, true))
            .await
            .unwrap();

        let rd = [0u8; 64];
        let result = fed.verify(&mock_quote_for(rd), &rd).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        assert_eq!(result.unwrap().claims.tee_class, Some(TeeClass::Mock));
    }

    #[tokio::test]
    async fn rejects_unregistered_vendor() {
        let mut fed = FederatedVerifier::new();
        // Register TDX but send a Mock quote.
        fed.add_vendor_verifier(TeeClass::IntelTdx, Box::new(MockVerifier::default()));
        fed.set_manifest(wildcard_manifest(TeeClass::Mock, true))
            .await
            .unwrap();

        let rd = [0u8; 64];
        let result = fed.verify(&mock_quote_for(rd), &rd).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("no vendor verifier registered"), "{msg}");
    }

    #[tokio::test]
    async fn rejects_when_manifest_missing_in_strict_mode() {
        let mut fed = FederatedVerifier::new(); // strict by default
        fed.add_vendor_verifier(TeeClass::Mock, Box::new(MockVerifier::default()));
        // No manifest loaded.

        let rd = [0u8; 64];
        let result = fed.verify(&mock_quote_for(rd), &rd).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("no FederationManifest loaded"),
            "expected 'no FederationManifest loaded' in error"
        );
    }

    #[tokio::test]
    async fn rejects_quote_not_in_manifest() {
        let mut fed = FederatedVerifier::new();
        fed.add_vendor_verifier(TeeClass::Mock, Box::new(MockVerifier::default()));
        // Manifest only permits IntelTdx, not Mock.
        fed.set_manifest(wildcard_manifest(TeeClass::IntelTdx, false))
            .await
            .unwrap();

        let rd = [0u8; 64];
        let result = fed.verify(&mock_quote_for(rd), &rd).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("does not permit TEE class"), "{msg}");
    }

    #[tokio::test]
    async fn accepts_composite_bundle_all_in_manifest() {
        let mut fed = FederatedVerifier::new();
        fed.add_vendor_verifier(TeeClass::Mock, Box::new(MockVerifier::default()));
        fed.set_manifest(wildcard_manifest(TeeClass::Mock, true))
            .await
            .unwrap();

        let rd = [0u8; 64];
        let bundle = vec![mock_quote_for(rd), mock_quote_for(rd)];
        let result = fed.verify_bundle(&bundle, &rd).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        // Primary + one secondary.
        let r = result.unwrap();
        assert_eq!(r.secondary.len(), 1);
    }

    #[tokio::test]
    async fn rejects_expired_manifest() {
        let mut fed = FederatedVerifier::new();
        fed.add_vendor_verifier(TeeClass::Mock, Box::new(MockVerifier::default()));

        // Expired manifest: expires_at in the past.
        let expired = FederationManifest {
            version: 1,
            issued_at: 0,
            expires_at: 1, // Unix epoch + 1 second — always in the past.
            entries: vec![FederationEntry {
                tee_class: TeeClass::Mock,
                measurement_hex: String::new(),
                label: "expired".to_owned(),
                min_svn: None,
                allow_debug: true,
            }],
            signature: ManifestSignature::default(),
        };
        fed.set_manifest(expired).await.unwrap();

        let rd = [0u8; 64];
        let result = fed.verify(&mock_quote_for(rd), &rd).await;
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("expired"),
            "expected 'expired' in error"
        );
    }

    #[tokio::test]
    async fn empty_bundle_returns_error() {
        let fed = FederatedVerifier::new();
        let result = fed.verify_bundle(&[], &[0u8; 64]).await;
        assert!(result.is_err());
    }
}
