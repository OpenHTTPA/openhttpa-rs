// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Error types for the `OpenHTTPA` protocol.

use thiserror::Error;

/// Top-level error type for the `OpenHTTPA` protocol library.
// MED-06: non_exhaustive prevents breaking changes when new variants are added.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum OpenHttpaError {
    /// The two parties could not agree on a cipher suite.
    #[error("cipher suite negotiation failed: no common suite between client and server")]
    NegotiationFailed,

    /// A replay attack was detected (duplicate or out-of-window nonce).
    #[error("replay detected: nonce {nonce} is invalid for this session")]
    ReplayDetected { nonce: u64 },

    /// The handshake AHLs failed integrity verification.
    #[error("handshake integrity check failed")]
    HandshakeIntegrityFailed,

    /// `AtQ` verification failed.
    #[error("attestation quote verification failed: {reason}")]
    AttestationFailed { reason: String },

    /// `AtB` allocation failed.
    #[error("attest base allocation failed: {reason}")]
    AtbAllocationFailed { reason: String },

    /// The requested `AtB` ID is unknown or has expired.
    #[error("attest base {atb_id} not found or expired")]
    AtbNotFound { atb_id: String },

    /// The session has not completed `AtHS` yet.
    #[error("session not yet attested — AtHS must complete before TrR")]
    SessionNotAttested,

    /// AEAD encryption or decryption failure.
    #[error("AEAD operation failed")]
    AeadFailure,

    /// Key derivation failure.
    #[error("key derivation failed")]
    KeyDerivationFailed,

    /// Invalid or unsupported protocol version.
    #[error("unsupported protocol version: {version}")]
    UnsupportedVersion { version: String },

    /// Serialisation / deserialisation error.
    #[error("serialisation error: {0}")]
    Serialisation(String),

    /// Transport-layer error.
    #[error("transport error: {0}")]
    Transport(String),

    /// TEE-specific error.
    #[error("TEE error: {0}")]
    Tee(#[from] TeeError),

    /// Generic I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors originating inside or around a Trusted Execution Environment.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TeeError {
    /// The TEE platform is not available on this host.
    #[error("TEE platform not available")]
    NotAvailable,

    /// Quote generation failed.
    #[error("quote generation failed: {reason}")]
    QuoteGenerationFailed { reason: String },

    /// Quote verification failed.
    #[error("quote verification failed: {reason}")]
    QuoteVerificationFailed { reason: String },

    /// An error returned by the underlying TEE SDK.
    #[error("TEE SDK error (code {code:#010x}): {message}")]
    SdkError { code: u32, message: String },
}

/// Errors from the attestation verification layer.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AttestError {
    /// The quote was syntactically invalid.
    #[error("malformed quote: {0}")]
    MalformedQuote(String),

    /// The quote was syntactically valid but the signature did not verify.
    #[error("quote signature invalid")]
    SignatureInvalid,

    /// TCB level is out of date.
    #[error("TCB out of date: {details}")]
    TcbOutOfDate { details: String },

    /// The verifier service returned an error.
    #[error("verifier service error: {0}")]
    ServiceError(String),

    /// Network error reaching the verifier.
    #[error("verifier network error: {0}")]
    NetworkError(String),

    /// The quote passed verification but violates the configured policy.
    #[error("policy violation: {0}")]
    PolicyViolation(String),

    /// The TEE platform or enclave has been revoked.
    #[error("attestation revoked: {0}")]
    Revoked(String),

    /// Generic malformed input error.
    #[error("malformed: {0}")]
    Malformed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_negotiation() {
        let e = OpenHttpaError::NegotiationFailed;
        assert!(e.to_string().contains("cipher suite"));
    }

    #[test]
    fn error_display_replay() {
        let e = OpenHttpaError::ReplayDetected { nonce: 42 };
        assert!(e.to_string().contains("42"));
    }

    #[test]
    fn attest_error_display_tcb() {
        let e = AttestError::TcbOutOfDate {
            details: "SVN too low".to_owned(),
        };
        assert!(e.to_string().contains("SVN too low"));
    }
}
