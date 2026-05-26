// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! RFC 9334 Entity Attestation Token (EAT) CBOR/COSE serialization and validation.

use crate::verifier::VerificationError;
use coset::{CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder};
use openhttpa_proto::EatClaims;

/// Supported signature algorithms for COSE Sign1 EAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EatSignAlgorithm {
    /// ECDSA using P-256 and SHA-256 (COSE algorithm 6 / ES256)
    Es256,
    /// ECDSA using P-384 and SHA-384 (COSE algorithm 34 / ES384)
    Es384,
    /// ML-DSA-65 post-quantum signature (COSE algorithm -46)
    MlDsa65,
}

impl EatSignAlgorithm {
    const fn to_cose_algorithm(self) -> coset::Algorithm {
        match self {
            Self::Es256 => {
                coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::ES256)
            }
            Self::Es384 => {
                coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::ES384)
            }
            Self::MlDsa65 => {
                coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::HSS_LMS)
            }
        }
    }

    fn from_cose_algorithm(alg: &coset::Algorithm) -> Result<Self, VerificationError> {
        match alg {
            coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::ES256) => {
                Ok(Self::Es256)
            }
            coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::ES384) => {
                Ok(Self::Es384)
            }
            coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::HSS_LMS)
            | coset::RegisteredLabelWithPrivate::PrivateUse(-46) => Ok(Self::MlDsa65),
            other => Err(VerificationError::Malformed(format!(
                "unsupported COSE algorithm: {other:?}"
            ))),
        }
    }
}

/// Serialize EAT claims to CBOR bytes.
///
/// # Errors
/// Returns [`Err`] if serialization fails.
pub fn serialize_claims(claims: &EatClaims) -> Result<Vec<u8>, VerificationError> {
    let mut buf = Vec::new();
    ciborium::into_writer(claims, &mut buf).map_err(|e| {
        VerificationError::Malformed(format!("failed to serialize claims to CBOR: {e}"))
    })?;
    Ok(buf)
}

/// Deserialize EAT claims from CBOR bytes.
///
/// # Errors
/// Returns [`Err`] if deserialization fails.
pub fn deserialize_claims(cbor_bytes: &[u8]) -> Result<EatClaims, VerificationError> {
    let claims: EatClaims = ciborium::from_reader(cbor_bytes).map_err(|e| {
        VerificationError::Malformed(format!("failed to deserialize claims from CBOR: {e}"))
    })?;
    Ok(claims)
}

/// Create a signed COSE Sign1 EAT token.
///
/// # Errors
/// Returns [`Err`] if signing or token construction fails.
pub fn create_signed_eat(
    claims: &EatClaims,
    signing_key_der: &[u8],
    algorithm: EatSignAlgorithm,
) -> Result<Vec<u8>, VerificationError> {
    let payload = serialize_claims(claims)?;

    let mut protected = HeaderBuilder::new().build();
    protected.alg = Some(algorithm.to_cose_algorithm());

    let mut cose_sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .build();

    let tbs = cose_sign1.tbs_data(&[]);

    let signature = match algorithm {
        EatSignAlgorithm::Es256 => {
            let rng = aws_lc_rs::rand::SystemRandom::new();
            let key_pair = aws_lc_rs::signature::EcdsaKeyPair::from_pkcs8(
                &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                signing_key_der,
            )
            .map_err(|e| VerificationError::Malformed(format!("invalid P-256 PKCS#8 key: {e}")))?;
            key_pair
                .sign(&rng, &tbs)
                .map_err(|_| VerificationError::SignatureInvalid)?
                .as_ref()
                .to_vec()
        }
        EatSignAlgorithm::Es384 => {
            let rng = aws_lc_rs::rand::SystemRandom::new();
            let key_pair = aws_lc_rs::signature::EcdsaKeyPair::from_pkcs8(
                &aws_lc_rs::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                signing_key_der,
            )
            .map_err(|e| VerificationError::Malformed(format!("invalid P-384 PKCS#8 key: {e}")))?;
            key_pair
                .sign(&rng, &tbs)
                .map_err(|_| VerificationError::SignatureInvalid)?
                .as_ref()
                .to_vec()
        }
        EatSignAlgorithm::MlDsa65 => {
            let sig = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65)
                .map_err(|e| VerificationError::Malformed(e.to_string()))?;
            let sk = sig.secret_key_from_bytes(signing_key_der).ok_or_else(|| {
                VerificationError::Malformed("invalid ML-DSA-65 secret key".to_owned())
            })?;
            let signature = sig
                .sign(&tbs, sk)
                .map_err(|_| VerificationError::SignatureInvalid)?;
            signature.into_vec()
        }
    };

    cose_sign1.signature = signature;

    cose_sign1
        .to_vec()
        .map_err(|e| VerificationError::Malformed(format!("failed to serialize COSE Sign1: {e:?}")))
}

/// Verify a signed COSE Sign1 EAT token and extract the claims.
///
/// # Errors
/// Returns [`Err`] if signature verification fails or the token is malformed.
pub fn verify_signed_eat(
    cose_bytes: &[u8],
    verification_key_der: &[u8],
) -> Result<EatClaims, VerificationError> {
    let cose_sign1 = CoseSign1::from_slice(cose_bytes)
        .map_err(|e| VerificationError::Malformed(format!("invalid COSE Sign1 envelope: {e:?}")))?;

    let alg_val = cose_sign1.protected.header.alg.as_ref().ok_or_else(|| {
        VerificationError::Malformed("missing algorithm in protected header".to_owned())
    })?;
    let algorithm = EatSignAlgorithm::from_cose_algorithm(alg_val)?;

    let tbs = cose_sign1.tbs_data(&[]);

    match algorithm {
        EatSignAlgorithm::Es256 => {
            let peer_pub = aws_lc_rs::signature::UnparsedPublicKey::new(
                &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED,
                verification_key_der,
            );
            peer_pub
                .verify(&tbs, &cose_sign1.signature)
                .map_err(|_| VerificationError::SignatureInvalid)?;
        }
        EatSignAlgorithm::Es384 => {
            let peer_pub = aws_lc_rs::signature::UnparsedPublicKey::new(
                &aws_lc_rs::signature::ECDSA_P384_SHA384_FIXED,
                verification_key_der,
            );
            peer_pub
                .verify(&tbs, &cose_sign1.signature)
                .map_err(|_| VerificationError::SignatureInvalid)?;
        }
        EatSignAlgorithm::MlDsa65 => {
            let sig = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65)
                .map_err(|e| VerificationError::Malformed(e.to_string()))?;
            let pk = sig
                .public_key_from_bytes(verification_key_der)
                .ok_or(VerificationError::SignatureInvalid)?;
            let s = sig
                .signature_from_bytes(&cose_sign1.signature)
                .ok_or(VerificationError::SignatureInvalid)?;
            sig.verify(&tbs, s, pk)
                .map_err(|_| VerificationError::SignatureInvalid)?;
        }
    }

    let payload_bytes = cose_sign1.payload.ok_or_else(|| {
        VerificationError::Malformed("missing payload in COSE Sign1 envelope".to_owned())
    })?;

    deserialize_claims(&payload_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::KeyPair;

    #[test]
    fn test_eat_claims_cbor_round_trip() {
        let claims = EatClaims {
            ueid: Some(vec![1, 2, 3, 4]),
            hwmodel: Some("Test Hardware".to_owned()),
            hwversion: Some("v1.0".to_owned()),
            oemid: Some("OEM Inc".to_owned()),
            dbgstat: Some(0),
            boot_progress: Some("booted".to_owned()),
            security_version: Some(3),
            iat: Some(1_716_681_600),
            exp: Some(1_716_681_600 + 3600), // 1-hour validity
        };

        let cbor = serialize_claims(&claims).unwrap();
        let claims2 = deserialize_claims(&cbor).unwrap();

        assert_eq!(claims.ueid, claims2.ueid);
        assert_eq!(claims.hwmodel, claims2.hwmodel);
        assert_eq!(claims.hwversion, claims2.hwversion);
        assert_eq!(claims.oemid, claims2.oemid);
        assert_eq!(claims.dbgstat, claims2.dbgstat);
        assert_eq!(claims.boot_progress, claims2.boot_progress);
        assert_eq!(claims.security_version, claims2.security_version);
        assert_eq!(claims.iat, claims2.iat);
        assert_eq!(claims.exp, claims2.exp);
    }

    #[test]
    fn test_cose_sign1_es256_round_trip() {
        let claims = EatClaims {
            hwmodel: Some("Confidential VM".to_owned()),
            dbgstat: Some(0),
            ..Default::default()
        };

        // Generate a standard P-256 key pair via aws-lc-rs
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let doc = aws_lc_rs::signature::EcdsaKeyPair::generate_pkcs8(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();

        let key_pair = aws_lc_rs::signature::EcdsaKeyPair::from_pkcs8(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            doc.as_ref(),
        )
        .unwrap();
        let pub_key = key_pair.public_key().as_ref().to_vec();

        // Sign
        let token = create_signed_eat(&claims, doc.as_ref(), EatSignAlgorithm::Es256).unwrap();

        // Verify
        let decoded_claims = verify_signed_eat(&token, &pub_key).unwrap();
        assert_eq!(decoded_claims.hwmodel, Some("Confidential VM".to_owned()));

        // Tamper
        let mut tampered = token;
        let len = tampered.len();
        tampered[len - 5] ^= 0xFF; // Flip signature byte
        assert!(verify_signed_eat(&tampered, &pub_key).is_err());
    }

    #[test]
    fn test_cose_sign1_mldsa65_round_trip() {
        let claims = EatClaims {
            hwmodel: Some("Confidential GPU Realm".to_owned()),
            dbgstat: Some(1),
            ..Default::default()
        };

        // Generate an ML-DSA-65 key pair via oqs
        let sig = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65).unwrap();
        let (pk, sk) = sig.keypair().unwrap();

        // Sign
        let token = create_signed_eat(&claims, sk.as_ref(), EatSignAlgorithm::MlDsa65).unwrap();

        // Verify
        let decoded_claims = verify_signed_eat(&token, pk.as_ref()).unwrap();
        assert_eq!(
            decoded_claims.hwmodel,
            Some("Confidential GPU Realm".to_owned())
        );

        // Tamper
        let mut tampered = token;
        let len = tampered.len();
        tampered[len - 5] ^= 0xFF; // Flip signature byte
        assert!(verify_signed_eat(&tampered, pk.as_ref()).is_err());
    }
}
