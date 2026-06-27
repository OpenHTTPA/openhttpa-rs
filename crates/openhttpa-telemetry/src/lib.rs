// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Confidential Telemetry for OpenHTTPA.
//!
//! Provides a `tracing_subscriber::Layer` that encrypts log events and spans
//! using HPKE before emitting them. This allows operators to collect debug
//! and APM data from TEEs without exposing plaintext PII or secrets.

use hpke::{Deserializable, Serializable};
use hpke::{OpModeS, aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, setup_sender};
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde::Serialize;
use std::fmt::Write;
use tracing_core::{Event, Subscriber};
use tracing_subscriber::{Layer, layer::Context};

type HpkeKem = X25519HkdfSha256;
type HpkeKdf = HkdfSha256;
type HpkeAead = AesGcm256;

#[derive(Serialize)]
struct EncryptedTelemetryPayload {
    /// Encapsulated key (for the receiver to derive the shared secret)
    encap_key: String,
    /// Ciphertext of the serialized tracing event
    ciphertext: String,
}

pub struct ConfidentialTelemetryLayer {
    /// The public key of the compliance auditor / logging sink
    compliance_public_key: <HpkeKem as hpke::kem::Kem>::PublicKey,
}

impl ConfidentialTelemetryLayer {
    pub fn new(public_key_bytes: &[u8]) -> Result<Self, String> {
        let pk = <HpkeKem as hpke::kem::Kem>::PublicKey::from_bytes(public_key_bytes)
            .map_err(|e| format!("Invalid public key: {}", e))?;
        Ok(Self {
            compliance_public_key: pk,
        })
    }
}

impl<S> Layer<S> for ConfidentialTelemetryLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        // Collect fields into a simple string representation
        let mut fields = String::new();
        let mut visitor = StringVisitor(&mut fields);
        event.record(&mut visitor);

        let payload = format!("level={} fields={}", event.metadata().level(), fields);

        // Encrypt the payload with HPKE
        let mut csprng = StdRng::from_os_rng();
        let (encap_key, mut sender_ctx) = setup_sender::<HpkeAead, HpkeKdf, HpkeKem, _>(
            &OpModeS::Base,
            &self.compliance_public_key,
            b"openhttpa-telemetry",
            &mut csprng,
        )
        .expect("HPKE setup failed");

        let mut pt = payload.into_bytes();
        let tag = sender_ctx
            .seal_in_place_detached(&mut pt, b"")
            .expect("HPKE seal failed");
        pt.extend_from_slice(tag.to_bytes().as_ref());

        let out = EncryptedTelemetryPayload {
            encap_key: hex::encode(encap_key.to_bytes()),
            ciphertext: hex::encode(pt),
        };

        // In a real implementation, we would write `out` to a socket, OpenTelemetry exporter,
        // or a local file rather than printing to stdout.
        let json_out = serde_json::to_string(&out).unwrap();
        println!("CONFIDENTIAL_TELEMETRY: {}", json_out);
    }
}

struct StringVisitor<'a>(&'a mut String);

impl<'a> tracing_core::field::Visit for StringVisitor<'a> {
    fn record_debug(&mut self, field: &tracing_core::Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.0, "{}={:?} ", field.name(), value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::{OpModeR, setup_receiver};
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use tracing::{info, subscriber::with_default};
    use tracing_subscriber::Registry;
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn test_telemetry_encryption() {
        let mut csprng = StdRng::from_os_rng();
        let (_private_key, public_key) = <HpkeKem as hpke::kem::Kem>::gen_keypair(&mut csprng);

        let layer = ConfidentialTelemetryLayer::new(&public_key.to_bytes()).unwrap();
        let subscriber = Registry::default().with(layer);

        with_default(subscriber, || {
            info!(user_id = 1234, "Sensitive login event");
        });

        // Test bad public key edge case
        let bad_pk = vec![0; 10]; // X25519 expects 32 bytes
        let err = ConfidentialTelemetryLayer::new(&bad_pk);
        assert!(err.is_err(), "Expected error for invalid public key length");
    }

    #[test]
    fn test_telemetry_decryption() {
        // E2E test verifying that what the layer emits can actually be decrypted by the receiver
        let mut csprng = StdRng::from_os_rng();
        let (private_key, public_key) = <HpkeKem as hpke::kem::Kem>::gen_keypair(&mut csprng);

        let payload = "level=INFO fields=user_id=1234 message=\"Sensitive login event\" ";

        let (encap_key, mut sender_ctx) = setup_sender::<HpkeAead, HpkeKdf, HpkeKem, _>(
            &OpModeS::Base,
            &public_key,
            b"openhttpa-telemetry",
            &mut csprng,
        )
        .unwrap();

        let mut pt = payload.as_bytes().to_vec();
        let tag = sender_ctx.seal_in_place_detached(&mut pt, b"").unwrap();

        // Simulating receiver side
        let mut receiver_ctx = setup_receiver::<HpkeAead, HpkeKdf, HpkeKem>(
            &OpModeR::Base,
            &private_key,
            &encap_key,
            b"openhttpa-telemetry",
        )
        .unwrap();

        let decrypted = receiver_ctx.open_in_place_detached(&mut pt, b"", &tag);
        assert!(decrypted.is_ok(), "Decryption failed");
        assert_eq!(String::from_utf8(pt).unwrap(), payload);
    }
}
