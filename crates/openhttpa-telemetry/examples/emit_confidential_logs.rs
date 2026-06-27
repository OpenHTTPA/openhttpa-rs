// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Example: Emitting confidential telemetry logs encrypted with HPKE.

use hpke::{Serializable, kem::X25519HkdfSha256};
use openhttpa_telemetry::ConfidentialTelemetryLayer;
use rand::SeedableRng;
use tracing::{Level, info, span, warn};
use tracing_subscriber::{Registry, layer::SubscriberExt, util::SubscriberInitExt};

fn main() {
    // 1. In a real-world scenario, this public key belongs to the offline compliance auditor
    // or central logging SIEM. We generate an ephemeral one here for the example.
    let mut csprng = rand::rngs::StdRng::from_os_rng();
    let (_sk, pk) = <X25519HkdfSha256 as hpke::kem::Kem>::gen_keypair(&mut csprng);

    // 2. Initialize the Confidential Telemetry Layer
    let telemetry_layer = ConfidentialTelemetryLayer::new(&pk.to_bytes())
        .expect("Failed to initialize telemetry layer");

    // 3. Register the layer globally
    Registry::default().with(telemetry_layer).init();

    // 4. Emit standard tracing logs. These will be intercepted, encrypted, and written out.
    let _s = span!(Level::INFO, "app_startup", version = "1.0.0").entered();

    info!(
        user_id = 9912,
        action = "login",
        "User successfully authenticated"
    );
    warn!(user_id = 9912, "User requested sensitive enclave data");

    // Check stdout to see the encrypted JSON payloads.
}
