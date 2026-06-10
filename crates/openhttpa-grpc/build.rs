// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

fn main() {
    // DES-01: Generate Rust message types from the authoritative proto
    // definition via prost-build.  Ensures the Rust types stay in sync with
    // the wire schema — any structural divergence is caught at compile time.
    //
    // Note: tonic-build v0.14 no longer wraps prost-build for proto
    // compilation; prost-build is used directly for message code-generation
    // while tonic-build's `manual` service API is used in service.rs for the
    // gRPC service trait.
    prost_build::compile_protos(&["proto/openhttpa.proto"], &["proto"])
        .expect("prost-build failed to compile proto/openhttpa.proto");

    println!("cargo:rerun-if-changed=proto/openhttpa.proto");
}
