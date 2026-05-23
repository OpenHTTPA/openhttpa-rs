// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

extern crate cbindgen;

use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_language(cbindgen::Language::C)
        .with_include_guard("OPENHTTPA_H")
        .with_documentation(true)
        .with_namespace("openhttpa")
        .generate()
        .expect("cbindgen failed")
        .write_to_file("include/openhttpa.h");
}
