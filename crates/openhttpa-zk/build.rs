// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

fn main() {
    #[cfg(feature = "zk")]
    {
        let skip = std::env::var("OPENHTTPA_SKIP_ZK_BUILD")
            .map(|v| v == "1")
            .unwrap_or(false)
            || std::env::var("RISC0_SKIP_BUILD")
                .map(|v| v == "1")
                .unwrap_or(false);

        if skip {
            // Inform Rust code that the ZK guest was not built so it can use
            // a pre-written stub for the generated `methods.rs` file.  This
            // lets static-analysis tools (CodeQL, rust-analyzer) fully resolve
            // call targets inside this crate without a RISC Zero guest build.
            println!("cargo:rustc-cfg=openhttpa_zk_stub");
            return;
        }
        risc0_build::embed_methods();
    }
}
