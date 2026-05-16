// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

fn main() {
    #[cfg(feature = "zk")]
    {
        if std::env::var("OPENHTTPA_SKIP_ZK_BUILD")
            .map(|v| v == "1")
            .unwrap_or(false)
            || std::env::var("RISC0_SKIP_BUILD")
                .map(|v| v == "1")
                .unwrap_or(false)
        {
            return;
        }
        risc0_build::embed_methods();
    }
}
