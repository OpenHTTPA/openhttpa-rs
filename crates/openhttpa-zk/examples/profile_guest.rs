// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Scalability Audit: Guest Cycle Profiler for ZAA.
//!
//! This example runs the `OpenHTTPA` ZK guest program and extracts the total
//! cycle counts to audit the performance of different attestation modes.

use openhttpa_zk::{DcapCollateral, ZkInput, ZkMode, OPENHTTPA_GUEST_ELF};
use risc0_zkvm::{ExecutorEnv, ExecutorImpl};

fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let mode = args
        .get(2)
        .map(|s| s.as_str())
        .unwrap_or("dcap-compression");

    println!("--- `OpenHTTPA` ZK Scalability Audit ---");
    println!("Target Mode: {}", mode);

    let input = match mode {
        "dcap-compression" => ZkInput {
            mode: ZkMode::DcapCompression,
            transcript_hash: [0x99u8; 48],
            quote_bytes: vec![0u8; 1024],
            report_data: [0xAAu8; 64],
            oracle_data: None,
            vai_data: None,
            dcap_collateral: Some(DcapCollateral {
                pck_cert: vec![1; 512],
                intermediate_ca: vec![2; 512],
                root_ca: vec![3; 512],
                tcb_info: b"{}".to_vec(),
                qe_identity: b"{}".to_vec(),
            }),
        },
        _ => panic!("Unknown mode: {}", mode),
    };

    // 1. Prepare Executor Environment
    let env = ExecutorEnv::builder()
        .write(&input)
        .expect("Failed to write input")
        .build()
        .expect("Failed to build env");

    // 2. Execute the guest program (Simulation mode for profiling)
    let mut exec =
        ExecutorImpl::from_elf(env, OPENHTTPA_GUEST_ELF).expect("Failed to create executor");
    let session = exec.run().expect("Execution failed");

    // 3. Extract and Print Cycle Counts
    let segment_count = session.segments.len();
    let estimated_cycles = segment_count * 1_048_576; // 1M cycles per segment default

    println!("\nVerification Success: {}", session.exit_code.is_ok());
    println!("Segments Generated: {}", segment_count);
    println!("Estimated Total Cycles: ~{}", estimated_cycles);

    if segment_count > 10 {
        println!("WARNING: High segment count detected (>10). Optimization required.");
    } else {
        println!("SUCCESS: Scalability targets achieved.");
    }
}
