// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

#[cfg(test)]
mod tests {
    use openhttpa_zk::prover::ZkProver;
    use openhttpa_zk::verifier::ZkVerifier;
    use openhttpa_zk::ZkInput;

    #[test]
    fn test_zk_roundtrip() {
        let transcript_hash = [0x42u8; 48];
        let mut report_data = [0u8; 64];
        let prefix = b"openhttpa hs server";
        let plen = prefix.len().min(32);
        report_data[..plen].copy_from_slice(&prefix[..plen]);
        report_data[32..].copy_from_slice(&transcript_hash[..32]);

        let input = ZkInput {
            mode: openhttpa_zk::ZkMode::Handshake,
            transcript_hash,
            quote_bytes: vec![0, 1, 2, 3],
            report_data,
            oracle_data: None,
            vai_data: None,
            dcap_collateral: None,
        };

        let res = ZkProver::prove(&input);
        let receipt = res.expect("Proving failed");

        // Verification should succeed in both mock (feature disabled) and real modes
        let output = ZkVerifier::verify(&receipt, &transcript_hash).expect("Verification failed");
        assert!(output.is_valid);
    }

    #[test]
    fn test_zk_vai_provenance() {
        let transcript_hash = [0x42u8; 48];
        let model_id = [0x11u8; 32];
        let input_hash = [0x22u8; 32];
        let output_hash = [0x33u8; 32];

        // Compute the expected binding hash that should be in the report_data
        use sha2::Digest;
        let mut vai_hasher = sha2::Sha256::new();
        vai_hasher.update(b"openhttpa vai v1");
        vai_hasher.update(model_id);
        vai_hasher.update(input_hash);
        vai_hasher.update(output_hash);
        let binding = vai_hasher.finalize();

        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(&binding);

        let input = openhttpa_zk::ZkInput {
            mode: openhttpa_zk::ZkMode::VerifiedAi,
            transcript_hash,
            quote_bytes: vec![0, 1, 2, 3],
            report_data,
            oracle_data: None,
            vai_data: Some(openhttpa_zk::VaiInput {
                model_id,
                input_hash,
                output_hash,
            }),
            dcap_collateral: None,
        };

        let res = ZkProver::prove(&input);
        let receipt = res.expect("Proving failed");

        let output = ZkVerifier::verify(&receipt, &transcript_hash).expect("Verification failed");
        assert!(output.is_valid);
        assert_eq!(output.mode, openhttpa_zk::ZkMode::VerifiedAi);

        let vai = output.vai_output.expect("Missing VAI output");
        assert_eq!(vai.model_id, model_id);
        assert_eq!(vai.output_hash, output_hash);
    }

    #[test]
    fn test_zk_dcap_compression() {
        let transcript_hash = [0x99u8; 48];
        let report_data = [0xAAu8; 64];

        // Mock DCAP quote (must be > 100 bytes for our skeleton verifier)
        let quote_bytes = vec![0u8; 1024];

        let input = openhttpa_zk::ZkInput {
            mode: openhttpa_zk::ZkMode::DcapCompression,
            transcript_hash,
            quote_bytes,
            report_data,
            oracle_data: None,
            vai_data: None,
            dcap_collateral: Some(openhttpa_zk::DcapCollateral {
                pck_cert: vec![1, 2, 3],
                intermediate_ca: vec![4, 5, 6],
                root_ca: vec![7, 8, 9],
                tcb_info: b"{}".to_vec(),
                qe_identity: b"{}".to_vec(),
            }),
        };

        let res = ZkProver::prove(&input);
        let receipt = res.expect("Proving failed");

        let output = ZkVerifier::verify(&receipt, &transcript_hash).expect("Verification failed");
        assert!(output.is_valid);
        assert!(output.dcap_verified);
        assert_eq!(output.mode, openhttpa_zk::ZkMode::DcapCompression);
    }
}
