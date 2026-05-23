// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use openhttpa_crypto::aead::{FileNonceSequence, NonceSequence, NONCE_LEN};
use tempfile::tempdir;

#[test]
fn test_file_nonce_persistence() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("nonce.bin");
    let iv = [0xAAu8; NONCE_LEN];

    {
        let seq = FileNonceSequence::new(path.clone()).unwrap();
        let n1 = seq.next_nonce(&iv).unwrap();
        let n2 = seq.next_nonce(&iv).unwrap();

        // Counter starts at 1. n1 uses count 1, n2 uses count 2.
        // IV XOR 1
        let mut expected1 = iv;
        expected1[11] ^= 1;
        assert_eq!(n1.0, expected1);

        let mut expected2 = iv;
        expected2[11] ^= 2;
        assert_eq!(n2.0, expected2);
    }

    // Re-open: should continue from 3
    {
        let seq = FileNonceSequence::new(path.clone()).unwrap();
        let n3 = seq.next_nonce(&iv).unwrap();
        let mut expected3 = iv;
        expected3[11] ^= 3;
        assert_eq!(n3.0, expected3);
    }
}

#[test]
fn test_file_nonce_locking() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("nonce_lock.bin");
    let iv = [0xAAu8; NONCE_LEN];

    let seq1 = FileNonceSequence::new(path.clone()).unwrap();
    let seq2 = FileNonceSequence::new(path.clone()).unwrap();

    let n1 = seq1.next_nonce(&iv).unwrap();
    let n2 = seq2.next_nonce(&iv).unwrap();

    assert_ne!(n1.0, n2.0);
}
