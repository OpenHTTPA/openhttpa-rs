// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

use openhttpa_crypto::hkdf::SessionKeys;
use openhttpa_crypto::key_exchange::HybridKemPair;

fn main() {
    let client_pair = HybridKemPair::generate().unwrap();
    let client_share = client_pair.public_key_share();

    let server_pair = HybridKemPair::generate().unwrap();
    let server_pub = server_pair.public_key_share();

    let (server_secret, ct) = server_pair.server_combine(&client_share).unwrap();
    let client_secret = client_pair.client_combine(&server_pub, &ct).unwrap();

    assert_eq!(server_secret.as_bytes(), client_secret.as_bytes());

    let transcript_hash = vec![0u8; 48]; // dummy hash for vector
    let session_keys = SessionKeys::derive(client_secret.as_bytes(), &transcript_hash).unwrap();

    println!("### Hybrid KEM Key Exchange\n");
    println!(
        "**Client ECDHE Public Key:**\n```text\n{}\n```\n",
        hex::encode(&client_share.ecdhe_public)
    );
    println!(
        "**Client ML-KEM Public Key:**\n```text\n{}\n```\n",
        hex::encode(&client_share.mlkem_public)
    );

    println!(
        "**Server ECDHE Public Key:**\n```text\n{}\n```\n",
        hex::encode(&server_pub.ecdhe_public)
    );
    println!(
        "**Server ML-KEM Ciphertext:**\n```text\n{}\n```\n",
        hex::encode(&ct)
    );

    println!(
        "**Combined Hybrid Secret (IKM):**\n```text\n{}\n```\n",
        hex::encode(client_secret.as_bytes())
    );

    println!("### Derived Session Keys\n");
    println!(
        "*Transcript Hash (All Zeros for Test Vector):*\n```text\n{}\n```\n",
        hex::encode(&transcript_hash)
    );
    println!(
        "**Master Secret:**\n```text\n{}\n```\n",
        hex::encode(&session_keys.master_secret)
    );
    println!(
        "**Client Write Key:**\n```text\n{}\n```\n",
        hex::encode(&session_keys.client_write_key)
    );
    println!(
        "**Server Write Key:**\n```text\n{}\n```\n",
        hex::encode(&session_keys.server_write_key)
    );
    println!(
        "**Client MAC Key:**\n```text\n{}\n```\n",
        hex::encode(&session_keys.client_mac_key)
    );
    println!(
        "**Server MAC Key:**\n```text\n{}\n```\n",
        hex::encode(&session_keys.server_mac_key)
    );
}
