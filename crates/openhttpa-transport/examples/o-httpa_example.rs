// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Example demonstrating Oblivious `OpenHTTPA` (O-HTTPA).
//!
//! In this flow, the client encapsulates its request using ML-KEM-768 (FIPS 203),
//! hiding its IP address from the TEE server while preserving Post-Quantum security.

use openhttpa_crypto::pqc::MlKemPair;
use openhttpa_transport::connection::{AttestTransport, TransportRequest, TransportResponse};
use openhttpa_transport::oblivious::{ObliviousClient, ObliviousServer};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Server Setup
    //    In a real TEE deployment the ML-KEM key pair would be generated inside
    //    the enclave and the decapsulation key would never leave it.
    let server_pair = MlKemPair::generate()?;
    let server_pk_bytes = server_pair.public_encap_key().to_vec();
    let server = Arc::new(ObliviousServer::new(server_pair));

    println!(
        "Server: ML-KEM-768 encapsulation key ready ({} bytes)",
        server_pk_bytes.len()
    );

    // 2. Mock Inner Transport (The Relay)
    //    The relay forwards encrypted blobs without being able to read them.
    struct MockRelay {
        server: Arc<ObliviousServer>,
    }

    impl AttestTransport for MockRelay {
        fn send(
            &self,
            req: TransportRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            TransportResponse,
                            openhttpa_transport::connection::SendError,
                        >,
                    > + Send
                    + '_,
            >,
        > {
            let server = Arc::clone(&self.server);
            Box::pin(async move {
                let body_bytes = openhttpa_transport::connection::to_bytes(req.body, usize::MAX)
                    .await
                    .unwrap();
                println!(
                    "Relay: Forwarding {} bytes of encrypted payload",
                    body_bytes.len()
                );

                // Decapsulate on the server side (ML-KEM + HKDF + AES-256-GCM).
                let (plaintext, resp_key) = server.decapsulate(&body_bytes).map_err(|e| {
                    openhttpa_transport::connection::SendError::Connection(format!(
                        "Server decapsulate failed: {e:?}"
                    ))
                })?;

                println!(
                    "Server: Received decrypted request: {}",
                    String::from_utf8_lossy(&plaintext)
                );

                // Generate and encrypt the response.
                let response_body = b"Confidential response from TEE";
                let enc_resp = server
                    .encapsulate_response(&resp_key, response_body)
                    .map_err(|e| {
                        openhttpa_transport::connection::SendError::Connection(format!(
                            "Server encapsulate failed: {e:?}"
                        ))
                    })?;

                Ok(TransportResponse {
                    status: http::StatusCode::OK,
                    headers: http::HeaderMap::new(),
                    body: openhttpa_transport::connection::full_body(enc_resp),
                    trailers: None,
                })
            })
        }
    }

    let relay = Arc::new(MockRelay {
        server: Arc::clone(&server),
    });

    // 3. Client Setup
    let client = ObliviousClient::new(relay, server_pk_bytes, 0x01);

    // 4. Send Oblivious Request
    let req = TransportRequest {
        method: http::Method::POST,
        uri: "http://tee-server/api/data".parse()?,
        headers: http::HeaderMap::new(),
        body: openhttpa_transport::connection::full_body("Secret client data"),
        trailers: None,
    };

    println!("Client: Sending oblivious request...");
    let resp = client.send(req).await?;

    let resp_bytes = openhttpa_transport::connection::to_bytes(resp.body, usize::MAX).await?;
    println!(
        "Client: Received decrypted response: {}",
        String::from_utf8_lossy(&resp_bytes)
    );

    Ok(())
}
