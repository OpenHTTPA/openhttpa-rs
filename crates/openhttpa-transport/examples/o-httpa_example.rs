// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Example demonstrating Oblivious `OpenHTTPA` (O-HTTPA).
//!
//! In this flow, the client encapsulates its request using HPKE,
//! hiding its IP address from the TEE server.

use hpke::kem::Kem;
use openhttpa_transport::connection::{AttestTransport, TransportRequest, TransportResponse};
use openhttpa_transport::oblivious::{ObliviousClient, ObliviousServer};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Server Setup (In a real TEE, the private key would be protected)
    let mut rng = rand::thread_rng();
    let (server_sk, server_pk) = hpke::kem::X25519HkdfSha256::gen_keypair(&mut rng);
    let server_pk_bytes = hpke::Serializable::to_bytes(&server_pk).to_vec();

    let server = ObliviousServer::new(server_sk);

    // 2. Mock Inner Transport (The Relay)
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
            Box::pin(async move {
                let body_bytes = axum::body::to_bytes(req.body, usize::MAX).await.unwrap();
                println!(
                    "Relay: Forwarding {} bytes of encrypted payload",
                    body_bytes.len()
                );

                // Decapsulate on the server side
                let (plaintext, receiver_ctx) =
                    self.server.decapsulate(&body_bytes).map_err(|e| {
                        openhttpa_transport::connection::SendError::Connection(format!(
                            "Server decapsulate failed: {:?}",
                            e
                        ))
                    })?;

                println!(
                    "Server: Received decrypted request: {}",
                    String::from_utf8_lossy(&plaintext)
                );

                // Generate response
                let response_body = b"Confidential response from TEE";
                let enc_resp = self
                    .server
                    .encapsulate_response(&receiver_ctx, response_body)
                    .map_err(|e| {
                        openhttpa_transport::connection::SendError::Connection(format!(
                            "Server encapsulate failed: {:?}",
                            e
                        ))
                    })?;

                Ok(TransportResponse {
                    status: http::StatusCode::OK,
                    headers: http::HeaderMap::new(),
                    body: axum::body::Body::from(enc_resp),
                    trailers: None,
                })
            })
        }
    }

    let relay = Arc::new(MockRelay {
        server: Arc::new(server),
    });

    // 3. Client Setup
    let client = ObliviousClient::new(relay, server_pk_bytes, 0x01);

    // 4. Send Oblivious Request
    let req = TransportRequest {
        method: http::Method::POST,
        uri: "http://tee-server/api/data".parse()?,
        headers: http::HeaderMap::new(),
        body: axum::body::Body::from("Secret client data"),
        trailers: None,
    };

    println!("Client: Sending oblivious request...");
    let resp = client.send(req).await?;

    let resp_bytes = axum::body::to_bytes(resp.body, usize::MAX).await?;
    println!(
        "Client: Received decrypted response: {}",
        String::from_utf8_lossy(&resp_bytes)
    );

    Ok(())
}
