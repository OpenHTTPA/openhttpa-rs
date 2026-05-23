// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use reqwest::blocking::Client;
use std::process::exit;
use std::time::Duration;

fn main() {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:8080/health".to_string());
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();

    match client.get(&url).send() {
        Ok(resp) if resp.status().is_success() => {
            println!("Health check passed: {}", resp.status());
            exit(0);
        }
        Ok(resp) => {
            eprintln!("Health check failed: {}", resp.status());
            exit(1);
        }
        Err(e) => {
            eprintln!("Health check error: {}", e);
            exit(1);
        }
    }
}
