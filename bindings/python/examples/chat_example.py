# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 The OpenHTTPA Foundation (AIQL.org)

"""
OpenHTTPA Python Binding Example

This script demonstrates how to use the `openhttpa` library to:
1. Establish a cryptographically attested session with a TEE.
2. Send a confidential LLM chat request (high-level API).
3. Send a manual trusted request (low-level API).

Requirements:
- openhttpa package (built via maturin)
- Running OpenHTTPA backend (e.g. via `make up` in demo/multiparty-webapp)
"""

import openhttpa
import sys

import os
# The address of our OpenHTTPA backend
SERVER_URI = os.getenv("OPENHTTPA_SERVER") or os.getenv("OPENHTTPA_BACKEND_URL") or "http://127.0.0.1:8080"

def main():
    print("=== OpenHTTPA Python Example ===")

    # --- 1. High-Level API: Confidential LLM Chat ---
    # This automatically runs the Attestation Handshake (AtHS) under the hood.
    print(f"\n[1] Connecting to {SERVER_URI} for confidential chat...")
    try:
        llm = openhttpa.PyConfidentialLlm(SERVER_URI, "llama3")
        
        print("    Sending chat request...")
        messages = [
            ("system", "You are a secure assistant running in a TEE."),
            ("user",   "Explain why TEEs are useful for LLMs in 2 sentences.")
        ]
        
        reply = llm.chat(messages)
        print(f"    Assistant Reply: {reply}")
        
    except Exception as e:
        print(f"    Error: {e}")
        print("    (Is the backend running? Run 'make up' in demo/multiparty-webapp)")
        sys.exit(1)

    # --- 2. Low-Level API: Attestation + Trusted Request ---
    print(f"\n[2] Manual Attestation Handshake (AtHS)...")
    client = openhttpa.PyOpenHttpaClient(SERVER_URI)
    
    # This performs the X25519 + ML-KEM-768 hybrid handshake.
    session = client.attest_handshake()
    print(f"    Handshake successful!")
    print(f"    Attestation-Binding (AtB) ID: {session.atb_id}")

    print("\n[3] Sending Trusted Request (/api/echo)...")
    # All data sent via trusted_request is AEAD-encrypted (AES-256-GCM) 
    # using the keys derived during the handshake.
    payload = b'{"message": "Hello from Python!"}'
    response_bytes = client.trusted_request(session, "POST", "/api/echo", payload)
    print(f"    Response Body: {response_bytes.decode()}")

    print("\nSuccess: Protocol integrity verified across Python/Rust/TEE layers.")

if __name__ == "__main__":
    main()
