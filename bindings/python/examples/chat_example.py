# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

"""
OpenHTTPA Python Binding Example

This script demonstrates how to use the `openhttpa` library to:
1. Establish a cryptographically attested session with a TEE.
2. Send a confidential LLM chat request (high-level API).
3. Send a manual trusted request (low-level API).

Requirements:
- openhttpa package (built via maturin)
- Running OpenHTTPA backend (e.g. via `make up` in demo/multiparty-webapp)

Environment variables:
- OPENHTTPA_SERVER / OPENHTTPA_BACKEND_URL: backend URL (default: http://127.0.0.1:8080)
- OPENHTTPA_CALL_TIMEOUT_SECS: per-call deadline in seconds (default: 30)
"""

import concurrent.futures
import os
import sys

import openhttpa

# The address of our OpenHTTPA backend.
SERVER_URI: str = (
    os.getenv("OPENHTTPA_SERVER")
    or os.getenv("OPENHTTPA_BACKEND_URL")
    or "http://127.0.0.1:8080"
)

# Configurable per-call deadline so CI never hangs indefinitely.
CALL_TIMEOUT_SECS: float = float(os.getenv("OPENHTTPA_CALL_TIMEOUT_SECS", "30"))


def run_with_timeout(fn, timeout_secs: float, label: str):
    """Run *fn* in a thread pool and raise TimeoutError if it exceeds *timeout_secs*."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(fn)
        try:
            return future.result(timeout=timeout_secs)
        except concurrent.futures.TimeoutError:
            raise TimeoutError(
                f"'{label}' did not complete within {timeout_secs:.0f}s. "
                "Check whether the backend is healthy."
            )


def main() -> None:
    print("=== OpenHTTPA Python Example ===")

    # --- 1. High-Level API: Confidential LLM Chat ---
    # This automatically runs the Attestation Handshake (AtHS) under the hood.
    print(f"\n[1] Connecting to {SERVER_URI} for confidential chat...")
    try:
        def _llm_chat():
            llm = openhttpa.PyConfidentialLlm(SERVER_URI, "llama3")
            messages = [
                ("system", "You are a secure assistant running in a TEE."),
                ("user", "Explain why TEEs are useful for LLMs in 2 sentences."),
            ]
            return llm.chat(messages)

        reply = run_with_timeout(_llm_chat, CALL_TIMEOUT_SECS, "confidential LLM chat")
        print(f"    Sending chat request...")
        print(f"    Assistant Reply: {reply}")

    except TimeoutError as exc:
        print(f"    Timeout: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"    Error: {exc}")
        print("    (Is the backend running? Run 'make up' in demo/multiparty-webapp)")
        sys.exit(1)

    # --- 2. Low-Level API: Attestation + Trusted Request ---
    print(f"\n[2] Manual Attestation Handshake (AtHS)...")
    try:
        client = openhttpa.PyOpenHttpaClient(SERVER_URI)

        # This performs the X25519 + ML-KEM-768 hybrid handshake.
        session = run_with_timeout(client.attest_handshake, CALL_TIMEOUT_SECS, "attest_handshake")
        print("    Handshake successful!")
        print(f"    Attestation-Binding (AtB) ID: {session.atb_id}")

        print("\n[3] Sending Trusted Request (/api/echo)...")
        # All data sent via trusted_request is AEAD-encrypted (AES-256-GCM)
        # using the keys derived during the handshake.
        payload = b'{"message": "Hello from Python!"}'

        def _trusted_request():
            return client.trusted_request(session, "POST", "/api/echo", payload)

        response_bytes = run_with_timeout(_trusted_request, CALL_TIMEOUT_SECS, "trusted_request")
        print(f"    Response Body: {response_bytes.decode()}")

    except TimeoutError as exc:
        print(f"    Timeout: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"    Error during low-level API: {exc}")
        sys.exit(1)

    print("\nSuccess: Protocol integrity verified across Python/Rust/TEE layers.")


if __name__ == "__main__":
    main()
