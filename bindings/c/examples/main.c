// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (AIQL.org)

#include <stdio.h>
#include <stdlib.h>
#include "../include/openhttpa.h"

int main() {
    printf("=== OpenHTTPA C Example ===\n\n");

    const char *server_uri = getenv("OPENHTTPA_BACKEND_URL");
    if (!server_uri) {
        server_uri = "http://127.0.0.1:8080";
    }
    const char *model = "llama3";
    const char *messages_json = "[[\"system\", \"You are a secure C assistant.\"], [\"user\", \"Hello from C!\"]]";

    // --- 1. Version Info ---
    char *version = openhttpa_version();
    if (version) {
        printf("[0] Library Version: %s\n", version);
        openhttpa_free_string(version);
    }

    // --- 2. Attestation Handshake ---
    printf("[1] Performing Attestation Handshake (AtHS) with %s...\n", server_uri);
    char *atb_id = openhttpa_attest_handshake(server_uri);
    
    if (atb_id) {
        printf("    Handshake success! Attestation-Binding ID: %s\n", atb_id);
        openhttpa_free_string(atb_id);
    } else {
        fprintf(stderr, "    Error: Handshake failed. Is the backend running?\n");
        return 1;
    }

    // --- 3. Confidential LLM Chat ---
    printf("\n[2] Sending confidential chat request...\n");
    char *reply = openhttpa_confidential_chat(server_uri, model, messages_json);
    
    if (reply) {
        printf("    Assistant Reply: %s\n", reply);
        openhttpa_free_string(reply);
    } else {
        fprintf(stderr, "    Error: Chat request failed.\n");
        return 1;
    }

    printf("\nSuccess: OpenHTTPA protocol verified via C/FFI.\n");

    return 0;
}
