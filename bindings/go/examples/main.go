// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (AIQL.org)

package main

import (
	"fmt"
	"log"
	"os"

	"openhttpa" // This maps to the local directory in go.mod
)

func getServerURI() string {
	uri := os.Getenv("OPENHTTPA_SERVER")
	if uri == "" {
		uri = os.Getenv("OPENHTTPA_BACKEND_URL")
	}
	if uri == "" {
		return "http://127.0.0.1:8080"
	}
	return uri
}

func main() {
	serverURI := getServerURI()
	fmt.Println("=== OpenHTTPA Go Example ===")

	// --- 1. Attestation Handshake ---
	fmt.Printf("\n[1] Performing Attestation Handshake (AtHS) with %s...\n", serverURI)
	atbID, err := openhttpa.AttestHandshake(serverURI)
	if err != nil {
		fmt.Printf("    Error: %v\n", err)
		fmt.Println("    (Is the backend running? Run 'make up' in demo/multiparty-webapp)")
		os.Exit(1)
	}
	fmt.Printf("    Handshake success! Attestation-Binding ID: %s\n", atbID)

	// --- 2. Confidential LLM Chat ---
	fmt.Println("\n[2] Sending confidential chat request...")
	messages := [][2]string{
		{"system", "You are a secure Go-based assistant."},
		{"user", "What is the primary benefit of ML-KEM in OpenHTTPA?"},
	}

	reply, err := openhttpa.ConfidentialChat(serverURI, "llama3", messages)
	if err != nil {
		log.Fatalf("    Error: %v", err)
	}
	fmt.Printf("    Assistant Reply: %s\n", reply)

	fmt.Println("\nSuccess: OpenHTTPA protocol verified via Go/cgo.")
}
