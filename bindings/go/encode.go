// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

// Package openhttpa — pure-Go helpers (no cgo).
package openhttpa

import "encoding/json"

// encodeMessages serialises a [][2]string slice into the JSON format expected
// by the Rust FFI layer: a JSON array of two-element arrays.
// Using encoding/json guarantees correct escaping for all Unicode code
// points, including embedded quotes, backslashes, and control characters.
// This prevents JSON-injection when message content contains special chars.
func encodeMessages(messages [][2]string) (string, error) {
	if len(messages) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(messages)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
