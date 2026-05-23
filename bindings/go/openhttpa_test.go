// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

package openhttpa

import (
	"encoding/json"
	"errors"
	"testing"
)

// ─── encodeMessages ─────────────────────────────────────────────────────────

// TestEncodeMessagesEmpty verifies that an empty slice encodes to "[]".
func TestEncodeMessagesEmpty(t *testing.T) {
	got, err := encodeMessages(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "[]" {
		t.Errorf("got %q, want %q", got, "[]")
	}
}

// TestEncodeMessagesSingle verifies a single-element slice.
func TestEncodeMessagesSingle(t *testing.T) {
	msgs := [][2]string{{"user", "Hello!"}}
	got, err := encodeMessages(msgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Round-trip through the JSON decoder.
	var decoded [][2]string
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("produced invalid JSON %q: %v", got, err)
	}
	if len(decoded) != 1 || decoded[0] != msgs[0] {
		t.Errorf("round-trip mismatch: got %v, want %v", decoded, msgs)
	}
}

// TestEncodeMessagesMultiple verifies multiple messages encode in order.
func TestEncodeMessagesMultiple(t *testing.T) {
	msgs := [][2]string{
		{"system", "You are helpful."},
		{"user", "What is 2+2?"},
		{"assistant", "4"},
	}
	got, err := encodeMessages(msgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded [][2]string
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("produced invalid JSON %q: %v", got, err)
	}
	if len(decoded) != len(msgs) {
		t.Fatalf("length mismatch: got %d, want %d", len(decoded), len(msgs))
	}
	for i := range msgs {
		if decoded[i] != msgs[i] {
			t.Errorf("index %d: got %v, want %v", i, decoded[i], msgs[i])
		}
	}
}

// TestEncodeMessagesSpecialCharsInRole verifies that role values with special
// characters are properly escaped.
func TestEncodeMessagesSpecialCharsInRole(t *testing.T) {
	msgs := [][2]string{{"use\"r", "hi"}}
	got, err := encodeMessages(msgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded [][2]string
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("produced invalid JSON after special chars in role: %v", err)
	}
	if decoded[0][0] != `use"r` {
		t.Errorf("role not preserved: got %q", decoded[0][0])
	}
}

// TestEncodeMessagesSpecialCharsInContent verifies that content with embedded
// quotes and backslashes is properly escaped so the JSON stays valid.
func TestEncodeMessagesSpecialCharsInContent(t *testing.T) {
	tricky := `He said "hello" and she said \bye\.`
	msgs := [][2]string{{"user", tricky}}
	got, err := encodeMessages(msgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded [][2]string
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("invalid JSON after special chars: %v\njson: %s", err, got)
	}
	if decoded[0][1] != tricky {
		t.Errorf("content not preserved: got %q, want %q", decoded[0][1], tricky)
	}
}

// TestEncodeMessagesUnicode verifies that non-ASCII content round-trips.
func TestEncodeMessagesUnicode(t *testing.T) {
	msgs := [][2]string{{"user", "こんにちは 🌍"}}
	got, err := encodeMessages(msgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded [][2]string
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("invalid JSON for unicode content: %v", err)
	}
	if decoded[0][1] != "こんにちは 🌍" {
		t.Errorf("unicode not preserved: got %q", decoded[0][1])
	}
}

// TestEncodeMessagesNewlineAndTab verifies that control characters are escaped.
func TestEncodeMessagesNewlineAndTab(t *testing.T) {
	msgs := [][2]string{{"user", "line1\nline2\ttab"}}
	got, err := encodeMessages(msgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded [][2]string
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("invalid JSON for control chars: %v", err)
	}
	if decoded[0][1] != "line1\nline2\ttab" {
		t.Errorf("control chars not preserved: got %q", decoded[0][1])
	}
}

// TestEncodeMessagesTableDriven is a table-driven test covering role mapping
// semantics (role is preserved verbatim since the C layer does the mapping).
func TestEncodeMessagesTableDriven(t *testing.T) {
	cases := []struct {
		name string
		msgs [][2]string
		want int // expected number of elements after round-trip
	}{
		{"zero messages", nil, 0},
		{"one user message", [][2]string{{"user", "hi"}}, 1},
		{"system + user", [][2]string{{"system", "prompt"}, {"user", "q"}}, 2},
		{"all roles", [][2]string{{"system", "s"}, {"user", "u"}, {"assistant", "a"}}, 3},
		{"unknown role passthrough", [][2]string{{"robot", "beep"}}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := encodeMessages(tc.msgs)
			if err != nil {
				t.Fatalf("encodeMessages error: %v", err)
			}
			var decoded [][2]string
			if err := json.Unmarshal([]byte(got), &decoded); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
			if len(decoded) != tc.want {
				t.Errorf("length: got %d, want %d", len(decoded), tc.want)
			}
		})
	}
}

// ─── Sentinel errors ─────────────────────────────────────────────────────────

// TestSentinelErrors verifies that the exported error variables are distinct
// and can be compared with errors.Is.
func TestSentinelErrors(t *testing.T) {
	if ErrHandshakeFailed == nil {
		t.Fatal("ErrHandshakeFailed must not be nil")
	}
	if ErrChatFailed == nil {
		t.Fatal("ErrChatFailed must not be nil")
	}
	if errors.Is(ErrHandshakeFailed, ErrChatFailed) {
		t.Error("ErrHandshakeFailed and ErrChatFailed must be distinct")
	}
}

// ─── Smoke tests (require native library) ────────────────────────────────────

// TestAttestHandshakeSmoke is a smoke test that verifies the binding compiles
// and returns a non-empty AtB ID.  Requires the native library to be present.
func TestAttestHandshakeSmoke(t *testing.T) {
	t.Skip("requires native openhttpa-c library; run with -run=TestAttestHandshake after `cargo build --release -p openhttpa-c`")
	id, err := AttestHandshake("http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("expected non-empty AtB ID")
	}
}

// TestConfidentialChatSmoke verifies the ConfidentialChat path end-to-end.
func TestConfidentialChatSmoke(t *testing.T) {
	t.Skip("requires native openhttpa-c library; run after `cargo build --release -p openhttpa-c`")
	reply, err := ConfidentialChat("http://127.0.0.1:8080", "llama3",
		[][2]string{{"user", "What is 1+1?"}})
	if err != nil {
		t.Fatal(err)
	}
	if reply == "" {
		t.Fatal("expected non-empty reply")
	}
}
