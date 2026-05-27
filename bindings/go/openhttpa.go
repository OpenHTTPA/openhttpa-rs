// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

// Package openhttpa provides Go bindings for the OpenHTTPA Rust library via cgo.
// # Building
// Build the Rust cdylib first:
//	cd ../../ && cargo build --release -p openhttpa-c
//	cp target/release/libopenhttpa_c.{so,dylib,dll} bindings/go/lib/
// Then use the package normally.
// # Example
//	id, err := openhttpa.AttestHandshake("http://127.0.0.1:8080")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	reply, err := openhttpa.ConfidentialChat("http://127.0.0.1:8080", "llama3",
//	    [][2]string{{"user", "Hello!"}})
package openhttpa

/*
#cgo LDFLAGS: -L${SRCDIR}/lib -lopenhttpa_c -Wl,-rpath,${SRCDIR}/lib -ldl -lm
#cgo darwin LDFLAGS: -laws_lc_fips_0_13_14_crypto -framework CoreFoundation -framework Security
#include "openhttpa.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"sync"
	"unsafe"
)

var (
	globalCtx *C.struct_OpenHttpaCtx
	ctxOnce   sync.Once
)

func getCtx() *C.struct_OpenHttpaCtx {
	ctxOnce.Do(func() {
		globalCtx = C.openhttpa_ctx_new()
		if globalCtx == nil {
			panic("openhttpa: failed to initialize FFI context")
		}
	})
	return globalCtx
}

// ErrHandshakeFailed is returned when the attestation handshake fails.
var ErrHandshakeFailed = errors.New("openhttpa: handshake failed")

// ErrChatFailed is returned when the confidential chat request fails.
var ErrChatFailed = errors.New("openhttpa: chat request failed")

// AttestHandshake performs the OpenHTTPA attestation handshake against
// serverURI and returns the allocated AtB ID on success.
func AttestHandshake(serverURI string) (string, error) {
	cURI := C.CString(serverURI)
	defer C.free(unsafe.Pointer(cURI))

	result := C.openhttpa_attest_handshake(getCtx(), cURI)
	if result == nil {
		return "", ErrHandshakeFailed
	}
	defer C.openhttpa_free_string(result)
	return C.GoString(result), nil
}

// ConfidentialChat sends a chat request to a confidential LLM endpoint over
// an attested OpenHTTPA session.
//
// messages is a list of [role, content] pairs.  Both role and content are
// properly JSON-escaped, so arbitrary Unicode content is safe.
func ConfidentialChat(serverURI, model string, messages [][2]string) (string, error) {
	msgsJSON, err := encodeMessages(messages)
	if err != nil {
		return "", err
	}

	cURI := C.CString(serverURI)
	defer C.free(unsafe.Pointer(cURI))
	cModel := C.CString(model)
	defer C.free(unsafe.Pointer(cModel))
	cMsgs := C.CString(msgsJSON)
	defer C.free(unsafe.Pointer(cMsgs))

	result := C.openhttpa_confidential_chat(getCtx(), cURI, cModel, cMsgs)
	if result == nil {
		return "", ErrChatFailed
	}
	defer C.openhttpa_free_string(result)
	return C.GoString(result), nil
}

// ServerHandshake performs a server-side OpenHTTPA handshake using a JSON
// request string. It returns the server-side response JSON on success.
// The session is automatically registered in the internal C-level registry.
func ServerHandshake(requestJSON string) (string, error) {
	cReq := C.CString(requestJSON)
	defer C.free(unsafe.Pointer(cReq))

	result := C.openhttpa_server_handshake(getCtx(), cReq)
	if result == nil {
		return "", ErrHandshakeFailed
	}
	defer C.openhttpa_free_string(result)
	return C.GoString(result), nil
}

// ServerDecrypt decrypts an incoming OpenHTTPA Trusted Request (TrR).
func ServerDecrypt(atbID string, nonce uint64, ciphertextHex string) (string, error) {
	cID := C.CString(atbID)
	defer C.free(unsafe.Pointer(cID))
	cCipher := C.CString(ciphertextHex)
	defer C.free(unsafe.Pointer(cCipher))

	result := C.openhttpa_server_decrypt(getCtx(), cID, C.uint64_t(nonce), cCipher)
	if result == nil {
		return "", errors.New("openhttpa: decryption failed")
	}
	defer C.openhttpa_free_string(result)
	return C.GoString(result), nil
}

// ServerEncrypt encrypts an outgoing OpenHTTPA Trusted Response (TrS).
func ServerEncrypt(atbID string, plaintextHex string) (string, error) {
	cID := C.CString(atbID)
	defer C.free(unsafe.Pointer(cID))
	cPlain := C.CString(plaintextHex)
	defer C.free(unsafe.Pointer(cPlain))

	result := C.openhttpa_server_encrypt(getCtx(), cID, cPlain)
	if result == nil {
		return "", errors.New("openhttpa: encryption failed")
	}
	defer C.openhttpa_free_string(result)
	return C.GoString(result), nil
}
