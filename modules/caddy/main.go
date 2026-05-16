// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (AIQL.org)

package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	hcf "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	"github.com/openhttpa/openhttpa-go"
)

func init() {
	caddy.RegisterModule(OpenHttpa{})
	hcf.RegisterHandlerDirective("openhttpa", func(h hcf.Helper) (caddyhttp.MiddlewareHandler, error) {
		mod := new(OpenHttpa)
		err := mod.UnmarshalCaddyfile(h.Dispenser)
		return mod, err
	})
}

func main() {
	caddycmd.Main()
}

const MaxResponseBodySize = 10 * 1024 * 1024 // 10MB limit

// OpenHttpa is a Caddy module that enables OpenHTTPA features.
type OpenHttpa struct {
	// Add config fields if needed
}

// CaddyModule returns the Caddy module information.
func (OpenHttpa) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.openhttpa",
		New: func() caddy.Module { return new(OpenHttpa) },
	}
}

// Provision sets up the module.
func (h *OpenHttpa) Provision(ctx caddy.Context) error {
	return nil
}

// ServeHTTP implements caddyhttp.Handler.
func (h *OpenHttpa) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Handle Handshake (AtHS)
	if r.Method == http.MethodPost && r.URL.Path == "/api/attest" {
		// [H-03 Hardening] OOM Mitigation: Limit request body size for handshakes
		limitedBody := io.LimitReader(r.Body, 64*1024) // Handshakes should be small (<64KB)
		body, err := io.ReadAll(limitedBody)
		if err != nil {
			return caddyhttp.Error(http.StatusBadRequest, err)
		}
		
		resp, err := openhttpa.ServerHandshake(string(body))
		if err != nil {
			return caddyhttp.Error(http.StatusForbidden, err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(resp))
		return nil
	}

	// Handle Trusted Request (TrR)
	if atbID := r.Header.Get("Attest-Base-ID"); atbID != "" {
		nonceStr := r.Header.Get("Attest-Nonce")
		var nonce uint64
		fmt.Sscanf(nonceStr, "%d", &nonce)

		// [M-01 Hardening] Limit request size
		limitedBody := io.LimitReader(r.Body, MaxResponseBodySize)
		body, err := io.ReadAll(limitedBody)
		if err != nil {
			return caddyhttp.Error(http.StatusRequestEntityTooLarge, err)
		}

		var trr struct {
			Ciphertext string `json:"ciphertext"`
		}
		if err := json.Unmarshal(body, &trr); err != nil {
			return caddyhttp.Error(http.StatusBadRequest, err)
		}

		plaintext, err := openhttpa.ServerDecrypt(atbID, nonce, trr.Ciphertext)
		if err != nil {
			return caddyhttp.Error(http.StatusForbidden, err)
		}

		// Replace request body with decrypted plaintext
		r.Body = io.NopCloser(strings.NewReader(plaintext))
		r.ContentLength = int64(len(plaintext))

		// [H-04 Hardening] Intercept response for TrS without full buffering if possible.
		// For now, we still need to buffer to encrypt the full payload as OpenHTTPA v0.1.0 
		// uses monolithic AEAD for simplicity. However, we add an explicit size check 
		// during capture to prevent memory exhaustion.
		rw := &responseInterceptor{
			ResponseWriter: w, 
			body:           new(strings.Builder),
			maxSize:        MaxResponseBodySize,
		}
		err = next.ServeHTTP(rw, r)
		if err != nil {
			return err
		}

		// Encrypt response
		plaintextHex := hex.EncodeToString([]byte(rw.body.String()))
		ciphertext, err := openhttpa.ServerEncrypt(atbID, plaintextHex)
		if err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}

		// Send encrypted response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rw.status)
		w.Write([]byte(ciphertext))
		return nil
	}

	return next.ServeHTTP(w, r)
}

type responseInterceptor struct {
	http.ResponseWriter
	body    *strings.Builder
	status  int
	maxSize int
}

func (rw *responseInterceptor) WriteHeader(status int) {
	if rw.status == 0 {
		rw.status = status
	}
}

func (rw *responseInterceptor) Write(b []byte) (int, error) {
	if rw.body.Len()+len(b) > rw.maxSize {
		return 0, fmt.Errorf("response body exceeds MaxResponseBodySize (%d bytes)", rw.maxSize)
	}
	return rw.body.Write(b)
}

// Flush implements http.Flusher.
func (rw *responseInterceptor) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker.
func (rw *responseInterceptor) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("http.Hijacker not implemented")
}

// UnmarshalCaddyfile sets up the module from Caddyfile.
func (h *OpenHttpa) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*OpenHttpa)(nil)
	_ caddyhttp.MiddlewareHandler = (*OpenHttpa)(nil)
	_ caddyfile.Unmarshaler       = (*OpenHttpa)(nil)
	_ http.Flusher                = (*responseInterceptor)(nil)
	_ http.Hijacker               = (*responseInterceptor)(nil)
)
