// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

/**
 * AHL MAC Verification — Playwright E2E test suite
 *
 * Tests for the HMAC-SHA384 Attest Header List (AHL) binding that protects
 * each encrypted request.  These cases cover the exact scenarios that were
 * diagnosed during the `enhancements` branch hardening:
 *
 *   - Happy path: correct origin-host authority passes MAC check (regression
 *     test for the browser-cache / authority-mismatch bug)
 *   - Tampered Attest-Ticket bytes → 401
 *   - Replayed nonce → 401  (StrictMonotonic strategy enforced)
 *   - Wrong authority in ticket → 401
 *   - Counter monotonically increments on every openhttpa_seal call
 *   - Multiple sequential submissions all succeed end-to-end
 *   - Attest-Binder / Attest-Ticket headers are excluded from the AHL
 *     (extra values in those fields must not break MAC verification)
 */

import { test, expect, Page } from '@playwright/test';

// ─── Types for window globals set by index.html ───────────────────────────────

declare global {
  interface Window {
    wasmModule: {
      openhttpa_seal(base_id: string, plaintext: string): string;
      openhttpa_seal_with_ahl(
        base_id: string,
        plaintext: string,
        method: string,
        path: string,
        query: string | null,
        headers_json: string,
      ): string;
      openhttpa_compute_ticket(
        base_id: string,
        nonce: bigint,
        method: string,
        path: string,
        query: string | null,
        headers_json: string,
      ): string;
      openhttpa_unseal(base_id: string, ciphertext: string): string;
    };
    WASM_SESSION: { base_id: string; transcript_hash: string } | null;
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Perform a full AtHS handshake by clicking the Handshake button. */
async function doHandshake(page: Page) {
  await page.click('#btn-wasm');
  await expect(page.locator('#wasm-status')).toContainText('Session ready', { timeout: 15000 });
}

// ─── Test suite ───────────────────────────────────────────────────────────────

test.describe('AHL MAC Verification', () => {
  test.beforeEach(async ({ page, request }) => {
    // Reset server state before each test to avoid cross-test contamination.
    await request.post('/api/reset');
    await page.goto('/');
    page.on('console', (msg) => {
      if (msg.type() === 'error') console.error(`BROWSER: ${msg.text()}`);
    });
  });

  // ── Regression: authority binding ─────────────────────────────────────────

  test('ticket MAC passes when authority equals window.location.host', async ({ page }) => {
    // Regression test for the browser-cache / authority-mismatch bug:
    // When loaded from http://127.0.0.1:PORT, window.location.host is
    // "127.0.0.1:PORT", which must match the Host header the server receives
    // via nginx's `proxy_set_header Host $http_host` directive.
    await doHandshake(page);

    const result = await page.evaluate(async () => {
      const proof = window.WASM_SESSION!;
      const sealed = JSON.parse(
        window.wasmModule.openhttpa_seal(
          proof.base_id,
          JSON.stringify({ party_id: 'alice', value: 42 }),
        ),
      );
      const ticket = window.wasmModule.openhttpa_compute_ticket(
        proof.base_id,
        BigInt(sealed.counter),
        'POST',
        '/api/submit',
        null,
        JSON.stringify({
          'attest-base-id': proof.base_id,
          'content-type': 'application/json',
          host: window.location.host,
        }),
      );
      const resp = await fetch('/api/submit', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Attest-Base-ID': proof.base_id,
          'Attest-Ticket': ticket,
        },
        body: JSON.stringify({ ciphertext: sealed.ciphertext }),
      });
      return { status: resp.status, body: await resp.text() };
    });

    expect(result.status).toBe(200);
    expect(result.body).not.toContain('Invalid header MAC');
  });

  // ── Tampered ticket rejection ──────────────────────────────────────────────

  test('tampered Attest-Ticket bytes → 401 Invalid header MAC', async ({ page }) => {
    await doHandshake(page);

    const result = await page.evaluate(async () => {
      const proof = window.WASM_SESSION!;
      const sealed = JSON.parse(
        window.wasmModule.openhttpa_seal(
          proof.base_id,
          JSON.stringify({ party_id: 'bob', value: 99 }),
        ),
      );
      const ticket = window.wasmModule.openhttpa_compute_ticket(
        proof.base_id,
        BigInt(sealed.counter),
        'POST',
        '/api/submit',
        null,
        JSON.stringify({
          'attest-base-id': proof.base_id,
          'content-type': 'application/json',
          host: window.location.host,
        }),
      );

      // Decode base64 → flip the last byte of the HMAC → re-encode.
      const raw = Uint8Array.from(atob(ticket), (c) => c.charCodeAt(0));
      raw[raw.length - 1] ^= 0xff;
      const tampered = btoa(String.fromCharCode(...raw));

      const resp = await fetch('/api/submit', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Attest-Base-ID': proof.base_id,
          'Attest-Ticket': tampered,
        },
        body: JSON.stringify({ ciphertext: sealed.ciphertext }),
      });
      return { status: resp.status, body: await resp.text() };
    });

    expect(result.status).toBe(401);
    expect(result.body).toContain('MAC');
  });

  // ── Nonce replay rejection ─────────────────────────────────────────────────

  test('replayed Attest-Ticket nonce → 401', async ({ page }) => {
    // The demo session uses StrictMonotonic replay strategy:
    // once a nonce N is accepted, any subsequent attempt with nonce ≤ N is rejected.
    await doHandshake(page);

    const result = await page.evaluate(async () => {
      const proof = window.WASM_SESSION!;

      const headers = JSON.stringify({
        'attest-base-id': proof.base_id,
        'content-type': 'application/json',
        host: window.location.host,
      });

      async function submit(ticket: string, ciphertext: string) {
        const r = await fetch('/api/submit', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Attest-Base-ID': proof.base_id,
            'Attest-Ticket': ticket,
          },
          body: JSON.stringify({ ciphertext }),
        });
        return r.status;
      }

      // First submission — nonce 1.
      const s1 = JSON.parse(
        window.wasmModule.openhttpa_seal(
          proof.base_id,
          JSON.stringify({ party_id: 'alice', value: 1 }),
        ),
      );
      const t1 = window.wasmModule.openhttpa_compute_ticket(
        proof.base_id,
        BigInt(s1.counter),
        'POST',
        '/api/submit',
        null,
        headers,
      );
      const status1 = await submit(t1, s1.ciphertext);

      // Replay the same ticket (same nonce). The server must reject it.
      // Use a fresh seal so the ciphertext/body is different — only the
      // nonce-based MAC matters for replay detection.
      const s2 = JSON.parse(
        window.wasmModule.openhttpa_seal(
          proof.base_id,
          JSON.stringify({ party_id: 'alice', value: 2 }),
        ),
      );
      const statusReplay = await submit(t1, s2.ciphertext); // same ticket t1

      return { status1, statusReplay };
    });

    expect(result.status1).toBe(200);
    expect(result.statusReplay).toBe(401);
  });

  // ── Wrong authority rejection ──────────────────────────────────────────────

  test('ticket computed with wrong authority → 401', async ({ page }) => {
    // The AHL binds method + path + authority + attest-* headers.
    // A ticket where the 'host' field in the headers JSON does not match
    // what the server sees in its Host header must be rejected.
    await doHandshake(page);

    const result = await page.evaluate(async () => {
      const proof = window.WASM_SESSION!;
      const sealed = JSON.parse(
        window.wasmModule.openhttpa_seal(
          proof.base_id,
          JSON.stringify({ party_id: 'charlie', value: 7 }),
        ),
      );
      // Deliberately use a wrong host value.
      const ticket = window.wasmModule.openhttpa_compute_ticket(
        proof.base_id,
        BigInt(sealed.counter),
        'POST',
        '/api/submit',
        null,
        JSON.stringify({
          'attest-base-id': proof.base_id,
          'content-type': 'application/json',
          host: 'wrong-host.example.com:9999',
        }),
      );
      const resp = await fetch('/api/submit', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Attest-Base-ID': proof.base_id,
          'Attest-Ticket': ticket,
        },
        body: JSON.stringify({ ciphertext: sealed.ciphertext }),
      });
      return { status: resp.status, body: await resp.text() };
    });

    expect(result.status).toBe(401);
  });

  // ── Counter monotonicity ───────────────────────────────────────────────────

  test('openhttpa_seal counter increments monotonically from 1', async ({ page }) => {
    // Each call to openhttpa_seal must return a strictly increasing counter
    // starting from 1 (nonce 0 is reserved / rejected by the server).
    await doHandshake(page);

    const counters = await page.evaluate(() => {
      const proof = window.WASM_SESSION!;
      const results: number[] = [];
      for (let i = 0; i < 3; i++) {
        const sealed = JSON.parse(
          window.wasmModule.openhttpa_seal(proof.base_id, JSON.stringify({ i })),
        );
        results.push(sealed.counter);
      }
      return results;
    });

    // Counters start at 1 and increment by 1 per seal call.
    expect(counters[0]).toBeGreaterThanOrEqual(1);
    expect(counters[1]).toBe(counters[0] + 1);
    expect(counters[2]).toBe(counters[1] + 1);
  });

  // ── Sequential multi-party submission ─────────────────────────────────────

  test('sequential submissions for all three parties all return 200', async ({ page }) => {
    // Exercises the full submit path three times with monotonically increasing
    // nonces, including the mandatory openhttpa_unseal of each server response
    // to keep the server_counter in sync.
    await doHandshake(page);

    const statuses = await page.evaluate(async () => {
      const proof = window.WASM_SESSION!;
      const results: number[] = [];

      for (const [partyId, value] of [
        ['alice', 10],
        ['bob', 20],
        ['charlie', 30],
      ] as [string, number][]) {
        const sealed = JSON.parse(
          window.wasmModule.openhttpa_seal(
            proof.base_id,
            JSON.stringify({ party_id: partyId, value }),
          ),
        );
        const ticket = window.wasmModule.openhttpa_compute_ticket(
          proof.base_id,
          BigInt(sealed.counter),
          'POST',
          '/api/submit',
          null,
          JSON.stringify({
            'attest-base-id': proof.base_id,
            'content-type': 'application/json',
            host: window.location.host,
          }),
        );
        const resp = await fetch('/api/submit', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Attest-Base-ID': proof.base_id,
            'Attest-Ticket': ticket,
          },
          body: JSON.stringify({ ciphertext: sealed.ciphertext }),
        });
        // Unseal server response to advance server_counter and keep WASM in sync.
        const enc = await resp.json();
        window.wasmModule.openhttpa_unseal(proof.base_id, enc.ciphertext);
        results.push(resp.status);
      }

      return results;
    });

    expect(statuses).toEqual([200, 200, 200]);
  });

  // ── AHL exclusion: Attest-Binder and Attest-Ticket ────────────────────────

  test('Attest-Binder and Attest-Ticket values in headers JSON are excluded from AHL', async ({
    page,
  }) => {
    // The AHL spec mandates that attest-binder and attest-ticket are never
    // included in the MAC computation (to avoid circular dependency).
    // Adding them to the headers JSON passed to openhttpa_compute_ticket must
    // not change the resulting MAC: the server, which excludes them from its
    // own AHL computation, must still accept the ticket.
    await doHandshake(page);

    const result = await page.evaluate(async () => {
      const proof = window.WASM_SESSION!;
      const sealed = JSON.parse(
        window.wasmModule.openhttpa_seal(
          proof.base_id,
          JSON.stringify({ party_id: 'alice', value: 5 }),
        ),
      );
      // Include attest-binder and attest-ticket in the headers JSON.
      // Both must be silently excluded from the AHL computation.
      const ticket = window.wasmModule.openhttpa_compute_ticket(
        proof.base_id,
        BigInt(sealed.counter),
        'POST',
        '/api/submit',
        null,
        JSON.stringify({
          'attest-base-id': proof.base_id,
          'attest-binder': 'should-be-excluded',
          'attest-ticket': 'also-excluded',
          'content-type': 'application/json',
          host: window.location.host,
        }),
      );
      const resp = await fetch('/api/submit', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Attest-Base-ID': proof.base_id,
          'Attest-Ticket': ticket,
          'Attest-Binder': 'some-binder-value',
        },
        body: JSON.stringify({ ciphertext: sealed.ciphertext }),
      });
      return { status: resp.status, body: await resp.text() };
    });

    // The MAC must verify despite attest-binder/attest-ticket being present.
    expect(result.status).toBe(200);
    expect(result.body).not.toContain('Invalid header MAC');
  });
});
