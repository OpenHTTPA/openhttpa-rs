// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (AIQL.org)

import { test, expect } from '@playwright/test';
import { randomBytes } from 'crypto';

/** Generate a hex string of `byteLen` random bytes. */
function randHex(byteLen: number): string {
  return randomBytes(byteLen).toString('hex');
}

/** A "valid" (all-zero) ML-KEM-768 public key for testing. */
const MOCK_MLKEM_PK = '00'.repeat(1184);

test.describe('HTTPA/3 0-RTT Resumption', () => {
  test('Full 0-RTT Handshake + Resumption Flow', async ({ request }) => {
    console.log('--- Step 1: Initial Handshake ---');
    const hres = await request.post('/api/attest', {
      data: {
        client_random: randHex(32),
        ecdhe_public: randHex(32),
        mlkem_public: MOCK_MLKEM_PK,
      },
    });
    expect(hres.ok()).toBeTruthy();
    const { base_id } = await hres.json();
    console.log(`Initial Session established: ${base_id}`);

    console.log('--- Step 2: Retrieve Resumption Ticket ---');
    const tres = await request.post('/api/ticket', {
      headers: { 'Attest-Base-ID': base_id },
    });
    expect(tres.ok()).toBeTruthy();

    const rawBody = await tres.text();
    console.log(`Raw ticket body: ${rawBody.substring(0, 100)}...`);

    let ticket_hex: string;
    try {
      const parsed = JSON.parse(rawBody);
      if (typeof parsed === 'object' && parsed !== null && 'ciphertext' in parsed) {
        ticket_hex = (parsed as any).ciphertext;
      } else if (typeof parsed === 'string') {
        ticket_hex = parsed;
      } else {
        ticket_hex = rawBody; // Fallback to raw text
      }
    } catch (e) {
      ticket_hex = rawBody; // Not JSON, assume raw text
    }

    // Final cleanup of quotes if they exist
    if (ticket_hex.startsWith('"') && ticket_hex.endsWith('"')) {
      ticket_hex = ticket_hex.substring(1, ticket_hex.length - 1);
    }

    expect(typeof ticket_hex).toBe('string');
    expect(ticket_hex.length).toBeGreaterThan(64);
    console.log(`Ticket retrieved (hex length: ${ticket_hex.length})`);

    console.log('--- Step 3: 0-RTT Resumption Flight ---');
    // We send the ticket in the header. The server should restore the session
    // using the Rtt0ResumptionLayer.
    const rres = await request.get('/api/result', {
      headers: {
        'Attest-Ticket-Resumption': ticket_hex,
        'Attest-Base-ID': base_id,
      },
    });

    if (!rres.ok()) {
      const errorText = await rres.text();
      console.error('0-RTT Resumption failed:', errorText);
    }

    expect(rres.status()).toBe(200);
    const body = await rres.json();
    expect(body.ciphertext).toBeDefined();
    console.log('✓ 0-RTT Resumption successful: Server accepted ticket and restored session.');
  });

  test('0-RTT Resumption REJECTS invalid ticket', async ({ request }) => {
    const invalidTicket = '00'.repeat(100);
    const res = await request.get('/api/result', {
      headers: {
        'Attest-Ticket-Resumption': invalidTicket,
        'Attest-Base-ID': '00000000-0000-0000-0000-000000000000',
      },
    });
    // Should fail with 401 or 403 (session not found or unauthorized)
    expect([401, 403]).toContain(res.status());
  });
});
