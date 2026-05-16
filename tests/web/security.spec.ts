// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (AIQL.org)

/**
 * OpenHTTPA Security & Formal Verification — Playwright E2E test suite
 */

import { test, expect, Page } from '@playwright/test';

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function assertNoProtocolErrors(page: Page) {
  const log = page.locator('#plog');
  const text = await log.innerText();
  const errorMarkers = ['!!', '✗', 'Error:', 'failed:'];
  for (const marker of errorMarkers) {
    if (text.includes(marker)) {
      throw new Error(`Protocol Log Error Detected: ${text}`);
    }
  }
}

test.beforeEach(async ({ page }) => {
  // Inject backend URL for local testing
  const backendUrl = process.env.OPENHTTPA_BACKEND_URL ?? '';
  await page.addInitScript((url) => {
    (window as any).OPENHTTPA_CONFIG = { backendUrl: url };
  }, backendUrl);

  await page.goto('/');
});

test.describe('Security & Formal Verification UI', () => {
  test('has Mathematical Assurance section linked in navbar', async ({ page }) => {
    const navLink = page.locator('nav a[href="#formal-verification"]');
    await expect(navLink).toBeVisible();
    await expect(navLink).toHaveText('Mathematical Assurance');

    // Clicking should scroll to the section
    await navLink.click();
    const section = page.locator('#formal-verification');
    await expect(section).toBeVisible();
    await expect(section.locator('h2')).toContainText('Mathematical Assurance');
  });

  test('displays verified status for formal proofs', async ({ page }) => {
    const section = page.locator('#formal-verification');

    // Check ProVerif Card
    const proVerifCard = section.locator('.dcard').filter({ hasText: 'ProVerif Proof' });
    await expect(proVerifCard).toBeVisible();
    await expect(proVerifCard.locator('span')).toHaveText('Verified');

    // Check Tamarin Card
    const tamarinCard = section.locator('.dcard').filter({ hasText: 'Tamarin Prover' });
    await expect(tamarinCard).toBeVisible();
    await expect(tamarinCard.locator('span')).toHaveText('Verified');

    // Check Audit Report link
    const auditLink = section.locator('a:has-text("View Formal Models")');
    await expect(auditLink).toBeVisible();
    await expect(auditLink).toHaveAttribute('href', /.*github.com.*formal/);
  });

  test('handshake section explains SIGMA-I and Hybrid KEM', async ({ page }) => {
    const handshakeSection = page.locator('#handshake');
    await expect(handshakeSection).toBeVisible();
    await expect(handshakeSection.locator('h2')).toContainText('Attestation Handshake');

    const intro = handshakeSection.locator('.sintro').first();
    await expect(intro).toBeVisible();
    const introText = await intro.innerText();
    expect(introText).toContain('SIGMA-I');
    expect(introText).toContain('hybrid post-quantum');
  });
});

test.describe('Edge Cases & Resiliency', () => {
  test('handles WebSocket manual disconnect and reconnect', async ({ page }) => {
    // 1. Enter MPC details to get a session
    await page.fill('#mcp-args', '{"test": 123}');
    const mcpBtn = page.locator('button:has-text("Execute Confidential Tool")');
    await expect(mcpBtn).toBeEnabled();
    await mcpBtn.click();

    // Wait for session ready
    const plog = page.locator('#plog');
    try {
      await expect(plog).toContainText('Session ready', { timeout: 20000 });
    } catch (e) {
      console.log('PROTOCOL LOG CONTENT ON TIMEOUT:', await plog.innerText());
      throw e;
    }

    // 2. Connect WebSocket
    const connectBtn = page.locator('#btn-ws-connect');
    await expect(connectBtn).toBeEnabled();
    await connectBtn.click();

    const wsStatus = page.locator('#ws-status-text');
    await expect(wsStatus).toHaveText('Connected (Secure)', { timeout: 20000 });

    // 3. Manual Stop
    const stopBtn = page.locator('#btn-ws-stop');
    await expect(stopBtn).toBeVisible();
    await stopBtn.click();

    // Wait for the status text to contain 'Disconnected' (case-insensitive)
    await expect(wsStatus).toContainText(/Disconnected/i, { timeout: 15000 });
    await expect(plog).toContainText('Connection closed by user');

    // 4. Reconnect
    await page.click('#btn-ws-connect');
    await expect(wsStatus).toHaveText('Connected (Secure)', { timeout: 10000 });
  });

  test('prevents submission with empty payload', async ({ page }) => {
    await page.fill('#mcp-args', '');
    const btn = page.locator('button:has-text("Execute Confidential Tool")');
    await btn.click();

    const plog = page.locator('#plog');
    // In index.html: logA(ts() + '<span class="le">✗ Payload is empty</span>');
    await expect(plog).toContainText(/empty/i, { timeout: 5000 });
  });

  test('mocks a failed attestation scenario', async ({ page }) => {
    // Intercept /api/handshake and return a mock error
    await page.route('**/api/attest', (route) => {
      route.fulfill({
        status: 403,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Attestation verification failed: TCB Outdated' }),
      });
    });

    await page.fill('#mcp-args', '{"test": 123}');
    await page.click('button:has-text("Execute Confidential Tool")');

    const plog = page.locator('#plog');
    await expect(plog).toContainText('Attestation verification failed', { timeout: 30000 });
  });
});
