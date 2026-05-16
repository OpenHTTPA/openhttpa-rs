// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (AIQL.org)

import { test, expect } from '@playwright/test';

/**
 * Verification suite for TEE Hardware Attestation UI reporting.
 */
test.describe('TEE Hardware Attestation Status', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('displays verified banner when running in Hardware mode (tdx)', async ({ page }) => {
    // Mock the status to return a real TEE type
    await page.route('**/api/status', (route) => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          tee_type: 'tdx',
          is_mock: false,
          registry_size: 10,
          party_count: 3,
        }),
      });
    });

    await page.goto('/');

    const marker = page.locator('#tee-status-marker');
    await expect(marker).toBeVisible();
    await expect(marker).toContainText('Hardware Verified');
    await expect(marker).toContainText(/tdx/i);
  });

  test('session proof displays correct TEE hardware type after handshake', async ({ page }) => {
    await page.route('**/api/status', (route) => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          tee_type: 'tdx',
          is_mock: false,
          registry_size: 10,
          party_count: 3,
        }),
      });
    });

    await page.goto('/');

    // Directly call fillSessionProof to verify UI rendering without full handshake
    await page.evaluate(() => {
      (window as any).fillSessionProof({
        session: {
          base_id: 'test-atb-id',
          cipher_suite: 'X25519_ML_KEM768_AES256GCM_SHA384',
          version: 'openhttpa',
          post_quantum: true,
          master_secret_len: 48,
          client_write_key_len: 32,
          server_write_key_len: 32,
          client_write_iv_len: 12,
          server_write_iv_len: 12,
          quote_type: 'tdx',
          quote_count: 1,
          expires_in_secs: 3600,
        },
        transcript_hash: '00'.repeat(48),
        attest_request: [],
        attest_response: [],
      });

      // Make the section visible
      const proof = document.getElementById('session-proof');
      if (proof) proof.classList.add('vis');
    });

    // Wait for session proof to appear
    const proof = page.locator('#session-proof');
    await expect(proof).toBeVisible({ timeout: 5000 });

    const providerEl = page.locator('#sp-provider');
    await expect(providerEl).toContainText(/tdx/i);

    const qtEl = page.locator('#sp-qt');
    await expect(qtEl).toContainText(/Hardware TEE/i);
  });
});
