// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

import { test, expect } from '@playwright/test';

/**
 * E2E test suite for OpenHTTPA Attestation.
 *
 * Verifies that the browser client can successfully perform the OpenHTTPA handshake
 * with the server and that the server provides valid hardware attestation quotes.
 */
test.describe('OpenHTTPA Handshake & Attestation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the dashboard or main page
    await page.goto('/');
  });

  /**
   * Scenario: Normal Handshake (TDX Mock)
   *
   * Verifies that the client and server can negotiate a PQC cipher suite and
   * complete the handshake when the server is backed by a TDX TEE.
   */
  test('should complete handshake with TDX attestation', async ({ page }) => {
    // 1. Click 'Connect' or perform action that triggers OpenHTTPA handshake
    const connectBtn = page.locator('#connect-openhttpa');
    await expect(connectBtn).toBeVisible();
    await connectBtn.click();

    // 2. Wait for session to be established
    const status = page.locator('#session-status');
    await expect(status).toHaveText('Connected', { timeout: 30000 });

    // 3. Verify that the TEE type is displayed as tdx
    const teeType = page.locator('#tee-type');
    await expect(teeType).not.toBeEmpty({ timeout: 15000 });
    const expectedTee = process.env.EXPECTED_TEE_TYPE || 'tdx';
    await expect(teeType).toHaveText(expectedTee);

    // 4. Verify that the attestation status marker is present
    const quoteStatus = page.locator('#attestation-status');
    await expect(quoteStatus).toBeVisible({ timeout: 10000 });
    await expect(quoteStatus).toHaveText('Verified');

    // 5. Inspect the quote details (simulated)
    const quoteLocator = page.locator('#raw-quote');
    await expect(quoteLocator).not.toBeEmpty({ timeout: 10000 });
    const quoteHex = await quoteLocator.textContent();
    expect(quoteHex?.length).toBeGreaterThan(0);
  });

  /**
   * Scenario: Multi-TEE Attestation (Composite CPU+GPU)
   *
   * Verifies that the client can handle multiple quotes in a single handshake
   * (e.g. host TDX + NVIDIA H100).
   */
  test('should handle composite CPU+GPU attestation', async ({ page }) => {
    await page.locator('#connect-composite').click({ force: true });

    const status = page.locator('#session-status');
    await expect(status).toHaveText('Connected', { timeout: 30000 });

    // Verify multiple quotes are displayed
    const quoteList = page.locator('.attest-quote-marker');
    await expect(quoteList).toHaveCount(2);

    const types = await quoteList.allTextContents();
    const expectedTee = process.env.EXPECTED_TEE_TYPE || 'tdx';
    expect(types).toContain(expectedTee);
    expect(types).toContain('nvidia_gpu');
  });

  /**
   * Scenario: Attestation Failure
   *
   * Verifies that the client correctly handles a server that fails to provide
   * valid attestation evidence (e.g. simulated driver failure).
   */
  test('should reject connection when attestation fails', async ({ page }) => {
    // This requires the server to be in a failed state
    await page.locator('#connect-failed-tee').click({ force: true });

    const errorAlert = page.locator('#test-alert-error');
    await errorAlert.waitFor({ state: 'visible', timeout: 15000 });
    await expect(errorAlert).toBeVisible();
    await expect(errorAlert).toContainText('TEE hardware driver error');
  });
});
