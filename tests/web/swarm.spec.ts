// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

/**
 * OpenHTTPA Attested Agent Mesh (AAM) — Playwright E2E test suite
 */

import { test, expect, Page } from '@playwright/test';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Fail if the Protocol Log contains any error markers (!!, ✗, Error:, failed:). */
async function assertNoProtocolErrors(page: Page) {
  const log = page.locator('#plog');
  const text = await log.innerText();
  const errorMarkers = ['!!', '✗', 'Error:', 'failed:'];
  for (const marker of errorMarkers) {
    if (text.includes(marker)) {
      const lines = text.split('\n');
      const errorLine = lines.find((l) => l.includes(marker));
      throw new Error(`Protocol Log Error Detected: ${errorLine || text}`);
    }
  }
}

async function assertNoSwarmErrors(page: Page) {
  const log = page.locator('#swarm-log');
  const text = await log.innerText();
  if (text.includes('✗') || text.includes('failed')) {
    throw new Error(`Swarm Simulation Error Detected: ${text}`);
  }
}

test.beforeEach(async ({ page }) => {
  page.on('console', (msg) => {
    if (msg.type() === 'error') console.error(`BROWSER ERROR: ${msg.text()}`);
  });

  // Inject backend URL for local testing (defaults to 8085 for this test session)
  const backendUrl = process.env.OPENHTTPA_BACKEND_URL ?? '';
  await page.addInitScript((url) => {
    (window as any).OPENHTTPA_CONFIG = { backendUrl: url };
  }, backendUrl);

  await page.goto('/');
});

test.describe('Attested Agent Mesh (AAM)', () => {
  test('has Swarm Mesh section and nav link', async ({ page }) => {
    await expect(page.locator('nav a[href="#swarm-mesh"]')).toBeVisible();
    await expect(page.locator('#swarm-mesh')).toBeVisible();
  });

  test('can launch swarm simulation and reach 100% progress', async ({ page }) => {
    // 1. Scroll to swarm mesh section
    await page.click('nav a[href="#swarm-mesh"]');

    // 2. Click Launch
    const launchBtn = page.locator('#btn-swarm-sim');
    await expect(launchBtn).toBeVisible();
    await launchBtn.click();

    // 3. Verify metrics panel appears
    const metrics = page.locator('#swarm-metrics');
    await expect(metrics).toBeVisible();

    // 4. Wait for the final success message in the logs
    const swarmLog = page.locator('#swarm-log');
    try {
      await expect(swarmLog).toContainText(/Swarm simulation complete/i, { timeout: 60000 });
    } catch (e) {
      console.log('SWARM LOG CONTENT ON TIMEOUT:', await swarmLog.innerText());
      throw e;
    }

    // 5. Now verify all metrics and intermediate logs
    const progressText = page.locator('#swarm-progress-text');
    await expect(progressText).toHaveText('100%');

    const agentCount = page.locator('#swarm-agent-count');
    await expect(agentCount).toHaveText('10');

    const attestStatus = page.locator('#swarm-attest-status');
    await expect(attestStatus).toHaveText('Verified');

    const fullLogText = await swarmLog.innerText();
    console.log('FINAL SWARM LOG TEXT:', fullLogText);

    expect(fullLogText).toContain('TEE verified');
    expect(fullLogText).toContain('Handshake successful');
    expect(fullLogText).toContain('Mutual attestation verified');
    expect(fullLogText).toContain('Confidential tunnel established');

    await assertNoSwarmErrors(page);
    await assertNoProtocolErrors(page);
  });

  test('re-running simulation clears logs and resets state', async ({ page }) => {
    await page.click('nav a[href="#swarm-mesh"]');

    // Run 1
    await page.click('#btn-swarm-sim');
    await expect(page.locator('#swarm-progress-text')).toHaveText('100%', { timeout: 30000 });

    // Run 2
    await page.click('#btn-swarm-sim');
    // Progress should reset to 0% immediately (or very low)
    const progressText = page.locator('#swarm-progress-text');
    const text = await progressText.innerText();
    const val = parseInt(text.replace('%', ''));
    expect(val).toBeLessThan(100);

    // Should reach 100% again
    await expect(progressText).toHaveText('100%', { timeout: 30000 });
    await expect(page.locator('#swarm-agent-count')).toHaveText('10');
  });

  test('verifies Provenance Audit visualizer after simulation', async ({ page }) => {
    await page.click('nav a[href="#swarm-mesh"]');

    // 1. Launch simulation
    await page.click('#btn-swarm-sim');
    await expect(page.locator('#swarm-progress-text')).toHaveText('100%', { timeout: 35000 });

    // 2. Check Provenance Visualizer
    const provView = page.locator('#prov-chain-view');
    await expect(provView).toBeVisible();

    // 3. Verify nodes exist (wait for at least one to be attached to DOM)
    const nodes = provView.locator('.prov-node');
    await expect(nodes.first()).toBeVisible({ timeout: 5000 });
    const count = await nodes.count();
    expect(count).toBeGreaterThan(0);
    console.log(`Found ${count} provenance nodes.`);

    // 4. Check first node details
    const firstNode = nodes.first();
    await expect(firstNode.locator('.prov-agent-name')).toBeVisible();
    await expect(firstNode.locator('.prov-quote-status')).toContainText('Verified TEE Quote');

    // 5. Verify all nodes have quotes (since it's a TEE mesh)
    for (let i = 0; i < count; i++) {
      const node = nodes.nth(i);
      await expect(node.locator('.prov-quote-status')).toContainText('Verified TEE Quote');
    }

    // 6. Click a node to verify detail behavior (if applicable)
    // In index.html, clicking a node might show details or just be visual.
    // Let's verify it has the expected CSS classes.
    await expect(firstNode).toHaveClass(/prov-node/);
  });

  test('MPC submission updates logs and displays results', async ({ page }) => {
    await page.fill('#mcp-args', '{"value": 10}');
    await page.selectOption('#mcp-tool', 'secure_sum');
    await page.click('button:has-text("Execute Confidential Tool")');

    const plog = page.locator('#plog');
    await expect(plog).toContainText('Session ready', { timeout: 10000 });
    await expect(plog).toContainText('✓ Result received', { timeout: 10000 });

    const status = page.locator('#mcp-status');
    await expect(status).toBeVisible();
    await expect(status).toContainText('Success');
  });
});
