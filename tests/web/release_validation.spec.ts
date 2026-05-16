import { test, expect } from '@playwright/test';

test.describe('Release Validation', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('UI branding is correct', async ({ page }) => {
    // Wait for the footer to be visible
    const footer = page.locator('.main-footer');
    await expect(footer).toBeVisible({ timeout: 10000 });

    const text = await footer.innerText();
    console.log(`FOOTER TEXT: "${text}"`);

    await expect(footer).toContainText(/The OpenHTTPA Foundation \(AIQL.org\)/i);
  });

  test('AtHS handshake succeeds', async ({ page }) => {
    await page.locator('#btn-wasm').click();
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 30000 });
    const log = page.locator('#plog');
    const text = await log.innerText();
    expect(text).not.toContain('!!');
  });

  test('Confidential Submit + Compute Sum works', async ({ page }) => {
    await page.locator('#btn-wasm').click();
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 30000 });
    await page.selectOption('#party', 'alice');
    await page.fill('#value', '100');
    await page
      .getByRole('button', { name: /submit/i })
      .first()
      .click();
    await expect(page.locator('#sub-ok')).toContainText(/alice submitted 100/i);
    await page.click('text=Compute Sum');
    await expect(page.locator('#rpanel')).toHaveClass(/vis/);
    await expect(page.locator('#sum')).toHaveText('100');
  });
});
