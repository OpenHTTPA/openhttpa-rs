import { test, expect } from '@playwright/test';

test.describe('OpenHTTPA Agent Server AIQL Policies', () => {
  test.beforeEach(async ({ page }) => {
    page.on('console', (msg) => console.log('PAGE LOG:', msg.text()));
    await page.goto('/');
    // Ensure the page has loaded by checking the main heading
    await expect(page.getByRole('heading', { name: 'AI Agent Server' })).toBeVisible();
  });

  test('Case 1: Ambiguous Workflow (Needs Clarification)', async ({ page }) => {
    // Fill out the intent with an ambiguous payload
    await page
      .getByPlaceholder('E.g., I want to transfer')
      .fill('Send some tokens, ambiguous intent');
    await page.getByPlaceholder('E.g., Secure keys or private').fill('My secret E2E memo');

    // Ensure Bypass Clarification is unchecked
    const bypassCheckbox = page.getByLabel('Bypass Clarification');
    await expect(bypassCheckbox).not.toBeChecked();

    // Verify TEE Identity
    await page.getByRole('button', { name: 'Request & Verify TDX Quote' }).click();
    await expect(page.getByText('Verified TDX TEE')).toBeVisible({ timeout: 5000 });

    // Dispatch
    await page.getByRole('button', { name: 'Dispatch Intent' }).click();

    // Verify the clarification modal appears
    const modalHeading = page.getByRole('heading', { name: 'Intent Ambiguous!' });
    await expect(modalHeading).toBeVisible({ timeout: 10000 });

    // Verify server asked clarifying questions
    await expect(page.getByText('Server asked:')).toBeVisible();

    // Verify it was logged in the transaction log
    await expect(page.locator('ul').filter({ hasText: 'Awaiting clarification...' })).toBeVisible();

    // Provide clarity
    await page
      .getByPlaceholder('Provide clarity here...')
      .fill('I meant exactly 50 tokens to agent 0x123');
    await page.getByRole('button', { name: 'Confirm Intent' }).click();

    // Modal should disappear, and dispatch success should be logged
    await expect(modalHeading).toBeHidden({ timeout: 10000 });
    await expect(page.locator('ul').filter({ hasText: 'Clarification accepted!' })).toBeVisible();

    // Verify Receiver Inbox received both the intent and the private payload
    await expect(page.getByText('I meant exactly 50 tokens to agent 0x123')).toBeVisible();
    await expect(page.getByText('My secret E2E memo')).toBeVisible();
  });

  test('Case 2: Deterministic Bypass Workflow', async ({ page }) => {
    // Fill out the intent
    await page.getByPlaceholder('E.g., I want to transfer').fill('Deterministic automated payload');
    await page.getByPlaceholder('E.g., Secure keys or private').fill('My secret E2E memo');

    // Check Bypass Clarification
    await page.getByLabel('Bypass Clarification').check();

    // Set a policy ID just for coverage
    await page.getByPlaceholder('e.g. strict-financial-01').fill('policy-auto-01');

    // Verify TEE Identity
    await page.getByRole('button', { name: 'Request & Verify TDX Quote' }).click();
    await expect(page.getByText('Verified TDX TEE')).toBeVisible({ timeout: 5000 });

    // Dispatch
    await page.getByRole('button', { name: 'Dispatch Intent' }).click();

    // Verify it instantly dispatches and the modal NEVER appears
    const modalHeading = page.getByRole('heading', { name: 'Intent Ambiguous!' });
    await expect(modalHeading).toBeHidden();

    // Verify success in the log
    await expect(
      page.locator('ul').filter({ hasText: 'Intent dispatched immediately.' }),
    ).toBeVisible({ timeout: 10000 });

    // Verify Receiver Inbox received deterministic intent and the private payload
    await expect(page.getByText('Deterministic automated payload')).toBeVisible();
    await expect(page.getByText('My secret E2E memo')).toBeVisible();
  });

  test('Case 3: Simulated Client Security Posture Workflow', async ({ page }) => {
    // Fill out the intent
    await page.getByPlaceholder('E.g., I want to transfer').fill('Posture test payload');

    // Select Simulated TEE posture
    await page.locator('select').selectOption('SimulatedTee');

    // Verify TEE Identity
    await page.getByRole('button', { name: 'Request & Verify TDX Quote' }).click();
    await expect(page.getByText('Verified TDX TEE')).toBeVisible({ timeout: 5000 });

    // Dispatch
    await page.getByRole('button', { name: 'Dispatch Intent' }).click();

    // Verify success in the log
    await expect(
      page.locator('ul').filter({ hasText: 'Intent dispatched immediately.' }),
    ).toBeVisible({ timeout: 10000 });

    // Select Mutual TEE posture
    await page.getByPlaceholder('E.g., I want to transfer').fill('Mutual TEE test payload');
    await page.locator('select').selectOption('MutualTee');
    await page.getByRole('button', { name: 'Dispatch Intent' }).click();

    // Verify success in the log again
    await expect(
      page.locator('li').filter({ hasText: 'Intent dispatched immediately.' }),
    ).toHaveCount(2, { timeout: 10000 });
  });
});
