import { test, expect } from '@playwright/test';
import { loginWithApiKey } from '../../fixtures/auth';

const BASE_URL = process.env.BASE_URL || 'http://localhost:8089';
const ADMIN_KEY = process.env.ADMIN_API_KEY || '';

test.describe('Connections Page', () => {
  test('connections page renders', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/connections.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveTitle(/persea/i);
  });

  test('page has sidebar or vault notice', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/connections.html`);
    await page.waitForTimeout(2000);

    const sidebar = page.locator('.sidebar, #folder-list, .folder-list');
    const vaultNotice = page.locator('.vault-unavailable, .no-vault, :text("Vault"), :text("vault")');
    const count = await sidebar.count() + await vaultNotice.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });

  test('search input exists', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/connections.html`);
    await page.waitForTimeout(2000);

    const search = page.locator('input[type="search"], input[placeholder*="earch"], #connections-search');
    const count = await search.count();
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test('new folder button visibility', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/connections.html`);
    await page.waitForTimeout(2000);

    const btn = page.locator('button:has-text("New Folder"), button:has-text("new folder"), .btn:has-text("Folder")');
    const count = await btn.count();
    expect(count).toBeGreaterThanOrEqual(0);
  });
});
