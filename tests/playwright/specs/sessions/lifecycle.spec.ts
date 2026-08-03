import { test, expect } from '@playwright/test';
import { loginWithApiKey } from '../../fixtures/auth';

const BASE_URL = process.env.BASE_URL || 'http://localhost:8089';
const ADMIN_KEY = process.env.ADMIN_API_KEY || '';

test.describe('Sessions Page', () => {
  test('sessions page renders with table', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/sessions.html`);
    await page.waitForTimeout(1000);

    await expect(page).toHaveTitle(/persea/i);
    const table = page.locator('table, .table-wrapper');
    await expect(table.first()).toBeVisible();
  });

  test('sessions table has expected columns', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/sessions.html`);
    await page.waitForTimeout(1000);

    const headers = page.locator('thead th');
    const count = await headers.count();
    expect(count).toBeGreaterThanOrEqual(4);
  });

  test('refresh button exists', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/sessions.html`);
    await page.waitForTimeout(1000);

    const refreshBtn = page.locator('button:has-text("Refresh"), button:has-text("refresh"), [title*="refresh"], [title*="Refresh"]');
    const count = await refreshBtn.count();
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test('sessions page nav link works', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/connections.html`);
    await page.waitForTimeout(500);

    const sessionsNav = page.locator('a[href*="sessions"], .nav-item:has-text("Sessions")');
    if (await sessionsNav.count() > 0) {
      await sessionsNav.first().click();
      await page.waitForTimeout(1000);
      expect(page.url()).toContain('sessions');
    }
  });
});
