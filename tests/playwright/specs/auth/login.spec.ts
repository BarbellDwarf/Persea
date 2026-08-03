import { test, expect } from '@playwright/test';
import { loginWithApiKey, logout } from '../../fixtures/auth';

const BASE_URL = process.env.BASE_URL || 'http://localhost:8089';
const ADMIN_KEY = process.env.ADMIN_API_KEY || '';

test.describe('Authentication Flow', () => {
  test('login page renders without auth', async ({ page }) => {
    await logout(page);
    await page.goto(`${BASE_URL}/`);
    await page.waitForTimeout(1000);

    const loginForm = page.locator('#api-key, input[type="password"], .login-card, .login-wrapper');
    const count = await loginForm.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });

  test('authenticated user sees connections page', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/connections.html`);
    await page.waitForTimeout(1000);
    expect(page.url()).toContain('connections');
  });

  test('admin user sees admin nav link', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/connections.html`);
    await page.waitForTimeout(1000);

    const adminNav = page.locator('a[href*="admin"], .nav-item:has-text("Admin")');
    const count = await adminNav.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });

  test('session storage API key persists across navigation', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/connections.html`);
    await page.waitForTimeout(500);

    const storedKey = await page.evaluate(() => sessionStorage.getItem('persea_api_key'));
    expect(storedKey).toBe(ADMIN_KEY);

    await page.goto(`${BASE_URL}/sessions.html`);
    await page.waitForTimeout(500);
    const keyAfterNav = await page.evaluate(() => sessionStorage.getItem('persea_api_key'));
    expect(keyAfterNav).toBe(ADMIN_KEY);
  });
});
