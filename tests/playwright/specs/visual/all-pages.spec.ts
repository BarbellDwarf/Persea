import { test, expect } from '@playwright/test';
test.use({ storageState: '.auth/user.json' });
import { loginWithApiKey, logout } from '../../fixtures/auth';

const BASE_URL = process.env.BASE_URL || 'http://localhost:8089';
const ADMIN_KEY = process.env.ADMIN_API_KEY || '';

test.describe('Visual Regression - All Pages', () => {
  test('login page screenshot', async ({ page }) => {
    await logout(page);
    await page.goto(`${BASE_URL}/`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('login-page.png', { fullPage: true });
  });

  test('connections page screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/connections.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('connections-page.png', { fullPage: true });
  });

  test('sessions page screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/sessions.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('sessions-page.png', { fullPage: true });
  });

  test('recordings page screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/recordings.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('recordings-page.png', { fullPage: true });
  });

  test('admin page screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/admin.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('admin-page.png', { fullPage: true });
  });

  test('admin settings screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/admin/settings.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('admin-settings.png', { fullPage: true });
  });

  test('admin users screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/admin/users.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('admin-users.png', { fullPage: true });
  });

  test('admin auth screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/admin/auth.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('admin-auth.png', { fullPage: true });
  });

  test('admin audit screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/admin/audit.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('admin-audit.png', { fullPage: true });
  });

  test('admin reports screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/admin/reports.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('admin-reports.png', { fullPage: true });
  });

  test('admin tunnels screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/admin/tunnels.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('admin-tunnels.png', { fullPage: true });
  });

  test('account profile screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/account/profile.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('account-profile.png', { fullPage: true });
  });

  test('account tokens screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/account/tokens.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('account-tokens.png', { fullPage: true });
  });

  test('account totp screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/account/totp.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('account-totp.png', { fullPage: true });
  });

  test('docs page screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/docs.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('docs-page.png', { fullPage: true });
  });

  test('client page screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/client.html?session_id=test`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('client-page.png', { fullPage: true });
  });
});
