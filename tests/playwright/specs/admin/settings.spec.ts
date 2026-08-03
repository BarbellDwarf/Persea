import { test, expect } from '@playwright/test';
import { loginWithApiKey } from '../../fixtures/auth';

const BASE_URL = process.env.BASE_URL || 'http://localhost:8089';
const ADMIN_KEY = process.env.ADMIN_API_KEY || '';

test.describe('Settings Page', () => {
  test('settings page renders with form fields', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/admin/settings.html`);
    await page.waitForTimeout(1000);

    const listenAddr = page.locator('input[name="listen_addr"]');
    await expect(listenAddr).toBeVisible();
    const value = await listenAddr.inputValue();
    expect(value.length).toBeGreaterThan(0);

    const guacdAddr = page.locator('input[name="guacd_addr"]');
    await expect(guacdAddr).toBeVisible();
  });

  test('settings form has save button', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/admin/settings.html`);
    await page.waitForTimeout(1000);

    const saveBtn = page.locator('button[type="submit"], button:has-text("Save"), .btn-primary');
    await expect(saveBtn.first()).toBeVisible();
  });

  test('settings page has session config fields', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/admin/settings.html`);
    await page.waitForTimeout(1000);

    const maxDuration = page.locator('input[name="session_max_duration_secs"]');
    await expect(maxDuration).toBeVisible();

    const idleTimeout = page.locator('input[name="session_idle_timeout_secs"]');
    await expect(idleTimeout).toBeVisible();
  });

  test('TLS config fields present', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/admin/settings.html`);
    await page.waitForTimeout(1000);

    const tlsCert = page.locator('input[name="tls_cert_path"]');
    await expect(tlsCert).toBeVisible();

    const tlsKey = page.locator('input[name="tls_key_path"]');
    await expect(tlsKey).toBeVisible();
  });
});
