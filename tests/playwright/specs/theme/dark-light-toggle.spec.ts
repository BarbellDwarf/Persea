import { test, expect } from '@playwright/test';
import { loginWithApiKey } from '../../fixtures/auth';

const BASE_URL = process.env.BASE_URL || 'http://localhost:9091';
const ADMIN_KEY = process.env.ADMIN_API_KEY || '';

test.describe('Theme Toggle', () => {
  test('dark mode is default', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/connections.html`);
    await page.waitForTimeout(1000);
    const isDark = await page.evaluate(() => document.documentElement.classList.contains('dark'));
    expect(isDark).toBe(true);
  });

  test('clicking toggle switches to light mode', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/connections.html`);
    await page.waitForTimeout(1000);

    await page.click('#theme-toggle');
    await page.waitForTimeout(500);

    const isLight = await page.evaluate(() => document.documentElement.classList.contains('light'));
    expect(isLight).toBe(true);

    const isDark = await page.evaluate(() => document.documentElement.classList.contains('dark'));
    expect(isDark).toBe(false);
  });

  test('clicking toggle again switches back to dark', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/connections.html`);
    await page.waitForTimeout(1000);

    // Switch to light
    await page.click('#theme-toggle');
    await page.waitForTimeout(500);
    let isLight = await page.evaluate(() => document.documentElement.classList.contains('light'));
    expect(isLight).toBe(true);

    // Switch back to dark
    await page.click('#theme-toggle');
    await page.waitForTimeout(500);
    let isDark = await page.evaluate(() => document.documentElement.classList.contains('dark'));
    expect(isDark).toBe(true);
  });

  test('theme persists in localStorage', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/connections.html`);
    await page.waitForTimeout(1000);

    // Switch to light
    await page.click('#theme-toggle');
    await page.waitForTimeout(500);

    const theme = await page.evaluate(() => localStorage.getItem('theme'));
    expect(theme).toBe('light');

    // Reload and verify it persists
    await page.reload();
    await page.waitForTimeout(1000);
    const isLight = await page.evaluate(() => document.documentElement.classList.contains('light'));
    expect(isLight).toBe(true);
  });

  test('dark mode background is dark', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/connections.html`);
    await page.waitForTimeout(1000);

    const bgColor = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    // Dark mode background should be dark (low RGB values)
    const match = bgColor.match(/rgb\((\d+),\s*(\d+),\s*(\d+)\)/);
    expect(match).toBeTruthy();
    const [, r, g, b] = match!.map(Number);
    expect(r).toBeLessThan(50);
    expect(g).toBeLessThan(50);
    expect(b).toBeLessThan(50);
  });

  test('light mode background is light', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/connections.html`);
    await page.waitForTimeout(1000);

    // Switch to light
    await page.click('#theme-toggle');
    await page.waitForTimeout(500);

    const bgColor = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    // Light mode background should be light (high RGB values)
    const match = bgColor.match(/rgb\((\d+),\s*(\d+),\s*(\d+)\)/);
    expect(match).toBeTruthy();
    const [, r, g, b] = match!.map(Number);
    expect(r).toBeGreaterThan(200);
    expect(g).toBeGreaterThan(200);
    expect(b).toBeGreaterThan(200);
  });

  test('theme toggle button is visible', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/connections.html`);
    await page.waitForTimeout(1000);

    const btn = page.locator('#theme-toggle');
    await expect(btn).toBeVisible();
  });

  test('theme toggle works on admin page', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/admin/users.html`);
    await page.waitForTimeout(1000);

    const isDark = await page.evaluate(() => document.documentElement.classList.contains('dark'));
    expect(isDark).toBe(true);

    await page.click('#theme-toggle');
    await page.waitForTimeout(500);

    const isLight = await page.evaluate(() => document.documentElement.classList.contains('light'));
    expect(isLight).toBe(true);
  });

  test('theme toggle works on profile page', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/account/profile.html`);
    await page.waitForTimeout(1000);

    await page.click('#theme-toggle');
    await page.waitForTimeout(500);

    const isLight = await page.evaluate(() => document.documentElement.classList.contains('light'));
    expect(isLight).toBe(true);
  });

  test('visual: dark mode screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/connections.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('theme-dark.png');
  });

  test('visual: light mode screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/connections.html`);
    await page.waitForTimeout(1000);
    await page.click('#theme-toggle');
    await page.waitForTimeout(1000);
    await expect(page).toHaveScreenshot('theme-light.png');
  });
});
