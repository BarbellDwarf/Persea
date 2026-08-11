import { test, expect } from '@playwright/test';
test.use({ storageState: '.auth/user.json' });
import { loginWithApiKey } from '../../fixtures/auth';

const BASE_URL = process.env.BASE_URL || 'https://localhost:8089';
const ADMIN_KEY = process.env.ADMIN_API_KEY || '';

async function gotoAuthenticated(page: import('@playwright/test').Page, path: string) {
  await loginWithApiKey(page, ADMIN_KEY);
  await page.goto(`${BASE_URL}${path}`);
  await page.waitForTimeout(1000);
}

// The theme toggle cycles Auto → Dark → Light → Auto. The default is
// "auto", which resolves to the light/dark CSS class from the OS
// prefers-color-scheme (light under Playwright's default color scheme).
// Preset themes are chosen separately via the user-menu theme picker
// (localStorage 'persea_theme'); the toggle preference lives in
// localStorage 'theme'.
test.describe('Theme Toggle', () => {
  test('default theme is auto (resolves via OS color scheme)', async ({ page }) => {
    await gotoAuthenticated(page, '/connections.html');
    const stored = await page.evaluate(() => localStorage.getItem('theme'));
    expect(stored).toBeNull();
    const cls = await page.evaluate(() => document.documentElement.className);
    const wantsDark = await page.evaluate(() => matchMedia('(prefers-color-scheme: dark)').matches);
    expect(cls).toBe(wantsDark ? 'dark' : 'light');
  });

  test('clicking toggle switches to dark mode', async ({ page }) => {
    await gotoAuthenticated(page, '/connections.html');
    await page.click('#theme-toggle');
    await page.waitForTimeout(300);
    expect(await page.evaluate(() => document.documentElement.classList.contains('dark'))).toBe(true);
    expect(await page.evaluate(() => document.documentElement.classList.contains('light'))).toBe(false);
    expect(await page.evaluate(() => localStorage.getItem('theme'))).toBe('dark');
  });

  test('clicking toggle again switches to light mode', async ({ page }) => {
    await gotoAuthenticated(page, '/connections.html');
    await page.click('#theme-toggle'); // auto → dark
    await page.click('#theme-toggle'); // dark → light
    await page.waitForTimeout(300);
    expect(await page.evaluate(() => document.documentElement.classList.contains('light'))).toBe(true);
    expect(await page.evaluate(() => document.documentElement.classList.contains('dark'))).toBe(false);
  });

  test('clicking toggle cycles back to auto', async ({ page }) => {
    await gotoAuthenticated(page, '/connections.html');
    await page.click('#theme-toggle'); // auto → dark
    await page.click('#theme-toggle'); // dark → light
    await page.click('#theme-toggle'); // light → auto
    await page.waitForTimeout(300);
    expect(await page.evaluate(() => localStorage.getItem('theme'))).toBe('auto');
    const wantsDark = await page.evaluate(() => matchMedia('(prefers-color-scheme: dark)').matches);
    expect(await page.evaluate((dark) => document.documentElement.classList.contains(dark ? 'dark' : 'light'), wantsDark)).toBe(true);
  });

  test('theme persists in localStorage', async ({ page }) => {
    await gotoAuthenticated(page, '/connections.html');
    await page.click('#theme-toggle'); // auto → dark
    await page.click('#theme-toggle'); // dark → light
    await page.waitForTimeout(300);

    const theme = await page.evaluate(() => localStorage.getItem('theme'));
    expect(theme).toBe('light');

    // Reload and verify it persists
    await page.reload();
    await page.waitForTimeout(1000);
    expect(await page.evaluate(() => document.documentElement.classList.contains('light'))).toBe(true);
  });

  test('dark mode background is dark', async ({ page }) => {
    await gotoAuthenticated(page, '/connections.html');
    await page.click('#theme-toggle'); // auto → dark
    await page.waitForTimeout(300);

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
    await gotoAuthenticated(page, '/connections.html');
    await page.click('#theme-toggle'); // auto → dark
    await page.click('#theme-toggle'); // dark → light
    await page.waitForTimeout(300);

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
    await gotoAuthenticated(page, '/connections.html');
    const btn = page.locator('#theme-toggle');
    await expect(btn).toBeVisible();
  });

  test('theme toggle works on admin page', async ({ page }) => {
    await gotoAuthenticated(page, '/admin/users.html');

    const isDark = await page.evaluate(() => document.documentElement.classList.contains('dark'));
    expect(isDark).toBe(false);

    await page.click('#theme-toggle'); // auto → dark
    await page.waitForTimeout(300);
    expect(await page.evaluate(() => document.documentElement.classList.contains('dark'))).toBe(true);

    await page.click('#theme-toggle'); // dark → light
    await page.waitForTimeout(300);
    expect(await page.evaluate(() => document.documentElement.classList.contains('light'))).toBe(true);
  });

  test('theme toggle works on profile page', async ({ page }) => {
    await gotoAuthenticated(page, '/account/profile.html');

    await page.click('#theme-toggle'); // auto → dark
    await page.waitForTimeout(300);
    expect(await page.evaluate(() => document.documentElement.classList.contains('dark'))).toBe(true);

    await page.click('#theme-toggle'); // dark → light
    await page.waitForTimeout(300);
    expect(await page.evaluate(() => document.documentElement.classList.contains('light'))).toBe(true);
  });

  test('visual: dark mode screenshot', async ({ page }) => {
    await gotoAuthenticated(page, '/connections.html');
    await page.click('#theme-toggle'); // auto → dark
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('theme-dark.png');
  });

  test('visual: light mode screenshot', async ({ page }) => {
    await gotoAuthenticated(page, '/connections.html');
    await page.click('#theme-toggle'); // auto → dark
    await page.click('#theme-toggle'); // dark → light
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('theme-light.png');
  });
});
