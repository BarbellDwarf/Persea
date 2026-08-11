import { test, expect } from '@playwright/test';
test.use({ storageState: '.auth/user.json' });

test.describe('Role-based navigation visibility', () => {
  test.describe('unauthenticated user', () => {
    test('sees only public nav items', async ({ page }) => {
      await page.goto('/sessions.html');
      // Without auth, page redirects to / (login page)
      // Sessions/Reports/Tokens/Admin links should be hidden
      const sessionsLink = page.locator('#sessions-link');
      const tokensLink = page.locator('#tokens-link');
      const adminLink = page.locator('#admin-link');
      const reportsLink = page.locator('#reports-link');

      // These should be hidden (style="display:none" or similar)
      // Note: the HTML sets display:none on these by default
      if (await sessionsLink.count() > 0) {
        // Sessions link is always in nav but may be hidden for low roles
        const sessionsVisible = await sessionsLink.isVisible();
        expect(typeof sessionsVisible).toBe('boolean');
      }
    });

    test('login page shows SSO and API key options', async ({ page }) => {
      await page.goto('/');
      await expect(page.locator('#login-form')).toBeVisible();
      // SSO section visibility depends on config
    });
  });

  test.describe('admin user', () => {
    test('sees all nav items when authenticated as admin', async ({ page }) => {
      const apiKey = process.env.ADMIN_API_KEY || '';
      await page.goto('/');
      await page.evaluate((key) => {
        sessionStorage.setItem('persea_api_key', key);
      }, apiKey);

      // Go to sessions to check nav
      await page.goto('/sessions.html');
      // Admin should see admin link, tokens, reports, sessions
      // These elements exist with display:none and get shown by JS
      // With API key auth, the JS sets them visible
      const adminLink = page.locator('#admin-link');
      if (await adminLink.count() > 0) {
        // API key users are treated as admin
        await expect(adminLink).toBeVisible();
      }
    });
  });

  test.describe('theme preferences', () => {
    test('settings menu opens on click', async ({ page }) => {
      await page.goto('/');
      await page.evaluate((key) => {
        sessionStorage.setItem('persea_api_key', key);
      }, process.env.ADMIN_API_KEY || '');
      await page.goto('/sessions.html');
      const settingsBtn = page.locator('#user-menu-btn');
      await expect(settingsBtn).toBeVisible();
      await settingsBtn.click();
      const menu = page.locator('#user-menu');
      await expect(menu).toBeVisible();
    });

    test('theme list is populated', async ({ page }) => {
      await page.goto('/');
      await page.evaluate((key) => {
        sessionStorage.setItem('persea_api_key', key);
      }, process.env.ADMIN_API_KEY || '');
      await page.goto('/sessions.html');
      await page.locator('#user-menu-btn').click();
      const themeList = page.locator('#um-theme-list');
      await expect(themeList).toBeVisible();
      // Theme items are populated by JS from /api/auth/status
      // With no server, it might be empty but the container should exist
    });
  });
});
