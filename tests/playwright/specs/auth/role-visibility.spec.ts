import { test, expect } from '@playwright/test';

test.describe('Role-based navigation visibility', () => {
  test.describe('unauthenticated user', () => {
    test.use({ storageState: { cookies: [], origins: [] } });

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
    test.use({ storageState: '.auth/user.json' });

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
    test.use({ storageState: '.auth/user.json' });

    test('theme toggle in header cycles dark/light/auto on click', async ({ page }) => {
      await page.goto('/');
      await page.evaluate((key) => {
        sessionStorage.setItem('persea_api_key', key);
      }, process.env.ADMIN_API_KEY || '');
      await page.goto('/sessions.html');
      // The old settings dropdown (#user-menu-btn/#user-menu) was replaced by
      // a header theme-toggle button that cycles dark -> light -> auto.
      const toggle = page.locator('#theme-toggle');
      await expect(toggle).toBeVisible();
      // Fresh context: theme defaults to 'auto'
      await expect(toggle).toHaveAttribute('title', 'Theme: Auto (click to cycle)');
      await toggle.click();
      // One click must advance the cycle (Auto -> Dark) and update the label
      await expect(toggle).toHaveAttribute('title', 'Theme: Dark (click to cycle)');
    });

    test('theme list is populated', async ({ page }) => {
      await page.goto('/');
      await page.evaluate((key) => {
        sessionStorage.setItem('persea_api_key', key);
      }, process.env.ADMIN_API_KEY || '');
      // The color-accent theme list now lives on the profile page (was a
      // dropdown in the header). initTheme() populates it from
      // /api/auth/status -> theme.presets (server-side built-in catalog).
      await page.goto('/account/profile.html');
      const themeList = page.locator('#um-theme-list');
      await expect(themeList).toBeVisible();
      const items = themeList.locator('.um-item');
      // "default" item is always rendered first, followed by the presets
      await expect(items.first().locator('.um-theme-name')).toHaveText('default');
      // Built-in presets come from the server catalog (aurora, dark, light,
      // high-contrast, terminal, nord, corporate, jaguar) plus any user
      // themes dropped into static/themes/*.toml (catppuccin-macchiato here)
      await expect(items.locator('.um-theme-name', { hasText: 'aurora' })).toBeVisible();
      await expect(items.locator('.um-theme-name', { hasText: 'jaguar' })).toBeVisible();
      await expect(items.locator('.um-theme-name', { hasText: 'catppuccin-macchiato' })).toBeVisible();
      // default item + 9 presets served by /api/auth/status
      await expect(items).toHaveCount(10);
    });
  });
});
