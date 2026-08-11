import { test, expect } from '@playwright/test';
test.use({ storageState: '.auth/user.json' });

async function authenticate(page: import('@playwright/test').Page) {
  await page.goto('/');
  await page.evaluate((key) => {
    sessionStorage.setItem('persea_api_key', key);
  }, process.env.ADMIN_API_KEY || '');
}

test.describe('Visual regression screenshots', () => {
  test('login page screenshot', async ({ page }) => {
    await page.goto('/');
    await page.waitForTimeout(1000);
    await expect(page).toHaveScreenshot('login-page.png', {
      fullPage: true,
      maxDiffPixels: 200,
    });
  });

  const authenticatedPages = [
    { name: 'sessions', url: '/sessions.html' },
    { name: 'connections', url: '/connections.html' },
    { name: 'recordings', url: '/recordings.html' },
    { name: 'admin', url: '/admin.html' },
    { name: 'tokens', url: '/tokens.html' },
  ];

  for (const { name, url } of authenticatedPages) {
    test(`${name} page screenshot`, async ({ page }) => {
      await authenticate(page);
      await page.goto(url);
      await page.waitForTimeout(1000);
      await expect(page).toHaveScreenshot(`${name}-page.png`, {
        fullPage: true,
        maxDiffPixels: 200,
      });
    });
  }

  test('sessions page with form expanded', async ({ page }) => {
    await authenticate(page);
    await page.goto('/sessions.html');
    // Expand the form
    const toggle = page.locator('#new-session-toggle');
    if (await toggle.isVisible()) {
      await toggle.click();
    }
    await page.waitForTimeout(500);
    await expect(page).toHaveScreenshot('sessions-form-expanded.png', {
      fullPage: true,
      maxDiffPixels: 200,
    });
  });

  test('connections page with vault state', async ({ page }) => {
    await authenticate(page);
    await page.goto('/connections.html');
    await page.waitForTimeout(1000);
    await expect(page).toHaveScreenshot('connections-vault-state.png', {
      fullPage: true,
      maxDiffPixels: 200,
    });
  });

  test('admin page system status', async ({ page }) => {
    await authenticate(page);
    await page.goto('/admin.html');
    await page.waitForTimeout(1000);
    await expect(page).toHaveScreenshot('admin-status.png', {
      fullPage: true,
      maxDiffPixels: 200,
    });
  });

  test('mobile sessions page', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await authenticate(page);
    await page.goto('/sessions.html');
    await page.waitForTimeout(500);
    await expect(page).toHaveScreenshot('sessions-mobile.png', {
      fullPage: true,
      maxDiffPixels: 200,
    });
  });

  test('mobile connections page', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await authenticate(page);
    await page.goto('/connections.html');
    await page.waitForTimeout(500);
    await expect(page).toHaveScreenshot('connections-mobile.png', {
      fullPage: true,
      maxDiffPixels: 200,
    });
  });
});
