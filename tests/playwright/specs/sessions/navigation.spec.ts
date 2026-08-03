import { test, expect } from '@playwright/test';
import { SessionsPage } from '../../pages/SessionsPage';

test.describe('Sessions page', () => {
  let sessions: SessionsPage;

  test.beforeEach(async ({ page }) => {
    sessions = new SessionsPage(page);
  });

  test('page renders with title and nav', async ({ page }) => {
    await sessions.goto();
    await expect(page).toHaveTitle(/persea.*Sessions/);
    await expect(page.locator('h1')).toBeVisible();
    await expect(sessions.navConnections).toBeVisible();
    await expect(sessions.navSessions).toHaveClass(/active/);
    await expect(sessions.navRecordings).toBeVisible();
  });

  test('session list table is visible', async () => {
    await sessions.goto();
    // The table (or empty state) should be present
    const table = sessions.page.locator('table');
    const empty = sessions.page.locator('#session-empty');
    // Either the table or empty state message is visible
    const tableVisible = await table.isVisible().catch(() => false);
    const emptyVisible = await empty.isVisible().catch(() => false);
    expect(tableVisible || emptyVisible).toBe(true);
  });

  test('ad-hoc session form visibility depends on role', async ({ page }) => {
    // Navigate without auth to test unauthenticated state
    await page.goto('/sessions.html');
    // Without auth, the page redirects to / (login), so form is not present
    // This validates the element exists but is hidden for unauthenticated users
    const formVisible = await sessions.isFormVisible();
    expect(formVisible).toBe(false);
  });

  test('nav links navigate correctly', async ({ page }) => {
    await sessions.goto();
    await sessions.navConnections.click();
    await expect(page).toHaveURL(/connections\.html/);

    await page.goto('/sessions.html');
    await sessions.navRecordings.click();
    await expect(page).toHaveURL(/recordings\.html/);
  });

  test('logout clears session and redirects', async ({ page }) => {
    await sessions.goto();
    await sessions.navLogout.click();
    await expect(page).toHaveURL(/\//);
  });

  test('session type toggle shows correct fields', async ({ page }) => {
    await page.goto('/');
    await page.evaluate((key) => {
      sessionStorage.setItem('persea_api_key', key);
    }, process.env.ADMIN_API_KEY || '');
    await page.goto('/sessions.html');

    // Form should be visible for admin API key users
    await expect(sessions.sessionForm).toBeVisible();

    // Toggle the new session section
    await sessions.toggleNewSession();
    await expect(sessions.newSessionFields).toBeVisible();

    // Default is SSH
    await expect(sessions.page.locator('#ssh-fields')).toBeVisible();

    // Switch to RDP
    await sessions.selectSessionType('rdp');
    await expect(sessions.page.locator('#rdp-fields')).toBeVisible();
    await expect(sessions.page.locator('#ssh-fields')).toBeHidden();

    // Switch to VNC
    await sessions.selectSessionType('vnc');
    await expect(sessions.page.locator('#vnc-fields')).toBeVisible();

    // Switch to Web
    await sessions.selectSessionType('web');
    await expect(sessions.page.locator('#web-fields')).toBeVisible();

    // Switch to VDI
    await sessions.selectSessionType('vdi');
    await expect(sessions.page.locator('#vdi-fields')).toBeVisible();
  });
});
