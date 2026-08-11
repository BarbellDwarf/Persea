import { test, expect } from '@playwright/test';
test.use({ storageState: '.auth/user.json' });
import { SessionsPage } from '../../pages/SessionsPage';

test.describe('Sessions page', () => {
  let sessions: SessionsPage;

  test.beforeEach(async ({ page }) => {
    sessions = new SessionsPage(page);
  });

  test('page renders with title and nav', async ({ page }) => {
    await sessions.goto();
    await expect(page).toHaveTitle(/persea.*Sessions/i);
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
    await sessions.goto();
    // Admin/poweruser: the "+ New Session" button appears once the role
    // check resolves, and opens the (initially hidden) form.
    await expect(sessions.newSessionBtn).toBeVisible();
    await sessions.openNewSession();
    await expect(sessions.newSessionFields).toBeVisible();

    // Without auth, /sessions.html redirects to the login page and the
    // form is never shown.
    await page.evaluate(() => sessionStorage.clear());
    await page.context().clearCookies();
    await page.reload();
    await expect(page).toHaveURL(/\?error=login_required/);
    await expect(sessions.sessionForm).toBeHidden();
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
    // Log in via the login form so this test holds its own DB-backed session.
    // Logout deletes that session row from the DB — doing it with the shared
    // storageState cookie would invalidate every other test's session mid-run.
    await page.goto('/');
    await page.evaluate(() => sessionStorage.clear());
    await page.context().clearCookies();
    await page.reload();
    await page.fill('#username', process.env.LOGIN_USERNAME || 'admin@local.test');
    await page.fill('#password', process.env.LOGIN_PASSWORD || 'AdminPass123!');
    await page.click('#login-submit');
    await page.waitForURL(/connections\.html|sessions\.html/, { timeout: 10_000 });
    await page.goto('/sessions.html');

    await sessions.navLogout.click();
    await expect(page).toHaveURL(/\//);
  });

  test('session type toggle shows correct fields', async ({ page }) => {
    await sessions.goto();

    // The form starts hidden; open it via the "+ New Session" button
    await expect(sessions.newSessionBtn).toBeVisible();
    await sessions.openNewSession();
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
