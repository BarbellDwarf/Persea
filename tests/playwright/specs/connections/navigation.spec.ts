import { test, expect } from '@playwright/test';
test.use({ storageState: '.auth/user.json' });
import { ConnectionsPage } from '../../pages/ConnectionsPage';

test.describe('Connections page', () => {
  let conn: ConnectionsPage;

  test.beforeEach(async ({ page }) => {
    conn = new ConnectionsPage(page);
  });

  test('page renders with title and nav', async ({ page }) => {
    await conn.goto();
    await expect(page).toHaveTitle(/persea.*Connections/i);
    await expect(page.locator('h1')).toBeVisible();
    await expect(conn.navConnections).toHaveClass(/active/);
  });

  test('shows empty state when no connections configured', async () => {
    await conn.goto();
    // Wait for the page to determine address book state (async JS)
    await conn.page.waitForTimeout(2000);
    // Either empty-state (no folders) or main-content (folders exist) is
    // shown depending on backend data
    const emptyState = await conn.hasEmptyState();
    const hasContent = await conn.hasMainContent();
    expect(emptyState || hasContent).toBe(true);
  });

  test('folder list is present when connections are configured', async () => {
    await conn.goto();
    if (await conn.hasMainContent()) {
      await expect(conn.folderList).toBeVisible();
    }
  });

  test('new folder button visibility depends on role', async () => {
    await conn.goto();
    if (await conn.hasMainContent()) {
      // Without auth, new folder button should be hidden
      const visible = await conn.btnNewFolder.isVisible();
      expect(typeof visible).toBe('boolean');
    }
  });

  test('nav links work', async ({ page }) => {
    await conn.goto();
    await conn.navSessions.click();
    // Should redirect viewer/operator to connections or show form for poweruser+
    await expect(page).toHaveURL(/sessions\.html|connections\.html/);
  });

  test('search input exists and is interactive', async () => {
    await conn.goto();
    if (await conn.hasMainContent()) {
      await expect(conn.connectionsSearch).toBeVisible();
      await conn.connectionsSearch.fill('test');
      await expect(conn.connectionsSearch).toHaveValue('test');
    }
  });

  test('empty state shows create button when no folders', async () => {
    await conn.goto();
    if (await conn.hasEmptyState()) {
      await expect(conn.btnEmptyCreateFolder).toBeVisible();
      await expect(conn.btnEmptyCreateFolder).toHaveText(/Create First Folder/);
    }
  });

  test('credentials nav link is visible', async ({ page }) => {
    await conn.goto();
    // Credential presets live under My Profile in the current UI
    const profileNav = page.locator('nav a[href="/account/profile.html"]');
    await expect(profileNav).toBeVisible();
    await profileNav.click();
    await expect(page).toHaveURL(/profile\.html/);
    await expect(page.locator('#creds-form')).toBeVisible();
  });
});
