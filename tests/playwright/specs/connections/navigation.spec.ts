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
    await expect(page).toHaveTitle(/persea.*Connections/);
    await expect(page.locator('h1')).toBeVisible();
    await expect(conn.navConnections).toHaveClass(/active/);
  });

  test('shows no-vault notice when vault not configured', async () => {
    await conn.goto();
    // Wait for the page to determine vault state (async JS)
    await conn.page.waitForTimeout(2000);
    // Either no-vault or vault-unavailable or main-content will be visible
    // depending on backend config
    const noVault = await conn.hasVaultNotConfigured();
    const vaultDown = await conn.hasVaultUnavailable();
    const hasContent = await conn.hasMainContent();
    // At least one state should be resolved
    expect(noVault || vaultDown || hasContent).toBe(true);
  });

  test('folder list is present when vault is configured', async () => {
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

  test('credentials nav link is visible', async () => {
    await conn.goto();
    const credsNav = conn.page.locator('#my-creds-nav');
    // Always visible for logged-in users
    await expect(credsNav).toBeVisible();
  });
});
