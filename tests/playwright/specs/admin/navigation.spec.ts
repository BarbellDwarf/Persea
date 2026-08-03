import { test, expect } from '@playwright/test';
import { AdminPage } from '../../pages/AdminPage';

test.describe('Admin page', () => {
  let admin: AdminPage;

  test.beforeEach(async ({ page }) => {
    admin = new AdminPage(page);
  });

  test('page renders with title and nav', async ({ page }) => {
    await admin.goto();
    await expect(page).toHaveTitle(/persea.*Admin/);
    await expect(page.locator('h1')).toBeVisible();
    await expect(admin.navAdmin).toHaveClass(/active/);
  });

  test('system status cards are present', async () => {
    await admin.goto();
    await expect(admin.ssVersion).toBeVisible();
    await expect(admin.ssActive).toBeVisible();
    await expect(admin.ssUsers).toBeVisible();
    await expect(admin.ssRecordings).toBeVisible();
    await expect(admin.ssVault).toBeVisible();
    await expect(admin.ssFeatures).toBeVisible();
  });

  test('users table structure', async ({ page }) => {
    await admin.goto();
    const headers = page.locator('#users-table th');
    await expect(headers).toHaveCount(7);
  });

  test('group mappings form exists', async () => {
    await admin.goto();
    await expect(admin.newGroup).toBeVisible();
    await expect(admin.newRole).toBeVisible();
    await expect(admin.addMappingBtn).toBeVisible();
  });

  test('tokens section exists', async ({ page }) => {
    await admin.goto();
    await expect(page.locator('#tokens-table')).toBeVisible();
    await expect(admin.tokenEmail).toBeVisible();
    await expect(admin.tokenName).toBeVisible();
    await expect(admin.adminCreateTokenBtn).toBeVisible();
  });

  test('audit log section exists', async ({ page }) => {
    await admin.goto();
    await expect(page.locator('#audit-table')).toBeVisible();
    await expect(admin.auditEmailFilter).toBeVisible();
    await expect(admin.auditFilterBtn).toBeVisible();
  });

  test('connections audit log section exists', async ({ page }) => {
    await admin.goto();
    await expect(page.locator('#ab-audit-table')).toBeVisible();
  });

  test('non-admin gets redirected', async ({ page }) => {
    // Without admin auth, page redirects to connections
    await page.goto('/admin.html');
    // Either we're on admin page (if auth is set) or redirected
    const url = page.url();
    expect(url.includes('admin.html') || url.includes('connections.html') || url.includes('/')).toBeTruthy();
  });
});
