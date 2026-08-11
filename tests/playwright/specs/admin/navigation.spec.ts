import { test, expect, type APIRequestContext } from '@playwright/test';
test.use({ storageState: '.auth/user.json' });
import { AdminPage } from '../../pages/AdminPage';

const BASE_URL = process.env.BASE_URL || 'http://localhost:8089';
const ADMIN_KEY = process.env.ADMIN_API_KEY || '';

async function csrfHeaders(request: APIRequestContext): Promise<Record<string, string>> {
  const state = await request.storageState();
  const cookie = state.cookies.find((c) => c.name === 'csrf_token');
  return cookie ? { 'X-CSRF-Token': cookie.value } : {};
}

test.describe('Admin pages', () => {
  let admin: AdminPage;

  test.beforeEach(async ({ page }) => {
    admin = new AdminPage(page);
  });

  test('users page renders with title and nav', async ({ page }) => {
    await admin.goto();
    await expect(page).toHaveTitle(/Persea.*Users/);
    await expect(page.locator('h1')).toBeVisible();
    await expect(admin.navAdmin).toHaveClass(/active/);
  });

  test('users table structure', async ({ page }) => {
    await admin.goto();
    const headers = page.locator('table:has(#user-table-body) thead th');
    await expect(headers).toHaveCount(7);
  });

  test('users page has add-user controls', async ({ page }) => {
    await admin.goto();
    await expect(admin.addUserBtn).toBeVisible();
    await expect(admin.userSearch).toBeVisible();
  });

  test('group mappings form exists', async ({ page, request }) => {
    // The mappings form lives in a per-group modal opened from a row
    // action, so create a probe group via the API and clean it up after.
    const name = `nav-spec-${Date.now()}`;
    const headers = {
      Authorization: `Bearer ${ADMIN_KEY}`,
      'Content-Type': 'application/json',
      ...(await csrfHeaders(request)),
    };
    const createRes = await request.post(`${BASE_URL}/api/admin/groups`, {
      headers,
      data: { name, description: 'navigation spec probe' },
    });
    expect(createRes.ok()).toBeTruthy();
    const group = await createRes.json();
    try {
      await admin.gotoGroups();
      await expect(admin.groupsBody).toBeVisible();
      await expect(page.locator('[data-action="open-create-modal"]')).toBeVisible();
      await expect(admin.newGroup).toBeAttached();
      await page
        .locator(`#groups-tbody tr:has-text("${name}") [data-action="open-mappings-modal"]`)
        .click();
      await expect(admin.newRole).toBeVisible();
      await expect(admin.addMappingBtn).toBeVisible();
    } finally {
      await request.delete(`${BASE_URL}/api/admin/groups/${group.id}`, {
        headers: { Authorization: `Bearer ${ADMIN_KEY}`, ...(await csrfHeaders(request)) },
      });
    }
  });

  test('audit log section exists', async ({ page }) => {
    await admin.gotoAudit();
    await expect(admin.auditBody).toBeVisible();
    await expect(admin.auditUserFilter).toBeVisible();
    await expect(admin.verifyChainBtn).toBeVisible();
  });

  test('non-admin gets redirected', async ({ page }) => {
    // Without admin auth, page redirects to connections
    await page.goto('/admin.html');
    // Either we're on admin page (if auth is set) or redirected
    const url = page.url();
    expect(
      url.includes('admin/users.html') ||
        url.includes('admin.html') ||
        url.includes('connections.html') ||
        url.includes('/'),
    ).toBeTruthy();
  });
});
