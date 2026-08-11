import { test, expect } from '@playwright/test';
test.use({ storageState: '.auth/user.json' });
import { PerseaApi, setApiKey } from '../../fixtures/api';
import { loginWithApiKey, logout } from '../../fixtures/auth';

const BASE_URL = process.env.BASE_URL || 'http://localhost:8089';
const ADMIN_KEY = process.env.ADMIN_API_KEY || '';

test.describe('User CRUD', () => {
  let api: PerseaApi;

  test.beforeEach(async ({ request }) => {
    api = new PerseaApi(request, ADMIN_KEY);
  });

  test('list users returns array with admin', async () => {
    const users = await api.listUsers();
    expect(Array.isArray(users)).toBeTruthy();
    expect(users.length).toBeGreaterThanOrEqual(1);
  });

  test('create user via API', async () => {
    const testEmail = `test-user-${Date.now()}@example.com`;
    const res = await api.request.post(`${BASE_URL}/api/users`, {
      headers: { Authorization: `Bearer ${ADMIN_KEY}`, 'Content-Type': 'application/json' },
      data: { email: testEmail, name: 'Test User', password: 'TestPass123!', role: 'viewer' },
    });
    expect(res.ok()).toBeTruthy();

    const users = await api.listUsers();
    const created = users.find((u: any) => u.email === testEmail);
    expect(created).toBeTruthy();
    expect(created?.role).toBe('viewer');
  });

  test('change user role via API', async () => {
    const testEmail = `role-test-${Date.now()}@example.com`;
    await api.request.post(`${BASE_URL}/api/users`, {
      headers: { Authorization: `Bearer ${ADMIN_KEY}`, 'Content-Type': 'application/json' },
      data: { email: testEmail, name: 'Role Test', password: 'TestPass123!', role: 'viewer' },
    });

    const res = await api.request.put(`${BASE_URL}/api/users/${encodeURIComponent(testEmail)}/role`, {
      headers: { Authorization: `Bearer ${ADMIN_KEY}`, 'Content-Type': 'application/json' },
      data: { role: 'operator' },
    });
    expect(res.ok()).toBeTruthy();

    const users = await api.listUsers();
    const updated = users.find((u: any) => u.email === testEmail);
    expect(updated?.role).toBe('operator');
  });

  test('disable and enable user via API', async () => {
    const testEmail = `disable-test-${Date.now()}@example.com`;
    await api.request.post(`${BASE_URL}/api/users`, {
      headers: { Authorization: `Bearer ${ADMIN_KEY}`, 'Content-Type': 'application/json' },
      data: { email: testEmail, name: 'Disable Test', password: 'TestPass123!', role: 'viewer' },
    });

    const disableRes = await api.request.post(`${BASE_URL}/api/users/${encodeURIComponent(testEmail)}/disable`, {
      headers: { Authorization: `Bearer ${ADMIN_KEY}`, 'Content-Type': 'application/json' },
    });
    expect(disableRes.ok()).toBeTruthy();

    const enableRes = await api.request.post(`${BASE_URL}/api/users/${encodeURIComponent(testEmail)}/enable`, {
      headers: { Authorization: `Bearer ${ADMIN_KEY}`, 'Content-Type': 'application/json' },
    });
    expect(enableRes.ok()).toBeTruthy();
  });

  test('delete user via API', async () => {
    const testEmail = `delete-test-${Date.now()}@example.com`;
    await api.request.post(`${BASE_URL}/api/users`, {
      headers: { Authorization: `Bearer ${ADMIN_KEY}`, 'Content-Type': 'application/json' },
      data: { email: testEmail, name: 'Delete Test', password: 'TestPass123!', role: 'viewer' },
    });

    const delRes = await api.request.delete(`${BASE_URL}/api/users/${encodeURIComponent(testEmail)}`, {
      headers: { Authorization: `Bearer ${ADMIN_KEY}` },
    });
    expect(delRes.ok()).toBeTruthy();

    const users = await api.listUsers();
    const deleted = users.find((u: any) => u.email === testEmail);
    expect(deleted).toBeUndefined();
  });

  test('viewer role cannot create users (403)', async ({ request }) => {
    const viewerKey = process.env.VIEWER_API_KEY || '';
    if (!viewerKey) {
      test.skip();
      return;
    }
    const res = await request.post(`${BASE_URL}/api/users`, {
      headers: { Authorization: `Bearer ${viewerKey}`, 'Content-Type': 'application/json' },
      data: { email: 'nope@example.com', name: 'No', password: 'TestPass123!', role: 'viewer' },
    });
    expect(res.status()).toBe(403);
  });

  test('user list visible in admin page UI', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/admin.html`);
    await page.waitForTimeout(1000);
    const table = page.locator('#users-table');
    await expect(table).toBeVisible();
    const rows = table.locator('tbody tr');
    const count = await rows.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });
});
