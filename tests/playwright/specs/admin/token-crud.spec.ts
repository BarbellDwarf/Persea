import { test, expect } from '@playwright/test';
import { PerseaApi, setApiKey } from '../../fixtures/api';
import { loginWithApiKey } from '../../fixtures/auth';

const BASE_URL = process.env.BASE_URL || 'http://localhost:8089';
const ADMIN_KEY = process.env.ADMIN_API_KEY || '';

test.describe('Token CRUD', () => {
  let api: PerseaApi;

  test.beforeEach(async ({ request }) => {
    api = new PerseaApi(request, ADMIN_KEY);
  });

  test('create token via API', async () => {
    const tokenName = `test-token-${Date.now()}`;
    const res = await api.request.post(`${BASE_URL}/api/admin/user-tokens`, {
      headers: { Authorization: `Bearer ${ADMIN_KEY}`, 'Content-Type': 'application/json' },
      data: { user_email: 'admin@setup-test.com', name: tokenName, role: 'admin' },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.token).toBeTruthy();
    expect(body.token.length).toBeGreaterThan(10);
  });

  test('list tokens via API', async () => {
    const res = await api.request.get(`${BASE_URL}/api/admin/user-tokens`, {
      headers: { Authorization: `Bearer ${ADMIN_KEY}` },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(Array.isArray(body.tokens || body)).toBeTruthy();
  });

  test('created token authenticates', async ({ request }) => {
    const tokenName = `auth-test-${Date.now()}`;
    const createRes = await api.request.post(`${BASE_URL}/api/admin/user-tokens`, {
      headers: { Authorization: `Bearer ${ADMIN_KEY}`, 'Content-Type': 'application/json' },
      data: { user_email: 'admin@setup-test.com', name: tokenName, role: 'admin' },
    });
    const { token } = await createRes.json();

    const meRes = await api.request.get(`${BASE_URL}/api/me`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(meRes.ok()).toBeTruthy();
    const me = await meRes.json();
    expect(me.role).toBe('admin');
  });

  test('revoke token via API', async () => {
    const tokenName = `revoke-test-${Date.now()}`;
    const createRes = await api.request.post(`${BASE_URL}/api/admin/user-tokens`, {
      headers: { Authorization: `Bearer ${ADMIN_KEY}`, 'Content-Type': 'application/json' },
      data: { user_email: 'admin@setup-test.com', name: tokenName, role: 'admin' },
    });
    const body = await createRes.json();
    const tokenId = body.id;

    if (tokenId) {
      const delRes = await api.request.delete(`${BASE_URL}/api/admin/user-tokens/${tokenId}`, {
        headers: { Authorization: `Bearer ${ADMIN_KEY}` },
      });
      expect(delRes.ok()).toBeTruthy();
    }
  });

  test('token section visible in admin page UI', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`${BASE_URL}/admin.html`);
    await page.waitForTimeout(1000);
    const tokensTable = page.locator('#tokens-table');
    await expect(tokensTable).toBeVisible();
  });
});
