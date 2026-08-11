import { test, expect, type APIRequestContext } from '@playwright/test';
test.use({ storageState: '.auth/user.json' });

const BASE_URL = process.env.BASE_URL || 'http://localhost:8089';
const ADMIN_KEY = process.env.ADMIN_API_KEY || '';

// State-changing API calls require the CSRF double-submit token (X-CSRF-Token
// header matching the csrf_token cookie). The `request` fixture carries the
// storageState cookies, so the value is read from there.
async function csrfHeaders(request: APIRequestContext): Promise<Record<string, string>> {
  const state = await request.storageState();
  const cookie = state.cookies.find((c) => c.name === 'csrf_token');
  return cookie ? { 'X-CSRF-Token': cookie.value } : {};
}

async function adminUserEmail(request: APIRequestContext): Promise<string> {
  const res = await request.get(`${BASE_URL}/api/users`, {
    headers: { Authorization: `Bearer ${ADMIN_KEY}` },
  });
  const users = await res.json();
  const adminUser = users.find((u: { role: string; email: string }) => u.role === 'admin');
  expect(adminUser).toBeTruthy();
  return adminUser!.email;
}

test.describe('Token CRUD', () => {
  test('create token via API', async ({ request }) => {
    const tokenName = `test-token-${Date.now()}`;
    const res = await request.post(`${BASE_URL}/api/admin/user-tokens`, {
      headers: {
        Authorization: `Bearer ${ADMIN_KEY}`,
        'Content-Type': 'application/json',
        ...(await csrfHeaders(request)),
      },
      data: { email: await adminUserEmail(request), name: tokenName, max_role: 'admin' },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.token).toBeTruthy();
    expect(body.token.length).toBeGreaterThan(10);
    expect(body.id).toBeTruthy();
  });

  test('list tokens via API', async ({ request }) => {
    const res = await request.get(`${BASE_URL}/api/admin/user-tokens`, {
      headers: { Authorization: `Bearer ${ADMIN_KEY}` },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(Array.isArray(body.tokens || body)).toBeTruthy();
  });

  test('created token authenticates', async ({ request }) => {
    const tokenName = `auth-test-${Date.now()}`;
    const createRes = await request.post(`${BASE_URL}/api/admin/user-tokens`, {
      headers: {
        Authorization: `Bearer ${ADMIN_KEY}`,
        'Content-Type': 'application/json',
        ...(await csrfHeaders(request)),
      },
      data: { email: await adminUserEmail(request), name: tokenName, max_role: 'admin' },
    });
    const { token } = await createRes.json();

    const meRes = await request.get(`${BASE_URL}/api/me`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(meRes.ok()).toBeTruthy();
    const me = await meRes.json();
    expect(me.role).toBe('admin');
  });

  test('revoke token via API', async ({ request }) => {
    const tokenName = `revoke-test-${Date.now()}`;
    const createRes = await request.post(`${BASE_URL}/api/admin/user-tokens`, {
      headers: {
        Authorization: `Bearer ${ADMIN_KEY}`,
        'Content-Type': 'application/json',
        ...(await csrfHeaders(request)),
      },
      data: { email: await adminUserEmail(request), name: tokenName, max_role: 'admin' },
    });
    const body = await createRes.json();
    expect(body.id).toBeTruthy();

    const delRes = await request.delete(`${BASE_URL}/api/admin/user-tokens/${body.id}`, {
      headers: { Authorization: `Bearer ${ADMIN_KEY}`, ...(await csrfHeaders(request)) },
    });
    expect(delRes.ok()).toBeTruthy();
  });

  test('created token visible in API Keys page UI', async ({ page, request }) => {
    // Tokens UI moved out of the admin page to the account API Keys page.
    const tokenName = `ui-test-${Date.now()}`;
    const createRes = await request.post(`${BASE_URL}/api/admin/user-tokens`, {
      headers: {
        Authorization: `Bearer ${ADMIN_KEY}`,
        'Content-Type': 'application/json',
        ...(await csrfHeaders(request)),
      },
      data: { email: await adminUserEmail(request), name: tokenName, max_role: 'admin' },
    });
    expect(createRes.ok()).toBeTruthy();

    // No API key in sessionStorage — the page authenticates via the
    // storageState session cookie so /api/me/tokens lists the user's tokens.
    await page.goto(`${BASE_URL}/account/tokens.html`);
    const tokenRow = page.locator(`#tokens-tbody tr:has-text("${tokenName}")`);
    await expect(tokenRow).toBeVisible();
  });
});
