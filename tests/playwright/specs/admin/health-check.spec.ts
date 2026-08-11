import { test, expect } from '@playwright/test';
test.use({ storageState: '.auth/user.json' });

const BASE_URL = process.env.BASE_URL || 'http://localhost:8089';
const ADMIN_KEY = process.env.ADMIN_API_KEY || '';

test.describe('Health & System Endpoints', () => {
  test('GET /api/health returns 200', async ({ request }) => {
    const res = await request.get(`${BASE_URL}/api/health`);
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.status).toBeTruthy();
  });

  test('GET /api/system/status returns system info', async ({ request }) => {
    const res = await request.get(`${BASE_URL}/api/system/status`, {
      headers: { Authorization: `Bearer ${ADMIN_KEY}` },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.version).toBeTruthy();
    expect(typeof body.sessions).toBe('object');
    expect(typeof body.users).toBe('object');
  });

  test('GET /api/me returns identity', async ({ request }) => {
    const res = await request.get(`${BASE_URL}/api/me`, {
      headers: { Authorization: `Bearer ${ADMIN_KEY}` },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.role).toBeTruthy();
  });

  test('GET /api/auth/status returns auth config', async ({ request }) => {
    const res = await request.get(`${BASE_URL}/api/auth/status`);
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(typeof body.oidc_enabled).toBe('boolean');
  });

  test('unauthenticated /api/users returns 401', async ({ playwright }) => {
    // Fresh context without the storageState session cookie: the runner's
    // request contexts inherit the test storage state, so an explicit empty
    // storageState is required. Otherwise the admin session cookie passes
    // require_auth and the handler runs (200) instead of the 401.
    const anon = await playwright.request.newContext({
      ignoreHTTPSErrors: true,
      storageState: { cookies: [], origins: [] },
    });
    try {
      const res = await anon.get(`${BASE_URL}/api/users`);
      expect(res.status()).toBe(401);
    } finally {
      await anon.dispose();
    }
  });

  test('invalid API key returns 401', async ({ request }) => {
    const res = await request.get(`${BASE_URL}/api/users`, {
      headers: { Authorization: 'Bearer invalid-key-12345' },
    });
    expect(res.status()).toBe(401);
  });
});
