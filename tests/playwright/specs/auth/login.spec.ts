import { test, expect } from '@playwright/test';

const BASE_URL = process.env.BASE_URL || 'http://localhost:8089';
const USERNAME = process.env.LOGIN_USERNAME || 'admin@local.test';
const PASSWORD = process.env.LOGIN_PASSWORD || 'AdminPass123!Secure';

// Regression test for wayfinder R15: on a fresh instance / brand-new client
// (no session cookie at all), `/auth/login` must be reachable WITHOUT first
// being authenticated. It previously sat inside the same router layer as
// `require_auth`, so every login attempt was rejected with "authentication
// required" before the credentials were ever checked. Uses the `request`
// fixture (not `page`) specifically so this makes zero requests with any
// cookie jar — it isolates the routing/middleware behavior from the login
// form's own JS.
test.describe('Fresh-instance login routing (R15)', () => {
  test('POST /auth/login is reachable with no prior session cookie', async ({ request }) => {
    // Real clients get a csrf_token cookie from any GET before they can POST
    // — fetch that the same way a fresh browser would, so this test isolates
    // require_auth (the R15 concern) from CSRF protection (a separate,
    // correctly-enforced check, not what this test is guarding against).
    await request.get(`${BASE_URL}/`);
    const cookies = await request.storageState();
    const csrfToken = cookies.cookies.find((c) => c.name === 'csrf_token')?.value || '';

    const res = await request.post(`${BASE_URL}/auth/login`, {
      form: { username: USERNAME, password: PASSWORD, csrf_token: csrfToken },
      maxRedirects: 0,
    });
    // A 401/403 here means the login route itself is gated by auth
    // middleware — the exact R15 regression. A redirect (whether to the
    // dashboard on success or to an error URL on bad credentials) proves
    // the route was reached and evaluated on its own merits — only "not
    // gated by auth" matters for this test.
    expect([301, 302, 303, 307, 308]).toContain(res.status());
  });
});

test.describe('Password login', () => {
  test('logs in with valid credentials', async ({ page }) => {
    await page.goto('/');
    await page.waitForSelector('#username');
    await page.fill('#username', USERNAME);
    await page.fill('#password', PASSWORD);
    await page.click('#login-submit');
    await expect(page).toHaveURL(/connections|sessions/);
    const cookies = await page.context().cookies();
    const session = cookies.find(c => c.name === 'persea_session');
    expect(session).toBeTruthy();
    expect(session!.value).toBeTruthy();
  });

  test('shows error for wrong password', async ({ page }) => {
    await page.goto('/');
    await page.waitForSelector('#username');
    await page.fill('#username', USERNAME);
    await page.fill('#password', 'wrongpassword');
    await page.click('#login-submit');
    await expect(page).toHaveURL(/error=/);
  });
});
