import { test, expect } from '@playwright/test';

const USERNAME = process.env.LOGIN_USERNAME || 'admin@local.test';
const PASSWORD = process.env.LOGIN_PASSWORD || 'AdminPass123!';

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
    await expect(page).toHaveURL(/error=login_failed/);
  });
});
