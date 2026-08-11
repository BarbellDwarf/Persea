import { test as base, type Page } from '@playwright/test';

/**
 * Authenticate via API key and store the session for reuse.
 * The persea API key is stored in sessionStorage as 'persea_api_key'.
 */
export async function loginWithApiKey(page: Page, apiKey: string): Promise<void> {
  await page.goto('/');
  await page.evaluate((key) => {
    sessionStorage.setItem('persea_api_key', key);
  }, apiKey);
}

/**
 * Login via the password form on the login page.
 */
export async function loginWithPassword(page: Page, username: string, password: string): Promise<void> {
  await page.goto('/');
  await page.waitForSelector('#username');
  await page.fill('#username', username);
  await page.fill('#password', password);
  await page.click('#login-submit');
  await page.waitForURL(/connections\.html|sessions\.html/, { timeout: 10_000 });
}

/**
 * Clear stored auth (sessionStorage + cookies).
 */
export async function logout(page: Page): Promise<void> {
  await page.evaluate(() => sessionStorage.clear());
  await page.context().clearCookies();
}

/** Role levels matching the JS in the frontend */
export const ROLE_LEVELS: Record<string, number> = {
  admin: 4,
  poweruser: 3,
  operator: 2,
  viewer: 1,
};

/**
 * Extended test fixtures with auth helpers.
 */
type AuthFixtures = {
  adminApiKey: string;
  poweruserApiKey: string;
  operatorApiKey: string;
  viewerApiKey: string;
};

export const test = base.extend<AuthFixtures>({
  adminApiKey: [process.env.ADMIN_API_KEY || '', { option: true }],
  poweruserApiKey: [process.env.POWERUSER_API_KEY || '', { option: true }],
  operatorApiKey: [process.env.OPERATOR_API_KEY || '', { option: true }],
  viewerApiKey: [process.env.VIEWER_API_KEY || '', { option: true }],
});

export { expect } from '@playwright/test';
