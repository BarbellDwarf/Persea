import { chromium, FullConfig } from '@playwright/test';

const BASE_URL = process.env.BASE_URL || 'http://localhost:8089';
const USERNAME = process.env.LOGIN_USERNAME || 'admin@local.test';
const PASSWORD = process.env.LOGIN_PASSWORD || 'AdminPass123!Secure';
const STORAGE_STATE = '.auth/user.json';

async function globalSetup(config: FullConfig): Promise<void> {
  const ignoreHTTPS = BASE_URL.startsWith('https');
  const browser = await chromium.launch();
  const context = await browser.newContext({ ignoreHTTPSErrors: ignoreHTTPS });
  const page = await context.newPage();

  console.log(`[global-setup] Authenticating at ${BASE_URL}`);
  await page.goto(`${BASE_URL}/`, { waitUntil: 'domcontentloaded', timeout: 15000 });
  await page.waitForSelector('#username', { timeout: 15000 });
  await page.fill('#username', USERNAME);
  await page.fill('#password', PASSWORD);
  await page.click('#login-submit');
  await page.waitForURL(/connections\.html|sessions\.html/, { timeout: 15000 });

  // Persist the admin API key in sessionStorage so the page JS can
  // authenticate API calls. The session cookie alone is not enough: the
  // API middleware gates on the Authorization header from apiHeaders().
  const apiKey = process.env.ADMIN_API_KEY || '';
  const state = await context.storageState();
  if (apiKey) {
    state.origins = [{
      origin: new URL(BASE_URL).origin,
      localStorage: [],
      sessionStorage: [{ name: 'persea_api_key', value: apiKey }],
    }];
  }
  const { mkdirSync, writeFileSync } = require('fs');
  const { dirname } = require('path');
  mkdirSync(dirname(STORAGE_STATE), { recursive: true });
  writeFileSync(STORAGE_STATE, JSON.stringify(state, null, 2));
  console.log(`[global-setup] Authenticated — storageState saved to ${STORAGE_STATE}`);

  await browser.close();
}

export default globalSetup;
