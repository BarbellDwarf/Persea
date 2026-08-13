/**
 * Playwright config for the canonical screenshot suite
 * (wayfinder/v1.2.0/S18). The specs live OUTSIDE the main suite's testDir
 * (tests/playwright/specs) because they write committed baseline images
 * instead of asserting against them.
 *
 * Run from tests/playwright after seeding:
 *   npx playwright test --config screenshots/playwright.config.ts
 */
import { defineConfig, devices } from '@playwright/test';

const BASE_URL = process.env.BASE_URL || 'http://localhost:8089';

export default defineConfig({
  testDir: '.',
  globalSetup: './global-setup.ts',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [['list']],
  timeout: 90_000,

  use: {
    baseURL: BASE_URL,
    // global-setup.ts authenticates the admin user against BASE_URL and
    // stores the session at tests/playwright/.auth/user.json (gitignored).
    storageState: '../.auth/user.json',
    trace: 'off',
    actionTimeout: 15_000,
    navigationTimeout: 20_000,
  },

  projects: [
    {
      name: 'Desktop Chrome',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1440, height: 900 },
      },
    },
  ],
});
