import { chromium } from 'playwright';

const BASE_URL = process.env.BASE_URL || 'http://localhost:8089';

async function main() {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  console.log('Navigating to setup page...');
  await page.goto(`${BASE_URL}/setup`, { waitUntil: 'networkidle', timeout: 15000 });
  console.log('Setup page loaded. URL:', page.url());

  console.log('Filling in setup form...');
  await page.fill('#admin_email', 'admin@local.test');
  await page.fill('#admin_name', 'Administrator');
  await page.fill('#admin_password', 'AdminPass123!');

  const listenAddr = await page.inputValue('#listen_addr');
  const dbPath = await page.inputValue('#db_path');
  console.log('listen_addr:', listenAddr);
  console.log('db_path:', dbPath);

  console.log('Submitting setup form...');
  await page.click('button[type="submit"]');

  await page.waitForURL(/(\?setup=complete|\/)/, { timeout: 10000 });
  console.log('Setup complete. URL:', page.url());

  // Clear session cookie from setup so we exercise the real login form
  await context.clearCookies();

  console.log('Logging in...');
  await page.goto(`${BASE_URL}/`, { waitUntil: 'networkidle', timeout: 15000 });

  const currentUrl = page.url();
  console.log('Current URL after setup:', currentUrl);

  if (currentUrl.includes('connections') || currentUrl.includes('sessions')) {
    console.log('Already logged in via session cookie');
  } else {
    await page.fill('#username', 'admin@local.test');
    await page.fill('#password', 'AdminPass123!');
    await page.click('#login-submit');
    await page.waitForURL(/connections\.html|sessions\.html/, { timeout: 10000 });
    console.log('Login successful. URL:', page.url());
  }

  await browser.close();
  console.log('Setup and login completed successfully!');
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
