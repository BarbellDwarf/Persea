/**
 * Canonical web-UI screenshots (wayfinder/v1.2.0/S18).
 *
 * Produces the committed baseline images in docs/screenshots/. Deterministic
 * by construction: seeded data (see ./seed.ts), fixed viewport, UTC timezone,
 * no live timers in the frame. Each test writes a PNG via page.screenshot()
 * — this is not a toHaveScreenshot() regression check.
 *
 * Run from tests/playwright (the suite's global-setup handles the setup
 * wizard, login, and seeding):
 *   BASE_URL=http://localhost:8089 ADMIN_API_KEY=... \
 *     SHOT_DB=... SHOT_RECORDING_DIR=... SHOT_SSH_KEY=... \
 *     npx playwright test --config screenshots/playwright.config.ts
 *
 * The live SSH session shot (ssh-session.png) needs guacd on port 4822 AND a
 * demo sshd reachable from the test instance (SHOT_SSH_KEY points at the
 * private key for the demo account; the CI regen workflow sets both up).
 * Without them the spec warns, captures the client page shell instead, and
 * the regen workflow's diff check reports the missing live frame.
 */
import { test, expect, type Page } from '@playwright/test';
import { existsSync, readFileSync } from 'fs';
import { Socket } from 'net';

test.use({ storageState: '.auth/user.json' });

const BASE_URL = process.env.BASE_URL || 'http://localhost:8089';
const ADMIN_KEY = process.env.ADMIN_API_KEY || '';
const OUT_DIR = process.env.SCREENSHOT_DIR || '../../docs/screenshots';
const VIEWPORT = { width: 1440, height: 900 };

// Live-session environment (documented in .github/workflows/screenshots.yml):
const SSH_HOST = process.env.SCREENSHOT_SSH_HOST || '127.0.0.1';
const SSH_PORT = Number(process.env.SCREENSHOT_SSH_PORT || '2222');
const SSH_USER = process.env.SCREENSHOT_SSH_USER || 'demo';
// The seed script's env name (SHOT_SSH_KEY) doubles as the spec's key path.
const SSH_KEY = process.env.SCREENSHOT_SSH_KEY || process.env.SHOT_SSH_KEY || '';
const GUACD_ADDR = process.env.SCREENSHOT_GUACD_ADDR || '127.0.0.1:4822';

const shot = (name: string) => `${OUT_DIR}/${name}.png`;

// The client page auto-hides its toolbar 1.5s after the mouse leaves the top
// strip. Pin it visible for the shot (screenshot-only manipulation, like the
// visual suite's stabilizeTable).
async function pinToolbar(page: Page) {
  await page.evaluate(() => {
    const t = document.getElementById('toolbar');
    if (t) t.classList.add('force-visible');
    document.body.classList.remove('toolbar-hidden');
  });
}

async function openClient(page: Page, path: string) {
  await page.setViewportSize(VIEWPORT);
  await page.goto(`${BASE_URL}${path}`);
  // Wait for the initial data loads to settle before any interaction.
  await page.waitForLoadState('networkidle').catch(() => {});
}

async function guacdReachable(): Promise<boolean> {
  try {
    const [host, port] = GUACD_ADDR.split(':');
    const sock = new Socket();
    return await new Promise((resolve) => {
      sock.setTimeout(1500);
      sock.once('connect', () => { sock.destroy(); resolve(true); });
      sock.once('error', () => resolve(false));
      sock.once('timeout', () => { sock.destroy(); resolve(false); });
      sock.connect(Number(port), host);
    });
  } catch {
    return false;
  }
}

test.describe('Canonical screenshots', () => {
  test.use({ timezoneId: 'UTC' });

  // The login shot must run unauthenticated (fresh context, no cookies).
  test.describe('login', () => {
    test.use({ storageState: { cookies: [], origins: [] } });
    test('login page', async ({ page }) => {
      await page.setViewportSize(VIEWPORT);
      await page.goto(`${BASE_URL}/`);
      await expect(page.locator('#username')).toBeVisible();
      await expect(page.locator('#password')).toBeVisible();
      await page.waitForTimeout(800);
      await page.screenshot({ path: shot('login'), fullPage: true });
    });
  });

  test('connections page with folder tree and details', async ({ page }) => {
    await openClient(page, '/connections.html');
    // Folder tree loads from /api/addressbook.
    await expect(page.locator('#folder-tree .folder-item').first()).toBeVisible();
    await page.waitForTimeout(500);
    // Open Production and select the Web Server entry so the details panel
    // shows (entries render sorted by name).
    await page.locator('#folder-tree .folder-item', { hasText: 'Production' }).click();
    await expect(page.locator('#entries-content .entry-row').first()).toBeVisible();
    await page.locator('#entries-content .entry-row', { hasText: 'Web Server' }).click();
    await expect(page.locator('#detail-panel')).toBeVisible();
    await expect(page.locator('#detail-name')).toHaveText(/Web Server/);
    await page.waitForTimeout(800);
    await page.screenshot({ path: shot('connections'), fullPage: true });
  });

  test('sessions page', async ({ page }) => {
    await openClient(page, '/sessions.html');
    // Active list is empty (deterministic); the recent-ended history table
    // carries the seeded rows with fixed timestamps.
    await expect(page.locator('#recent-ended-list tr').first()).toBeVisible();
    await page.waitForTimeout(800);
    await page.screenshot({ path: shot('sessions'), fullPage: true });
  });

  test('recordings player', async ({ page }) => {
    await openClient(page, '/recordings.html');
    await expect(page.locator('#recordings-list tr').first()).toBeVisible();
    await page.waitForTimeout(500);
    // Open the player on the first recording, start playback, and wait for
    // it to reach the end (fixed duration from the seeded .guac sync
    // timestamps). The display canvas only sizes up once playback applies
    // frames; the play button reads "Play" again at the end.
    await page.locator('#recordings-list tr').first().locator('.rec-play').click();
    await expect(page.locator('#player-section')).toBeVisible();
    // Wait for the recording to load (duration appears in the time display),
    // then start playback.
    await expect(page.locator('#player-time')).not.toHaveText('00:00 / 00:00', { timeout: 10_000 });
    await page.locator('#play-btn').click();
    // Playback started (button flips to Pause) …
    await expect(page.locator('#play-btn')).toHaveText('Pause', { timeout: 10_000 });
    // … and ran to the end (fixed duration from the seeded .guac syncs).
    await expect(page.locator('#play-btn')).toHaveText('Play', { timeout: 20_000 });
    await expect(page.locator('#player-display canvas').first()).toBeVisible();
    await page.waitForTimeout(300);
    await page.screenshot({ path: shot('recordings-player') });
  });

  test('admin settings (with Desktop toggles)', async ({ page }) => {
    await openClient(page, '/admin/settings.html');
    // The native checkboxes are visually hidden by the toggle-switch style;
    // assert on the section labels instead (exact text — the description
    // paragraphs contain the same words).
    const desktop = page.locator('.card', { hasText: 'Desktop' });
    await expect(desktop.getByText('Kiosk Mode', { exact: true })).toBeVisible();
    await expect(desktop.getByText('File Transfers', { exact: true })).toBeVisible();
    await expect(desktop.getByText('Device Pairing', { exact: true })).toBeVisible();
    await page.waitForTimeout(800);
    await page.screenshot({ path: shot('admin-settings'), fullPage: true });
  });

  test('admin audit page', async ({ page }) => {
    await openClient(page, '/admin/audit.html');
    await expect(page.locator('#audit-table-body tr').first()).toBeVisible();
    await page.waitForTimeout(800);
    await page.screenshot({ path: shot('admin-audit'), fullPage: true });
  });

  test('account tokens page', async ({ page }) => {
    await openClient(page, '/account/tokens.html');
    await expect(page.locator('#tokens-tbody tr').first()).toBeVisible();
    await page.waitForTimeout(800);
    await page.screenshot({ path: shot('account-tokens'), fullPage: true });
  });

  test('live SSH session (client page)', async ({ page }) => {
    const keyPath = SSH_KEY;
    const canLive =
      (await guacdReachable()) &&
      keyPath !== '' &&
      existsSync(keyPath);

    if (!canLive) {
      console.warn(
        `[screenshots] live SSH shot unavailable (guacd=${GUACD_ADDR}, key=${keyPath || '<unset>'}) — capturing the client page shell instead`,
      );
      // Shell capture: block the session-info fetch so the page stays on its
      // initial chrome (toolbar, status, display area) without a session.
      await page.route('**/api/sessions/*', (route) => route.abort());
      await page.setViewportSize(VIEWPORT);
      await page.goto(`${BASE_URL}/client/00000000-0000-4000-8000-000000000000`);
      await expect(page.locator('#toolbar')).toBeVisible();
      await pinToolbar(page);
      await page.waitForTimeout(800);
      await page.screenshot({ path: shot('ssh-session') });
      return;
    }

    // Create the session with the demo key, then open the client page in the
    // SAME test — the first WebSocket attach is the owner connect.
    const csrfProbe = await fetch(`${BASE_URL}/`, {
      headers: { Authorization: `Bearer ${ADMIN_KEY}` },
    });
    const csrf = (csrfProbe.headers.get('set-cookie') || '').match(/csrf_token=([a-f0-9]+)/)?.[1] || '';
    const key = readFileSync(keyPath, 'utf8');
    const res = await fetch(`${BASE_URL}/api/sessions`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${ADMIN_KEY}`,
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrf,
        Cookie: `csrf_token=${csrf}`,
      },
      body: JSON.stringify({
        session_type: 'ssh',
        hostname: SSH_HOST,
        port: SSH_PORT,
        username: SSH_USER,
        width: 1280,
        height: 800,
        reason: 'Documentation screenshot',
        ssh: { private_key: key },
      }),
    });
    expect(res.status).toBe(200);
    const created = (await res.json()) as { session_id: string; status: string };

    await page.setViewportSize(VIEWPORT);
    await page.goto(`${BASE_URL}/client/${created.session_id}`);
    // Live indicator: the favicon swaps to the pulsing-green variant and the
    // status text reports the connection (S17 branding).
    await page.waitForFunction(
      () => document.getElementById('persea-favicon')?.getAttribute('href')?.includes('live'),
      undefined,
      { timeout: 20_000 },
    );
    // Let the terminal render its first frame and the reconnect timers idle,
    // then pin the auto-hiding toolbar for the shot.
    await page.waitForTimeout(2500);
    await pinToolbar(page);
    await page.screenshot({ path: shot('ssh-session') });

    // Tidy up: terminate the demo session so re-runs stay deterministic.
    await page.evaluate(
      (sid) => fetch(`/api/sessions/${sid}`, { method: 'DELETE', headers: { 'X-CSRF-Token': document.cookie.match(/csrf_token=([a-f0-9]+)/)?.[1] || '' }, credentials: 'same-origin' }),
      created.session_id,
    ).catch(() => {});
  });

});
