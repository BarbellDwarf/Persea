import { test, expect } from '@playwright/test';
test.use({ storageState: '.auth/user.json' });
import { RecordingsPage } from '../../pages/RecordingsPage';

test.describe('Recordings page', () => {
  let rec: RecordingsPage;

  test.beforeEach(async ({ page }) => {
    rec = new RecordingsPage(page);
  });

  test('page renders with title and nav', async ({ page }) => {
    await rec.goto();
    await expect(page).toHaveTitle(/persea.*Recordings/i);
    await expect(page.locator('h1')).toBeVisible();
    await expect(rec.navRecordings).toHaveClass(/active/);
  });

  test('player section is hidden initially', async () => {
    await rec.goto();
    await expect(rec.playerSection).toBeHidden();
  });

  test('search input is visible', async () => {
    await rec.goto();
    await expect(rec.recSearch).toBeVisible();
    await expect(rec.recSearch).toHaveAttribute('placeholder', /Search recordings/);
  });

  test('recording list container is visible', async () => {
    await rec.goto();
    // On a fresh DB with no recordings, the empty state is shown.
    // When recordings exist, the content table is shown instead.
    const listOrEmpty = rec.recordingList.or(rec.recordingEmpty);
    await expect(listOrEmpty.first()).toBeVisible({ timeout: 10_000 });
  });

  test('search filters recordings', async ({ page }) => {
    await rec.goto();
    const resp = page.waitForResponse((r) => r.url().includes('/api/recordings') && r.url().includes('q='));
    await rec.searchRecordings('nonexistent-session-xyz');
    await resp;
    await expect(rec.recordingEmpty).toBeVisible();
    await expect(rec.recordingEmpty).toContainText(/No recordings/);
  });

  test('nav links navigate correctly', async ({ page }) => {
    await rec.goto();
    await rec.navConnections.click();
    await expect(page).toHaveURL(/connections\.html/);
  });
});
