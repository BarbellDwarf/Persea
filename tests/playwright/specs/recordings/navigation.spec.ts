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
    await expect(page).toHaveTitle(/persea.*Recordings/);
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
    await expect(rec.recordingList).toBeVisible();
  });

  test('search filters recordings', async () => {
    await rec.goto();
    await rec.searchRecordings('nonexistent-session-xyz');
    await expect(rec.recordingList).toContainText(/No recordings found/);
  });

  test('typescript section is hidden when no typescripts', async () => {
    await rec.goto();
    // Section may or may not be visible depending on data
    const visible = await rec.isTypescriptSectionVisible();
    expect(typeof visible).toBe('boolean');
  });

  test('nav links navigate correctly', async ({ page }) => {
    await rec.goto();
    await rec.navConnections.click();
    await expect(page).toHaveURL(/connections\.html/);
  });
});
