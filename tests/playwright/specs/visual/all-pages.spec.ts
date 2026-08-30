import { test, expect } from '@playwright/test';
test.use({ storageState: '.auth/user.json' });
import { loginWithApiKey, logout } from '../../fixtures/auth';

const ADMIN_KEY = process.env.ADMIN_API_KEY || '';

// Freeze a live table's geometry for the screenshot: wait for the initial
// data load, pin the auto-computed column widths, then cap the (masked)
// rows to a fixed set of single-line placeholders so the fullPage height
// and header layout stay deterministic as the underlying data changes.
async function stabilizeTable(
  page: import('@playwright/test').Page,
  tbodySelector: string,
  maxRows: number,
  emptySelector?: string,
) {
  try {
    await page.waitForFunction(
      ([sel, emptySel]) => {
        const tbody = document.querySelector(sel);
        if (tbody && tbody.querySelectorAll('tr').length > 0) return true;
        if (emptySel) {
          const el = document.querySelector(emptySel);
          return !!el && !el.classList.contains('hidden');
        }
        return false;
      },
      [tbodySelector, emptySelector || null] as const,
      { timeout: 8000 },
    );
  } catch {
    // data load may be slow — proceed with whatever is rendered
  }
  await page.evaluate(
    ([sel, n]) => {
      const tbody = document.querySelector(sel);
      const table = tbody && tbody.closest('table');
      if (table) {
        table.style.tableLayout = 'fixed';
        table.querySelectorAll('th').forEach((th) => {
          th.style.width = Math.round((th as HTMLElement).getBoundingClientRect().width) + 'px';
        });
      }
      const firstRow = tbody && tbody.querySelector('tr');
      if (firstRow) {
        const template = firstRow.cloneNode(true) as HTMLElement;
        template.querySelectorAll('td').forEach((td) => {
          td.textContent = '\u00a0';
        });
        tbody!.innerHTML = '';
        for (let i = 0; i < n; i++) tbody!.appendChild(template.cloneNode(true));
      }
    },
    [tbodySelector, maxRows] as const,
  );
}

test.describe('Visual Regression - All Pages', () => {
  test('login page screenshot', async ({ page }) => {
    // Navigate before clearing auth — sessionStorage is not accessible on about:blank
    await page.goto(`/`);
    await logout(page);
    await page.goto(`/`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('login-page.png', { fullPage: true });
  });

  test('connections page screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`/connections.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('connections-page.png', { fullPage: true });
  });

  test('sessions page screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`/sessions.html`);
    await page.waitForTimeout(2000);
    await stabilizeTable(page, '#session-list', 5, '#session-empty');
    await expect(page).toHaveScreenshot('sessions-page.png', {
      fullPage: true,
      mask: [page.locator('#session-list'), page.locator('#session-counts'), page.locator('#session-empty')],
      maskColor: '#e2e8f0',
    });
  });

  test('recordings page screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`/recordings.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('recordings-page.png', { fullPage: true });
  });

  test('admin page screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`/admin.html`);
    await page.waitForTimeout(2000);
    await stabilizeTable(page, '#user-table-body', 5);
    await expect(page).toHaveScreenshot('admin-page.png', {
      fullPage: true,
      mask: [page.locator('#user-table-body'), page.locator('#user-pagination')],
      maskColor: '#e2e8f0',
    });
  });

  test('admin settings screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`/admin/settings.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('admin-settings.png', { fullPage: true });
  });

  test('admin users screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`/admin/users.html`);
    await page.waitForTimeout(2000);
    await stabilizeTable(page, '#user-table-body', 5);
    await expect(page).toHaveScreenshot('admin-users.png', {
      fullPage: true,
      mask: [page.locator('#user-table-body'), page.locator('#user-pagination')],
      maskColor: '#e2e8f0',
    });
  });

  test('admin auth screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`/admin/auth.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('admin-auth.png', { fullPage: true });
  });

  test('admin audit screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`/admin/audit.html`);
    await page.waitForTimeout(2000);
    await stabilizeTable(page, '#audit-table-body', 10);
    await expect(page).toHaveScreenshot('admin-audit.png', {
      fullPage: true,
      mask: [page.locator('#audit-table-body'), page.locator('#audit-pagination')],
      maskColor: '#e2e8f0',
    });
  });

  test('admin reports screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`/admin/reports.html`);
    await page.waitForTimeout(2000);
    await stabilizeTable(page, '#top-connections', 5);
    await stabilizeTable(page, '#top-users', 5);
    await stabilizeTable(page, '#recent-sessions', 5);
    await expect(page).toHaveScreenshot('admin-reports.png', {
      fullPage: true,
      mask: [
        page.locator('#stat-total-sessions'),
        page.locator('#stat-active-sessions'),
        page.locator('#stat-total-users'),
        page.locator('#stat-uptime'),
        page.locator('#chart-area'),
        page.locator('#top-connections'),
        page.locator('#top-users'),
        page.locator('#recent-sessions'),
      ],
      maskColor: '#e2e8f0',
    });
  });

  test('admin tunnels screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`/admin/tunnels.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('admin-tunnels.png', { fullPage: true });
  });

  test('account profile screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`/account/profile.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('account-profile.png', { fullPage: true });
  });

  test('account tokens screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`/account/tokens.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('account-tokens.png', { fullPage: true });
  });

  test('account totp screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`/account/totp.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('account-totp.png', { fullPage: true });
  });

  test('docs page screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`/docs.html`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('docs-page.png', { fullPage: true });
  });

  test('client page screenshot', async ({ page }) => {
    await loginWithApiKey(page, ADMIN_KEY);
    await page.goto(`/client.html?session_id=test`);
    await page.waitForTimeout(2000);
    await expect(page).toHaveScreenshot('client-page.png', { fullPage: true });
  });
});
