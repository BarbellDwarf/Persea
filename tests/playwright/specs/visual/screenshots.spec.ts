import { test, expect } from '@playwright/test';
test.use({ storageState: '.auth/user.json' });

async function authenticate(page: import('@playwright/test').Page) {
  await page.goto('/');
  await page.evaluate((key) => {
    sessionStorage.setItem('persea_api_key', key);
  }, process.env.ADMIN_API_KEY || '');
}

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

test.describe('Visual regression screenshots', () => {
  test('login page screenshot', async ({ page }) => {
    await page.goto('/');
    await page.waitForTimeout(1000);
    await expect(page).toHaveScreenshot('login-page.png', {
      fullPage: true,
      maxDiffPixels: 200,
    });
  });

  const authenticatedPages = [
    {
      name: 'sessions',
      url: '/sessions.html',
      masks: ['#session-list', '#session-counts'],
    },
    { name: 'connections', url: '/connections.html' },
    { name: 'recordings', url: '/recordings.html' },
    {
      name: 'admin',
      url: '/admin.html',
      masks: ['#user-table-body', '#user-pagination'],
    },
    { name: 'tokens', url: '/tokens.html' },
  ];

  for (const { name, url, masks } of authenticatedPages) {
    test(`${name} page screenshot`, async ({ page }) => {
      await authenticate(page);
      await page.goto(url);
      await page.waitForTimeout(1000);
      const mask = (masks || []).map((sel) => page.locator(sel));
      if (name === 'sessions') {
        await stabilizeTable(page, '#session-list', 5, '#session-empty');
      } else if (name === 'admin') {
        await stabilizeTable(page, '#user-table-body', 5);
      }
      await expect(page).toHaveScreenshot(`${name}-page.png`, {
        fullPage: true,
        maxDiffPixels: 200,
        ...(mask.length ? { mask, maskColor: '#e2e8f0' } : {}),
      });
    });
  }

  test('sessions page with form expanded', async ({ page }) => {
    await authenticate(page);
    await page.goto('/sessions.html');
    // Expand the form
    const toggle = page.locator('#new-session-toggle');
    if (await toggle.isVisible()) {
      await toggle.click();
    }
    await page.waitForTimeout(500);
    await stabilizeTable(page, '#session-list', 5, '#session-empty');
    await expect(page).toHaveScreenshot('sessions-form-expanded.png', {
      fullPage: true,
      maxDiffPixels: 200,
      mask: [page.locator('#session-list'), page.locator('#session-counts')],
      maskColor: '#e2e8f0',
    });
  });

  test('connections page with vault state', async ({ page }) => {
    await authenticate(page);
    await page.goto('/connections.html');
    await page.waitForTimeout(1000);
    await expect(page).toHaveScreenshot('connections-vault-state.png', {
      fullPage: true,
      maxDiffPixels: 200,
    });
  });

  test('admin page system status', async ({ page }) => {
    await authenticate(page);
    await page.goto('/admin.html');
    await page.waitForTimeout(1000);
    await stabilizeTable(page, '#user-table-body', 5);
    await expect(page).toHaveScreenshot('admin-status.png', {
      fullPage: true,
      maxDiffPixels: 200,
      mask: [page.locator('#user-table-body'), page.locator('#user-pagination')],
      maskColor: '#e2e8f0',
    });
  });

  test('mobile sessions page', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await authenticate(page);
    await page.goto('/sessions.html');
    await page.waitForTimeout(500);
    await stabilizeTable(page, '#session-list', 5, '#session-empty');
    await expect(page).toHaveScreenshot('sessions-mobile.png', {
      fullPage: true,
      maxDiffPixels: 200,
      mask: [page.locator('#session-list'), page.locator('#session-counts')],
      maskColor: '#e2e8f0',
    });
  });

  test('mobile connections page', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await authenticate(page);
    await page.goto('/connections.html');
    await page.waitForTimeout(500);
    await expect(page).toHaveScreenshot('connections-mobile.png', {
      fullPage: true,
      maxDiffPixels: 200,
    });
  });
});
