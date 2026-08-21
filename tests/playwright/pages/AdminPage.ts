import type { Page, Locator } from '@playwright/test';

/**
 * Page object for the v1.1.0 admin area:
 * - /admin/users.html   — user management (also served at /admin.html)
 * - /admin/groups.html  — groups + provider-group mappings
 * - /admin/audit.html   — audit log
 * - /account/tokens.html — API Keys (tokens UI moved out of the admin page)
 *
 * Selectors are inlined here (the fixtures/selectors.ts ADMIN_PAGE block is
 * stale — it describes the pre-rework monolithic admin page).
 */
export class AdminPage {
  readonly page: Page;

  // Nav
  readonly navConnections: Locator;
  readonly navSessions: Locator;
  readonly navRecordings: Locator;
  readonly navAdmin: Locator;

  // Users page (/admin/users.html)
  readonly usersBody: Locator;
  readonly userSearch: Locator;
  readonly addUserBtn: Locator;

  // Groups page (/admin/groups.html)
  readonly groupsBody: Locator;
  readonly newGroup: Locator;
  readonly newRole: Locator;
  readonly addMappingBtn: Locator;

  // Tokens page (/account/tokens.html)
  readonly tokensBody: Locator;
  readonly createTokenBtn: Locator;

  // Audit page (/admin/audit.html)
  readonly auditBody: Locator;
  readonly auditUserFilter: Locator;
  readonly verifyChainBtn: Locator;

  constructor(page: Page) {
    this.page = page;

    this.navConnections = page.locator('nav a[href="/connections.html"]');
    this.navSessions = page.locator('nav a[href="/sessions.html"]');
    this.navRecordings = page.locator('nav a[href="/recordings.html"]');
    // The consolidated Security page hosts the admin sections since #172;
    // deep links to the old pages highlight it.
    this.navAdmin = page.locator('nav a[href="/admin/security.html"]');

    this.usersBody = page.locator('#user-table-body');
    this.userSearch = page.locator('#user-search');
    this.addUserBtn = page.locator('button:has-text("+ Add User")');

    this.groupsBody = page.locator('#groups-tbody');
    this.newGroup = page.locator('#create-group-name');
    this.newRole = page.locator('#mappings-select');
    this.addMappingBtn = page.locator('[data-action="add-mapping"]');

    this.tokensBody = page.locator('#tokens-tbody');
    this.createTokenBtn = page.locator('#btn-create-token');

    this.auditBody = page.locator('#audit-table-body');
    this.auditUserFilter = page.locator('input[name="user"]');
    this.verifyChainBtn = page.locator('button:has-text("Verify Chain")');
  }

  async goto(): Promise<void> {
    await this.page.goto('/admin/users.html');
  }

  async gotoGroups(): Promise<void> {
    await this.page.goto('/admin/groups.html');
  }

  async gotoAudit(): Promise<void> {
    await this.page.goto('/admin/audit.html');
  }

  async gotoTokens(): Promise<void> {
    await this.page.goto('/account/tokens.html');
  }

  async getUserRowCount(): Promise<number> {
    return this.page.locator('#user-table-body tr').count();
  }

  async getAuditRowCount(): Promise<number> {
    return this.page.locator('#audit-table-body tr').count();
  }
}
