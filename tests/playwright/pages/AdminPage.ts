import type { Page, Locator } from '@playwright/test';
import { ADMIN_PAGE as S } from '../fixtures/selectors';

export class AdminPage {
  readonly page: Page;

  // Nav
  readonly navConnections: Locator;
  readonly navSessions: Locator;
  readonly navRecordings: Locator;
  readonly navAdmin: Locator;

  // System status
  readonly ssVersion: Locator;
  readonly ssActive: Locator;
  readonly ssUsers: Locator;
  readonly ssHistory: Locator;
  readonly ssRecordings: Locator;
  readonly ssDisk: Locator;
  readonly ssVault: Locator;
  readonly ssFeatures: Locator;

  // Users
  readonly usersBody: Locator;

  // Mappings
  readonly mappingsBody: Locator;
  readonly newGroup: Locator;
  readonly newRole: Locator;
  readonly addMappingBtn: Locator;

  // Tokens
  readonly tokensBody: Locator;
  readonly noTokens: Locator;
  readonly tokenEmail: Locator;
  readonly tokenName: Locator;
  readonly tokenMaxRole: Locator;
  readonly tokenExpires: Locator;
  readonly adminCreateTokenBtn: Locator;
  readonly adminTokenReveal: Locator;
  readonly adminTokenPlaintext: Locator;

  // Audit
  readonly auditBody: Locator;
  readonly noAudit: Locator;
  readonly auditEmailFilter: Locator;
  readonly auditFilterBtn: Locator;

  // Connections audit
  readonly abAuditBody: Locator;
  readonly noAbAudit: Locator;

  readonly error: Locator;

  constructor(page: Page) {
    this.page = page;

    this.navConnections = page.locator(S.navConnections);
    this.navSessions = page.locator(S.navSessions);
    this.navRecordings = page.locator(S.navRecordings);
    this.navAdmin = page.locator(S.navAdmin);

    this.ssVersion = page.locator(S.ssVersion);
    this.ssActive = page.locator(S.ssActive);
    this.ssUsers = page.locator(S.ssUsers);
    this.ssHistory = page.locator(S.ssHistory);
    this.ssRecordings = page.locator(S.ssRecordings);
    this.ssDisk = page.locator(S.ssDisk);
    this.ssVault = page.locator(S.ssVault);
    this.ssFeatures = page.locator(S.ssFeatures);

    this.usersBody = page.locator(S.usersBody);

    this.mappingsBody = page.locator(S.mappingsBody);
    this.newGroup = page.locator(S.newGroup);
    this.newRole = page.locator(S.newRole);
    this.addMappingBtn = page.locator(S.addMappingBtn);

    this.tokensBody = page.locator(S.tokensBody);
    this.noTokens = page.locator(S.noTokens);
    this.tokenEmail = page.locator(S.tokenEmail);
    this.tokenName = page.locator(S.tokenName);
    this.tokenMaxRole = page.locator(S.tokenMaxRole);
    this.tokenExpires = page.locator(S.tokenExpires);
    this.adminCreateTokenBtn = page.locator(S.adminCreateTokenBtn);
    this.adminTokenReveal = page.locator(S.adminTokenReveal);
    this.adminTokenPlaintext = page.locator(S.adminTokenPlaintext);

    this.auditBody = page.locator(S.auditBody);
    this.noAudit = page.locator(S.noAudit);
    this.auditEmailFilter = page.locator(S.auditEmailFilter);
    this.auditFilterBtn = page.locator(S.auditFilterBtn);

    this.abAuditBody = page.locator(S.abAuditBody);
    this.noAbAudit = page.locator(S.noAbAudit);

    this.error = page.locator(S.error);
  }

  async goto(): Promise<void> {
    await this.page.goto('/');
    await this.page.evaluate((key) => {
      sessionStorage.setItem('persea_api_key', key);
    }, process.env.ADMIN_API_KEY || '');
    await this.page.goto('/admin.html');
  }

  async getVersion(): Promise<string> {
    return (await this.ssVersion.textContent()) || '';
  }

  async getActiveSessions(): Promise<string> {
    return (await this.ssActive.textContent()) || '';
  }

  async getUserCount(): Promise<string> {
    return (await this.ssUsers.textContent()) || '';
  }

  async getUserRowCount(): Promise<number> {
    return this.page.locator(`${S.usersBody} tr`).count();
  }

  async getMappingRowCount(): Promise<number> {
    return this.page.locator(`${S.mappingsBody} tr`).count();
  }

  async getTokenRowCount(): Promise<number> {
    return this.page.locator(`${S.tokensBody} tr`).count();
  }

  async getAuditRowCount(): Promise<number> {
    return this.page.locator(`${S.auditBody} tr`).count();
  }

  async createTokenForUser(email: string, name: string): Promise<string> {
    await this.tokenEmail.fill(email);
    await this.tokenName.fill(name);
    await this.adminCreateTokenBtn.click();
    await this.adminTokenReveal.waitFor({ state: 'visible' });
    return (await this.adminTokenPlaintext.textContent()) || '';
  }

  async filterAuditByEmail(email: string): Promise<void> {
    await this.auditEmailFilter.fill(email);
    await this.auditFilterBtn.click();
  }
}
