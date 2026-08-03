import type { Page, Locator } from '@playwright/test';
import { TOKENS_PAGE as S } from '../fixtures/selectors';

export class TokensPage {
  readonly page: Page;

  // Nav
  readonly navConnections: Locator;
  readonly navSessions: Locator;
  readonly navTokens: Locator;

  readonly loading: Locator;
  readonly noPermission: Locator;

  // Create
  readonly createSection: Locator;
  readonly tokenName: Locator;
  readonly tokenMaxRole: Locator;
  readonly tokenExpires: Locator;
  readonly createBtn: Locator;
  readonly tokenReveal: Locator;
  readonly tokenPlaintext: Locator;
  readonly copyTokenBtn: Locator;
  readonly dismissTokenBtn: Locator;

  // List
  readonly tokensSection: Locator;
  readonly tokensBody: Locator;
  readonly noTokens: Locator;

  readonly error: Locator;

  constructor(page: Page) {
    this.page = page;

    this.navConnections = page.locator(S.navConnections);
    this.navSessions = page.locator(S.navSessions);
    this.navTokens = page.locator(S.navTokens);

    this.loading = page.locator(S.loading);
    this.noPermission = page.locator(S.noPermission);

    this.createSection = page.locator(S.createSection);
    this.tokenName = page.locator(S.tokenName);
    this.tokenMaxRole = page.locator(S.tokenMaxRole);
    this.tokenExpires = page.locator(S.tokenExpires);
    this.createBtn = page.locator(S.createBtn);
    this.tokenReveal = page.locator(S.tokenReveal);
    this.tokenPlaintext = page.locator(S.tokenPlaintext);
    this.copyTokenBtn = page.locator(S.copyTokenBtn);
    this.dismissTokenBtn = page.locator(S.dismissTokenBtn);

    this.tokensSection = page.locator(S.tokensSection);
    this.tokensBody = page.locator(S.tokensBody);
    this.noTokens = page.locator(S.noTokens);

    this.error = page.locator(S.error);
  }

  async goto(): Promise<void> {
    await this.page.goto('/');
    await this.page.evaluate((key) => {
      sessionStorage.setItem('persea_api_key', key);
    }, process.env.ADMIN_API_KEY || '');
    await this.page.goto('/tokens.html');
  }

  async isCreateSectionVisible(): Promise<boolean> {
    return this.createSection.isVisible();
  }

  async isTokensSectionVisible(): Promise<boolean> {
    return this.tokensSection.isVisible();
  }

  async hasNoPermission(): Promise<boolean> {
    return this.noPermission.isVisible();
  }

  async createToken(name: string): Promise<string> {
    await this.tokenName.fill(name);
    await this.createBtn.click();
    await this.tokenReveal.waitFor({ state: 'visible' });
    return (await this.tokenPlaintext.textContent()) || '';
  }

  async getTokenRowCount(): Promise<number> {
    return this.page.locator(`${S.tokensBody} tr`).count();
  }

  async revokeToken(index: number): Promise<void> {
    const revokeBtn = this.page.locator(`${S.tokensBody} tr`).nth(index).locator('button:has-text("revoke")');
    await revokeBtn.click();
    // Handle confirmation dialog
    this.page.once('dialog', (dialog) => dialog.accept());
  }
}
