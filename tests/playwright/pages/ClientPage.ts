import type { Page, Locator } from '@playwright/test';
import { CLIENT_PAGE as S } from '../fixtures/selectors';

export class ClientPage {
  readonly page: Page;

  readonly status: Locator;
  readonly display: Locator;
  readonly disconnectedOverlay: Locator;
  readonly disconnectedTitle: Locator;
  readonly disconnectedMessage: Locator;
  readonly btnReconnect: Locator;
  readonly btnCloseSession: Locator;
  readonly bannerOverlay: Locator;
  readonly bannerText: Locator;
  readonly bannerContinue: Locator;
  readonly fsBar: Locator;
  readonly fsBarTitle: Locator;
  readonly fsExit: Locator;
  readonly fsDisconnect: Locator;

  constructor(page: Page) {
    this.page = page;

    this.status = page.locator(S.status);
    this.display = page.locator(S.display);
    this.disconnectedOverlay = page.locator(S.disconnectedOverlay);
    this.disconnectedTitle = page.locator(S.disconnectedTitle);
    this.disconnectedMessage = page.locator(S.disconnectedMessage);
    this.btnReconnect = page.locator(S.btnReconnect);
    this.btnCloseSession = page.locator(S.btnCloseSession);
    this.bannerOverlay = page.locator(S.bannerOverlay);
    this.bannerText = page.locator(S.bannerText);
    this.bannerContinue = page.locator(S.bannerContinue);
    this.fsBar = page.locator(S.fsBar);
    this.fsBarTitle = page.locator(S.fsBarTitle);
    this.fsExit = page.locator(S.fsExit);
    this.fsDisconnect = page.locator(S.fsDisconnect);
  }

  async goto(sessionId: string): Promise<void> {
    await this.page.goto(`/client/${sessionId}`);
  }

  async waitForConnection(timeout = 30_000): Promise<void> {
    await this.status.waitFor({ state: 'hidden', timeout });
  }

  async isDisconnected(): Promise<boolean> {
    return this.disconnectedOverlay.isVisible();
  }

  async dismissBanner(): Promise<void> {
    if (await this.bannerOverlay.isVisible()) {
      await this.bannerContinue.click();
    }
  }

  async reconnect(): Promise<void> {
    await this.btnReconnect.click();
  }

  async closeSession(): Promise<void> {
    await this.btnCloseSession.click();
  }
}
