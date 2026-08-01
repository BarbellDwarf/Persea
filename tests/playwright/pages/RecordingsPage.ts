import type { Page, Locator } from '@playwright/test';
import { RECORDINGS_PAGE as S } from '../fixtures/selectors';

export class RecordingsPage {
  readonly page: Page;

  // Nav
  readonly navConnections: Locator;
  readonly navSessions: Locator;
  readonly navRecordings: Locator;
  readonly navAdmin: Locator;

  // Player
  readonly playerSection: Locator;
  readonly playerTitle: Locator;
  readonly playerClose: Locator;
  readonly playerDisplay: Locator;
  readonly playBtn: Locator;
  readonly seekSlider: Locator;
  readonly playerTime: Locator;

  // List
  readonly recSearch: Locator;
  readonly recordingList: Locator;
  readonly recPagination: Locator;

  // Typescripts
  readonly typescriptSection: Locator;
  readonly typescriptList: Locator;
  readonly typescriptPagination: Locator;

  constructor(page: Page) {
    this.page = page;

    this.navConnections = page.locator(S.navConnections);
    this.navSessions = page.locator(S.navSessions);
    this.navRecordings = page.locator(S.navRecordings);
    this.navAdmin = page.locator(S.navAdmin);

    this.playerSection = page.locator(S.playerSection);
    this.playerTitle = page.locator(S.playerTitle);
    this.playerClose = page.locator(S.playerClose);
    this.playerDisplay = page.locator(S.playerDisplay);
    this.playBtn = page.locator(S.playBtn);
    this.seekSlider = page.locator(S.seekSlider);
    this.playerTime = page.locator(S.playerTime);

    this.recSearch = page.locator(S.recSearch);
    this.recordingList = page.locator(S.recordingList);
    this.recPagination = page.locator(S.recPagination);

    this.typescriptSection = page.locator(S.typescriptSection);
    this.typescriptList = page.locator(S.typescriptList);
    this.typescriptPagination = page.locator(S.typescriptPagination);
  }

  async goto(): Promise<void> {
    await this.page.goto('/');
    await this.page.evaluate((key) => {
      sessionStorage.setItem('rustguac_api_key', key);
    }, process.env.ADMIN_API_KEY || '');
    await this.page.goto('/recordings.html');
  }

  async isPlayerVisible(): Promise<boolean> {
    return this.playerSection.isVisible();
  }

  async searchRecordings(query: string): Promise<void> {
    await this.recSearch.fill(query);
  }

  async getRecordingRowCount(): Promise<number> {
    return this.page.locator(`${S.recordingList} tbody tr`).count();
  }

  async playFirstRecording(): Promise<void> {
    const playBtn = this.page.locator(`${S.recordingList} button[data-play]`).first();
    await playBtn.click();
    await this.playerSection.waitFor({ state: 'visible' });
  }

  async closePlayer(): Promise<void> {
    await this.playerClose.click();
    await this.playerSection.waitFor({ state: 'hidden' });
  }

  async isTypescriptSectionVisible(): Promise<boolean> {
    return this.typescriptSection.isVisible();
  }
}
