import type { Page, Locator } from '@playwright/test';
import { CONNECTIONS_PAGE as S } from '../fixtures/selectors';

export class ConnectionsPage {
  readonly page: Page;

  // Nav
  readonly navConnections: Locator;
  readonly navSessions: Locator;
  readonly navAdmin: Locator;
  readonly navTokens: Locator;

  // Layout
  readonly mainContent: Locator;
  readonly noVault: Locator;
  readonly vaultUnavailable: Locator;
  readonly emptyState: Locator;
  readonly btnEmptyCreateFolder: Locator;

  // Sidebar
  readonly folderList: Locator;
  readonly btnNewFolder: Locator;

  // Main
  readonly entriesTitle: Locator;
  readonly entriesContent: Locator;
  readonly connectionsSearch: Locator;
  readonly btnNewEntry: Locator;
  readonly btnNewSubfolder: Locator;
  readonly btnEditFolder: Locator;
  readonly btnDeleteFolder: Locator;

  // Active sessions
  readonly activeSessions: Locator;
  readonly activeSessionsGrid: Locator;

  // Folder modal
  readonly folderModal: Locator;
  readonly fmName: Locator;
  readonly fmDesc: Locator;
  readonly fmScope: Locator;
  readonly fmSave: Locator;
  readonly fmCancel: Locator;
  readonly fmError: Locator;

  // Entry modal
  readonly entryModal: Locator;
  readonly emName: Locator;
  readonly emDisplayName: Locator;
  readonly emType: Locator;
  readonly emHostname: Locator;
  readonly emPort: Locator;
  readonly emUsername: Locator;
  readonly emPassword: Locator;
  readonly emSave: Locator;
  readonly emCancel: Locator;
  readonly emError: Locator;

  constructor(page: Page) {
    this.page = page;

    this.navConnections = page.locator(S.navConnections);
    this.navSessions = page.locator(S.navSessions);
    this.navAdmin = page.locator(S.navAdmin);
    this.navTokens = page.locator(S.navTokens);

    this.mainContent = page.locator(S.mainContent);
    this.noVault = page.locator(S.noVault);
    this.vaultUnavailable = page.locator(S.vaultUnavailable);
    this.emptyState = page.locator(S.emptyState);
    this.btnEmptyCreateFolder = page.locator(S.btnEmptyCreateFolder);

    this.folderList = page.locator(S.folderList);
    this.btnNewFolder = page.locator(S.btnNewFolder);

    this.entriesTitle = page.locator(S.entriesTitle);
    this.entriesContent = page.locator(S.entriesContent);
    this.connectionsSearch = page.locator(S.connectionsSearch);
    this.btnNewEntry = page.locator(S.btnNewEntry);
    this.btnNewSubfolder = page.locator(S.btnNewSubfolder);
    this.btnEditFolder = page.locator(S.btnEditFolder);
    this.btnDeleteFolder = page.locator(S.btnDeleteFolder);

    this.activeSessions = page.locator(S.activeSessions);
    this.activeSessionsGrid = page.locator(S.activeSessionsGrid);

    this.folderModal = page.locator(S.folderModal);
    this.fmName = page.locator(S.fmName);
    this.fmDesc = page.locator(S.fmDesc);
    this.fmScope = page.locator(S.fmScope);
    this.fmSave = page.locator(S.fmSave);
    this.fmCancel = page.locator(S.fmCancel);
    this.fmError = page.locator(S.fmError);

    this.entryModal = page.locator(S.entryModal);
    this.emName = page.locator(S.emName);
    this.emDisplayName = page.locator(S.emDisplayName);
    this.emType = page.locator(S.emType);
    this.emHostname = page.locator(S.emHostname);
    this.emPort = page.locator(S.emPort);
    this.emUsername = page.locator(S.emUsername);
    this.emPassword = page.locator(S.emPassword);
    this.emSave = page.locator(S.emSave);
    this.emCancel = page.locator(S.emCancel);
    this.emError = page.locator(S.emError);
  }

  async goto(): Promise<void> {
    await this.page.goto('/');
    await this.page.evaluate((key) => {
      sessionStorage.setItem('rustguac_api_key', key);
    }, process.env.ADMIN_API_KEY || '');
    await this.page.goto('/connections.html');
  }

  async getFolderCount(): Promise<number> {
    return this.page.locator(`${S.folderList} > li`).count();
  }

  async selectFolder(index: number): Promise<void> {
    await this.page.locator(`${S.folderList} > li`).nth(index).click();
  }

  async openNewFolderModal(): Promise<void> {
    await this.btnNewFolder.click();
    await this.folderModal.waitFor({ state: 'visible' });
  }

  async createFolder(name: string, desc?: string): Promise<void> {
    await this.openNewFolderModal();
    await this.fmName.fill(name);
    if (desc) await this.fmDesc.fill(desc);
    await this.fmSave.click();
    await this.folderModal.waitFor({ state: 'hidden' });
  }

  async openNewEntryModal(): Promise<void> {
    await this.btnNewEntry.click();
    await this.entryModal.waitFor({ state: 'visible' });
  }

  async selectEntryType(type: string): Promise<void> {
    await this.emType.selectOption(type);
  }

  async hasVaultNotConfigured(): Promise<boolean> {
    return this.noVault.isVisible();
  }

  async hasVaultUnavailable(): Promise<boolean> {
    return this.vaultUnavailable.isVisible();
  }

  async hasMainContent(): Promise<boolean> {
    return this.mainContent.isVisible();
  }

  async hasEmptyState(): Promise<boolean> {
    return this.emptyState.isVisible();
  }

  async hasActiveSessions(): Promise<boolean> {
    return this.activeSessions.isVisible();
  }
}
