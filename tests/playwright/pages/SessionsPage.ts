import type { Page, Locator } from '@playwright/test';
import { SESSIONS_PAGE as S } from '../fixtures/selectors';

export class SessionsPage {
  readonly page: Page;

  // Nav
  readonly navConnections: Locator;
  readonly navSessions: Locator;
  readonly navRecordings: Locator;
  readonly navAdmin: Locator;
  readonly navTokens: Locator;
  readonly navReports: Locator;
  readonly navLogout: Locator;

  // Form
  readonly sessionForm: Locator;
  readonly newSessionToggle: Locator;
  readonly newSessionFields: Locator;
  readonly sessionType: Locator;
  readonly connectBtn: Locator;
  readonly error: Locator;

  // SSH
  readonly hostname: Locator;
  readonly port: Locator;
  readonly username: Locator;
  readonly password: Locator;
  readonly generateKeypair: Locator;

  // RDP
  readonly rdpHostname: Locator;
  readonly rdpPort: Locator;
  readonly rdpUsername: Locator;
  readonly rdpPassword: Locator;

  // VNC
  readonly vncHostname: Locator;
  readonly vncPort: Locator;

  // Web
  readonly url: Locator;

  // VDI
  readonly vdiImage: Locator;

  // Jump hosts
  readonly jumpSection: Locator;
  readonly addHopBtn: Locator;

  // Session list
  readonly sessionList: Locator;
  readonly sessionEmpty: Locator;
  readonly sessionCounts: Locator;

  constructor(page: Page) {
    this.page = page;

    this.navConnections = page.locator(S.navConnections);
    this.navSessions = page.locator(S.navSessions);
    this.navRecordings = page.locator(S.navRecordings);
    this.navAdmin = page.locator(S.navAdmin);
    this.navTokens = page.locator(S.navTokens);
    this.navReports = page.locator(S.navReports);
    this.navLogout = page.locator(S.navLogout);

    this.sessionForm = page.locator(S.sessionForm);
    this.newSessionToggle = page.locator(S.newSessionToggle);
    this.newSessionFields = page.locator(S.newSessionFields);
    this.sessionType = page.locator(S.sessionType);
    this.connectBtn = page.locator(S.connectBtn);
    this.error = page.locator(S.error);

    this.hostname = page.locator(S.hostname);
    this.port = page.locator(S.port);
    this.username = page.locator(S.username);
    this.password = page.locator(S.password);
    this.generateKeypair = page.locator(S.generateKeypair);

    this.rdpHostname = page.locator(S.rdpHostname);
    this.rdpPort = page.locator(S.rdpPort);
    this.rdpUsername = page.locator(S.rdpUsername);
    this.rdpPassword = page.locator(S.rdpPassword);

    this.vncHostname = page.locator(S.vncHostname);
    this.vncPort = page.locator(S.vncPort);

    this.url = page.locator(S.url);

    this.vdiImage = page.locator(S.vdiImage);

    this.jumpSection = page.locator(S.jumpSection);
    this.addHopBtn = page.locator(S.addHopBtn);

    this.sessionList = page.locator(S.sessionList);
    this.sessionEmpty = page.locator(S.sessionEmpty);
    this.sessionCounts = page.locator(S.sessionCounts);
  }

  async goto(): Promise<void> {
    await this.page.goto('/');
    await this.page.evaluate((key) => {
      sessionStorage.setItem('persea_api_key', key);
    }, process.env.ADMIN_API_KEY || '');
    await this.page.goto('/sessions.html');
  }

  async selectSessionType(type: 'ssh' | 'rdp' | 'vnc' | 'web' | 'vdi'): Promise<void> {
    await this.sessionType.selectOption(type);
  }

  async toggleNewSession(): Promise<void> {
    await this.newSessionToggle.click();
  }

  async isFormVisible(): Promise<boolean> {
    return this.sessionForm.isVisible();
  }

  async isFieldTypeVisible(type: 'ssh' | 'rdp' | 'vnc' | 'web' | 'vdi'): Promise<boolean> {
    const fieldMap: Record<string, Locator> = {
      ssh: this.page.locator(S.sshFields),
      rdp: this.page.locator(S.rdpFields),
      vnc: this.page.locator(S.vncFields),
      web: this.page.locator(S.webFields),
      vdi: this.page.locator(S.vdiFields),
    };
    return fieldMap[type].isVisible();
  }

  async fillSshSession(host: string, port = 22, user?: string, pass?: string): Promise<void> {
    await this.hostname.fill(host);
    await this.port.fill(String(port));
    if (user) await this.username.fill(user);
    if (pass) await this.password.fill(pass);
  }

  async fillRdpSession(host: string, port = 3389, user?: string, pass?: string): Promise<void> {
    await this.rdpHostname.fill(host);
    await this.rdpPort.fill(String(port));
    if (user) await this.rdpUsername.fill(user);
    if (pass) await this.rdpPassword.fill(pass);
  }

  async fillVncSession(host: string, port = 5900): Promise<void> {
    await this.vncHostname.fill(host);
    await this.vncPort.fill(String(port));
  }

  async fillWebSession(url: string): Promise<void> {
    await this.url.fill(url);
  }

  async fillVdiSession(image: string): Promise<void> {
    await this.vdiImage.fill(image);
  }

  async submitConnect(): Promise<void> {
    await this.connectBtn.click();
  }

  async getSessionRows(): Promise<number> {
    return this.page.locator(`${S.sessionList} tr`).count();
  }

  async hasEmptyState(): Promise<boolean> {
    return this.sessionEmpty.isVisible();
  }
}
