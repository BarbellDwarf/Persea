import { test, expect } from '@playwright/test';
import { SessionsPage } from '../../pages/SessionsPage';

test.describe('Sessions form validation', () => {
  let sessions: SessionsPage;

  test.beforeEach(async ({ page }) => {
    sessions = new SessionsPage(page);
    await page.goto('/');
    await page.evaluate((key) => {
      sessionStorage.setItem('rustguac_api_key', key);
    }, process.env.ADMIN_API_KEY || '');
    await page.goto('/sessions.html');
    await expect(sessions.sessionForm).toBeVisible();
    await sessions.toggleNewSession();
  });

  test('SSH form has correct default port', async () => {
    await expect(sessions.port).toHaveValue('22');
  });

  test('RDP form has correct default port', async () => {
    await sessions.selectSessionType('rdp');
    await expect(sessions.rdpPort).toHaveValue('3389');
  });

  test('VNC form has correct default port', async () => {
    await sessions.selectSessionType('vnc');
    await expect(sessions.vncPort).toHaveValue('5900');
  });

  test('generate keypair checkbox disables password', async () => {
    await sessions.generateKeypair.check();
    await expect(sessions.password).toBeDisabled();
    // Private key field should be hidden
    await expect(sessions.page.locator('#private-key-field')).toBeHidden();

    await sessions.generateKeypair.uncheck();
    await expect(sessions.password).toBeEnabled();
    await expect(sessions.page.locator('#private-key-field')).toBeVisible();
  });

  test('connect button is clickable', async () => {
    await expect(sessions.connectBtn).toBeEnabled();
    await expect(sessions.connectBtn).toHaveText('Connect');
  });

  test('SSH session submission sends correct payload', async ({ page }) => {
    // Intercept the POST request
    const requestPromise = page.waitForRequest('/api/sessions');
    await sessions.hostname.fill('10.0.0.1');
    await sessions.port.fill('22');
    await sessions.username.fill('testuser');
    await sessions.password.fill('testpass');
    await sessions.submitConnect();

    const request = await requestPromise;
    const body = JSON.parse(request.postData() || '{}');
    expect(body.session_type).toBe('ssh');
    expect(body.hostname).toBe('10.0.0.1');
    expect(body.port).toBe(22);
    expect(body.username).toBe('testuser');
    expect(body.password).toBe('testpass');
  });

  test('RDP session submission sends correct payload', async ({ page }) => {
    await sessions.selectSessionType('rdp');
    const requestPromise = page.waitForRequest('/api/sessions');
    await sessions.rdpHostname.fill('10.0.0.2');
    await sessions.rdpPort.fill('3389');
    await sessions.rdpUsername.fill('admin');
    await sessions.rdpPassword.fill('pass123');
    await sessions.submitConnect();

    const request = await requestPromise;
    const body = JSON.parse(request.postData() || '{}');
    expect(body.session_type).toBe('rdp');
    expect(body.hostname).toBe('10.0.0.2');
    expect(body.port).toBe(3389);
  });

  test('VDI session submission sends correct payload', async ({ page }) => {
    await sessions.selectSessionType('vdi');
    const requestPromise = page.waitForRequest('/api/sessions');
    await sessions.vdiImage.fill('myregistry/xrdp:latest');
    await sessions.submitConnect();

    const request = await requestPromise;
    const body = JSON.parse(request.postData() || '{}');
    expect(body.session_type).toBe('vdi');
    expect(body.container_image).toBe('myregistry/xrdp:latest');
  });

  test('jump section visibility toggles', async () => {
    // Jump section is hidden for VDI
    await sessions.selectSessionType('vdi');
    await expect(sessions.jumpSection).toBeHidden();

    // Jump section is visible for SSH
    await sessions.selectSessionType('ssh');
    await expect(sessions.jumpSection).toBeVisible();
  });

  test('add hop button creates hop card', async () => {
    // Jump section is only visible for non-VDI session types
    await sessions.selectSessionType('ssh');
    await expect(sessions.jumpSection).toBeVisible();
    // The jump fields (containing the add-hop-btn) are collapsed by default — expand them
    await sessions.page.click('#jump-toggle');
    await expect(sessions.page.locator('#jump-fields')).toBeVisible();
    await expect(sessions.page.locator('.hop-card')).toHaveCount(0);
    await sessions.addHopBtn.click();
    await expect(sessions.page.locator('.hop-card')).toHaveCount(1);
    await sessions.addHopBtn.click();
    await expect(sessions.page.locator('.hop-card')).toHaveCount(2);
  });
});
