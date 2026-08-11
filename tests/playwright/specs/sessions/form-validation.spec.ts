import { test, expect } from '@playwright/test';
test.use({ storageState: '.auth/user.json' });
import { SessionsPage } from '../../pages/SessionsPage';

test.describe('Sessions form validation', () => {
  let sessions: SessionsPage;

  test.beforeEach(async ({ page }) => {
    sessions = new SessionsPage(page);
    await sessions.goto();
    // The form starts hidden — it is revealed via the "+ New Session" button,
    // which appears once the /api/me role check resolves for admin/poweruser.
    await expect(sessions.newSessionBtn).toBeVisible();
    await sessions.openNewSession();
    await expect(sessions.newSessionFields).toBeVisible();
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

  test('SSH connect shows validation error when host is empty', async () => {
    await sessions.submitConnect();
    await expect(sessions.error).toBeVisible();
    await expect(sessions.error).toHaveText(/Host is required/);
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
});
