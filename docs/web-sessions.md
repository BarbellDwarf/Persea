# Web Browser Sessions

> **Audience:** admins enabling web browser sessions (domain allowlists, login scripts, clipboard control).
> **Next:** [Security](security-hardening.md#web-session-hardening) for hardening, or [Configuration](configuration.md#browser-session-settings) for the browser settings.

A web session is a full Chromium browser running **on the persea server**, streamed to the user's own browser through the same Guacamole pipeline used for SSH and RDP. The user sees and operates a real browser, a corporate portal, an internal web app, an IPMI console, without installing anything locally, and without the target site ever seeing the user's real machine.

This is useful for:

- **Controlled web access**: let operators reach specific internal web applications without exposing credentials or giving them network access
- **Credential isolation**: passwords and session cookies stay on the server, never reach the user's machine
- **Kiosk-style portals**: lock the browser to specific sites with domain allowlisting
- **Automated login**: a login script can fill in the login form for the user (see [Login scripts](#login-scripts))

## How it works

```
User's browser
    │
    │ WebSocket (Guacamole protocol)
    ▼
persea
    │
    │ Guacamole protocol (TCP/TLS)
    ▼
guacd
    │
    │ VNC to localhost
    ▼
Xvnc (virtual display :100–:199)
    │
    └── Chromium (kiosk mode, isolated profile)
            │
            └── https://target-app.example.com
```

1. persea picks a free X display number and starts Xvnc, a virtual monitor that exists only in memory
2. Chromium starts on that display with a fresh, isolated profile directory (`/tmp/persea-chromium-{uuid}`), so each session starts clean
3. If a login script is configured, a Chrome DevTools Protocol (CDP) port is allocated so the script can drive the browser
4. Chromium opens the configured URL
5. guacd connects to the Xvnc display over VNC and streams it to the user's browser
6. A login script, if any, runs to sign the user in
7. When the session ends, Chromium and Xvnc are stopped and the profile directory is deleted

## Prerequisites

- **Xvnc** and **Chromium** must be installed on the persea server. By default persea runs `Xvnc` and `chromium` from the system `PATH`; point them elsewhere with `xvnc_path` and `chromium_path` in the config if needed. `install.sh` and the Docker image install both.
- **Web sessions must be enabled**: the `enable_web_sessions` switch in **Admin → Settings** gates the feature (default: on). While it is off, web sessions are refused.
- **The target must be reachable**: by default web sessions may only connect to `localhost` (see [Network allowlist](#network-allowlist)). Add the networks your internal apps live on before trying to reach them.

## Starting a session

### From the Connections page

Create a connections entry with:

| Field | Value |
|-------|-------|
| Type | `web` |
| URL | `https://your-app.example.com` |

Add a username and password to the entry if you plan to use a login script or [URL placeholders](#url-placeholders).

### From the API

```bash
curl -X POST https://persea.example.com/api/sessions \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "session_type": "web",
    "url": "https://your-app.example.com",
    "width": 1920,
    "height": 1080
  }'
```

## Network allowlist

By default, web sessions can only connect to `localhost`. To allow external URLs, add the target networks to `web_allowed_networks`:

```toml
web_allowed_networks = ["10.0.0.0/8", "172.16.0.0/12"]
```

This is a server-side CIDR check (CIDR = a compact way of writing an IP range) applied when the session is created. The URL's hostname is resolved and the session is created only if at least one of the resolved IPs falls inside an allowed range. A hostname resolving to a mix of allowed and disallowed addresses passes: one match is enough. See [Domain allowlisting](#domain-allowlisting) for the separate, stricter control over which sites the user can visit inside the session.

## Domain allowlisting

A connections entry can restrict which websites the browser can reach. This is enforced **inside Chromium** via the `--host-rules` flag, which blocks DNS resolution for every domain except the ones you list.

- Set `allowed_domains` on the entry (via the address-book API; the Connections UI does not currently expose it).
- Subdomains are included automatically: adding `example.com` also allows `*.example.com`.
- `localhost` (`127.0.0.1`) is always allowed.

### Two layers of restriction

| Layer | Config | Applied | Scope |
|-------|--------|---------|-------|
| **`web_allowed_networks`** | `config.toml` (global) | Server-side, at session creation | CIDR ranges: which IPs persea will connect to |
| **`allowed_domains`** | Connections entry | Client-side, inside Chromium at runtime | Domain names: which sites the user can navigate to |

Both can be active at once for defence in depth. `web_allowed_networks` stops persea from initiating connections to networks it shouldn't reach (SSRF protection: it stops an attacker using the server as a proxy to internal systems). `allowed_domains` stops a user inside an already-running session from navigating anywhere outside the allowlist.

**Example:** the config allows `10.0.0.0/8` (server-side). A connections entry for the internal wiki sets `allowed_domains: ["wiki.internal.example.com"]`. The session can only reach the wiki, even though the server-side allowlist permits the whole `10.0.0.0/8` range.

## Login scripts

Some login flows cannot be handled by simple form filling: multi-step forms, CAPTCHAs, JavaScript-heavy single-page apps, MFA prompts. For these, persea can run a **login script**: a server-side executable that connects to the already-running Chromium and drives the login automatically, leaving the user on an authenticated page.

### How it works

1. The connections entry names a script, e.g. `portal-login.js`
2. When the session starts, Chromium is launched with a CDP port open (CDP = Chrome DevTools Protocol, the interface automation tools use to drive a browser)
3. Once Chromium is up, persea starts the script as a child process
4. The script connects to Chromium over CDP, performs the login, and exits
5. The user watches it happen live (it is all on the VNC display) and takes over

### What the script receives

The script gets these environment variables:

| Variable | Description |
|----------|-------------|
| `DISPLAY` | X display number (e.g. `:100`) |
| `RUSTGUAC_CDP_PORT` | Chrome DevTools Protocol port (e.g. `9200`) |
| `RUSTGUAC_URL` | Target URL |
| `RUSTGUAC_SESSION_ID` | Session UUID |

Credentials are **not** passed as environment variables: they arrive as JSON on **stdin**, which is more secure (environment variables are readable via `/proc/<pid>/environ` on Linux):

```json
{
  "username": "operator@example.com",
  "password": "secret",
  "url": "https://app.example.com",
  "cdp_port": 9200,
  "session_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Rules:**

- The script must live in `login_scripts_dir` (default: `/opt/persea/scripts`)
- It must be executable (`chmod +x`)
- Path traversal is blocked: the filename is validated against the scripts directory
- Scripts are killed after a timeout (default: 120 seconds, configurable via `login_script_timeout_secs`)
- Script failure is **not fatal**: the session continues and the user can log in manually

### Example: Playwright login script

This example uses [Playwright](https://playwright.dev/) to automate a login flow. It reads credentials from stdin, connects to the running Chromium, fills a login form, and disconnects.

```javascript
#!/usr/bin/env node
// login-example.js, Playwright login script for persea
//
// Install: npm install playwright-core  (in /opt/persea/scripts or globally)
// The script uses playwright-core (no bundled browsers) since Chromium is
// already running, it connects via CDP rather than launching a new browser.

'use strict';

const { chromium } = require('playwright-core');

// ── Read credentials from stdin (secure) ────────────────────────────

function readStdin() {
    return new Promise((resolve) => {
        const chunks = [];
        const timer = setTimeout(() => {
            process.stdin.destroy();
            resolve(chunks.join(''));
        }, 1000);
        process.stdin.setEncoding('utf8');
        process.stdin.on('data', (chunk) => chunks.push(chunk));
        process.stdin.on('end', () => { clearTimeout(timer); resolve(chunks.join('')); });
        process.stdin.on('error', () => { clearTimeout(timer); resolve(''); });
        process.stdin.resume();
    });
}

// ── Connect to Chromium CDP with retry ──────────────────────────────

async function connectCDP(port, timeoutMs = 15000) {
    const url = `http://127.0.0.1:${port}`;
    const deadline = Date.now() + timeoutMs;
    let lastErr;
    while (Date.now() < deadline) {
        try {
            return await chromium.connectOverCDP(url);
        } catch (e) {
            lastErr = e;
            await new Promise(r => setTimeout(r, 500));
        }
    }
    throw new Error(`CDP not ready on port ${port}: ${lastErr?.message}`);
}

// ── Main ────────────────────────────────────────────────────────────

async function main() {
    const stdinData = await readStdin();
    let creds;
    try {
        creds = JSON.parse(stdinData);
    } catch (e) {
        console.error('[login] Failed to parse stdin JSON');
        process.exit(1);
    }

    if (!creds.cdp_port) {
        console.error('[login] No CDP port, exiting');
        process.exit(1);
    }

    console.log(`[login] Connecting to CDP on port ${creds.cdp_port}...`);
    const browser = await connectCDP(creds.cdp_port);
    const page = browser.contexts()[0]?.pages()[0];
    if (!page) {
        console.error('[login] No page found');
        await browser.close();
        process.exit(1);
    }

    // Wait for the page to load (Chromium may still be navigating)
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 }).catch(() => {});

    // ── Automate your login flow here ───────────────────────────────
    //
    // This example fills a simple username/password form.
    // Adapt the selectors and steps for your target application.

    await page.fill('#username', creds.username);
    await page.fill('#password', creds.password);
    await page.click('button[type="submit"]');

    // Wait for navigation to confirm login succeeded
    try {
        await page.waitForURL('**/dashboard**', { timeout: 10000 });
        console.log('[login] Login successful');
    } catch {
        console.error('[login] Login may have failed, user can retry manually');
    }

    // Disconnect CDP, browser stays running for the user
    await browser.close();
}

main().catch((err) => {
    console.error(`[login] Error: ${err.message}`);
    process.exit(1);
});
```

**To use this script:**

1. Save it to `/opt/persea/scripts/login-example.js`
2. Make it executable: `chmod +x /opt/persea/scripts/login-example.js`
3. Install Playwright: `cd /opt/persea/scripts && npm install playwright-core`
4. Set the `login_script` field on a connections entry to `login-example.js`

### Configuration

| Config key | Default | Description |
|------------|---------|-------------|
| `login_scripts_dir` | `/opt/persea/scripts` | Directory containing login scripts |
| `login_script_timeout_secs` | `120` | Maximum script runtime before it's killed |
| `cdp_port_range_start` | `9200` | First CDP port in the allocation pool |
| `cdp_port_range_end` | `9299` | Last CDP port |

## Native autofill (disabled)

> **Status: disabled.** The `autofill` field is still accepted by the entry schema and API, but persea no longer writes credentials into Chromium's password store: the population step is a no-op and Chromium is launched with `--disable-autofill`. No login data is ever written to disk. For automated login, use [login scripts](#login-scripts).

Because the field is accepted for compatibility, entries may still carry it; it simply has no effect. The intended JSON shape, if you encounter it in existing data, is an array of credential objects:

```json
[
  {
    "url": "https://your-app.example.com",
    "username": "$USERNAME",
    "password": "$PASSWORD"
  }
]
```

The `$USERNAME` and `$PASSWORD` placeholders would be resolved server-side from the entry's credentials, and the result passed to the browser spawner, which then ignores it.

## URL placeholders

The entry URL supports credential placeholders that are URL-encoded and substituted before Chromium navigates:

```
https://app.example.com/login?user=$RUSTGUAC_USERNAME&pass=$RUSTGUAC_PASSWORD
```

| Placeholder | Substituted with |
|-------------|-----------------|
| `$RUSTGUAC_USERNAME` | Entry username (URL-encoded) |
| `$RUSTGUAC_PASSWORD` | Entry password (URL-encoded) |

Useful for applications that accept credentials as URL parameters (e.g. some IPMI/KVM web consoles).

## Clipboard control

Clipboard copy and paste can be disabled per connections entry. This uses guacd's native `disable-copy` and `disable-paste` parameters and works for all session types (SSH, RDP, VNC, Web):

| Field | Effect |
|-------|--------|
| `disable_copy` | Prevents server → client clipboard transfer (data loss prevention) |
| `disable_paste` | Prevents client → server clipboard transfer (prevents pasting malicious content) |

## In-session keyboard shortcuts

| Shortcut | Action | Notes |
|----------|--------|-------|
| `Ctrl+Alt+Shift` | Toggle the auto-hide toolbar (Paste, Fullscreen, Screenshot buttons) | Works globally on the session page, including when the remote display is focused |
| `F11` | Toggle fullscreen | Intercepted before it reaches the remote session |
| `Ctrl+V` (Windows/Linux) or `Cmd+V` (macOS) | Sync browser clipboard text to the remote session, then send paste | Works when clipboard API access is available |

Additional behaviour:

- `Esc` exits browser fullscreen natively (browser behaviour: not intercepted)
- The entry-level `fullscreen_on_connect` field opens the session fullscreen automatically
- All other keys pass through to the remote host
- `disable_copy` / `disable_paste` still apply regardless of local shortcuts

## SSH tunnels for web sessions

Web sessions support [multi-hop SSH tunnel chains](integrations.md#ssh-tunnels--multi-hop-jump-hosts) to reach targets on isolated networks. When jump hosts are configured:

1. An SSH tunnel chain is established through the bastion hosts
2. The final hop forwards to the URL's host and port
3. The URL is rewritten to `{scheme}://127.0.0.1:{tunnel_port}{path}` before being passed to Chromium

**Note:** HTTPS targets will show certificate warnings when tunnelled, because the hostname changes from the original to `127.0.0.1`. The original URL is still displayed in the session list.

## Chromium hardening

Every web session runs Chromium with a comprehensive managed policy and an isolated profile. See [Security: Web session hardening](security-hardening.md#session-level-controls) for the full policy table. Highlights:

- Downloads, printing, file dialogs, extensions, and DevTools UI are disabled
- Dangerous URL schemes (`file://`, `chrome://`, `javascript:`) are blocked
- Browser sign-in and sync are disabled
- Each session gets a fresh UUID-based profile directory, deleted on session end
- Chromium runs with its normal SUID sandbox: `--no-sandbox` is only appended when persea itself runs as root (e.g. local development); production installs (install.sh, Docker) run as the `persea` system user and keep the sandbox active

**Warning:** the managed policy is installed globally at `/etc/chromium/policies/managed/persea.json`. It affects **all** Chromium instances on the machine, not just persea sessions. Do not install persea on a desktop machine where you want to use Chromium for normal browsing: persea is designed to run on a dedicated server or VM.

## Display and port ranges

Each concurrent web session consumes one X display and, when a login script is configured, one CDP port. Both are allocated from ranges you can configure:

| Config key | Default | Purpose |
|------------|---------|---------|
| `display_range_start` / `display_range_end` | `100` / `199` | X display numbers (VNC port = display + 5900) |
| `cdp_port_range_start` / `cdp_port_range_end` | `9200` / `9299` | CDP ports for login scripts |

If a range is exhausted, session creation fails with "no X display numbers available" / "no CDP ports available". If you run more than one persea instance on the same host, keep the ranges disjoint (see [High Availability](high-availability.md#whats-supported--and-the-honest-limitations)).

## Troubleshooting

**Browser shows a blank/black screen:**
- Check the persea logs for Xvnc startup errors. persea waits up to 2 seconds for Xvnc to listen on its VNC port and logs Xvnc's stderr on failure.
- Verify `chromium_path` and `xvnc_path` point at valid binaries (defaults: `Xvnc`, `chromium` on the `PATH`).
- Ensure the `persea` system user has a real home directory (`/home/persea`): Chromium's crashpad handler crashes without one, and persea will log "Chromium exited immediately" with the reason.
- If Chromium exits within the first 500 ms, persea captures and logs its stderr: look for missing libraries or sandbox errors there.

**"Controlled by automated test software" banner:**
- Cosmetic. It appears when `allowed_domains` is set, because `--enable-automation` is used to suppress a different infobar about `--host-rules`. It does not affect functionality.

**Domain blocking is too strict:**
- Subdomains are automatically included: adding `example.com` allows `*.example.com`.
- CDN domains may need to be added separately (e.g. `cdn.example.com`, `fonts.googleapis.com`).
- If the browser shows "This site can't be reached", the domain is being blocked by `allowed_domains`.

**Login script doesn't run:**
- The script must be executable: `chmod +x /opt/persea/scripts/my-script.js`
- Check `login_scripts_dir` points at the right directory.
- Check persea logs for `[login-script]` messages: script stdout/stderr is captured.
- The script has a 120-second default timeout. Increase `login_script_timeout_secs` if the flow needs longer.

**Certificate errors when using SSH tunnels:**
- Expected. When tunnelling, the URL is rewritten to `127.0.0.1:{port}`, which won't match the target's TLS certificate. The user can click through the warning, or the target can be served over plain HTTP if the tunnel is trusted.

## API reference

### Create a web session

```
POST /api/sessions
```

```json
{
  "session_type": "web",
  "url": "https://app.example.com",
  "username": "operator",
  "password": "secret",
  "width": 1920,
  "height": 1080,
  "allowed_domains": ["app.example.com"],
  "login_script": "my-login.js",
  "disable_copy": false,
  "disable_paste": false
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `session_type` | string | Yes | Must be `"web"` |
| `url` | string | Yes | Target URL (`http://` or `https://`; other schemes are rejected) |
| `username` | string | No | Username for script/URL-placeholder substitution |
| `password` | string | No | Password for script/URL-placeholder substitution |
| `width` | integer | No | Browser width in pixels (default: 1920, range: 640–8192) |
| `height` | integer | No | Browser height in pixels (default: 1080, range: 480–8192) |
| `dpi` | integer | No | Display DPI (default: 96) |
| `autofill` | string | No | JSON array of autofill credentials: accepted for compatibility but currently has no effect |
| `allowed_domains` | array | No | Domain allowlist (see [Domain allowlisting](#domain-allowlisting)) |
| `login_script` | string | No | Script filename in `login_scripts_dir` |
| `disable_copy` | boolean | No | Disable clipboard copy (default: false) |
| `disable_paste` | boolean | No | Disable clipboard paste (default: false) |
| `jump_hosts` | array | No | SSH tunnel hops (see [SSH tunnels](#ssh-tunnels-for-web-sessions)) |

The same fields are available on connections entries (created via the Connections UI or the address-book API), plus `display_name` and `enable_recording`.
