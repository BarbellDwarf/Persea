# Overview

## What persea is

persea is a web-based remote-access gateway. It lets people open SSH terminals, RDP desktops, VNC screens, SPICE consoles, and web-browser sessions straight from their own browser: no client software to install on their machine. It is a lightweight replacement for the Apache Guacamole web application, built as a single Rust program instead of a Java webapp running on Tomcat.

It handles the web side of remote access:

- the login page and user accounts,
- the list of saved connections (an "address book" of servers, desktops, and consoles),
- starting, watching, and ending remote sessions,
- recording sessions for later playback,
- sharing a live session with other people,
- permissions: who is allowed to see and connect to what,
- an audit log of who did what and when.

## The two moving parts

persea is not one program. It is two, working together:

**persea** (the program this repo builds) is the web server. It talks to the browser over HTTPS and a WebSocket, a two-way connection a web page can keep open for a long time, which is how keystrokes and screen updates keep flowing. It also holds the user accounts, the address book, and the recordings.

**guacd** (pronounced "gua-see-dee") is the protocol translator. It is the same daemon Apache Guacamole uses, built from [guacamole-server](https://github.com/apache/guacamole-server). persea does not understand SSH or RDP itself: it sends instructions to guacd, and guacd does the actual connecting: it speaks SSH to your Linux boxes, RDP to your Windows machines, VNC to your KVM consoles, and so on. Everything guacd receives and sends flows through persea in a format called the **Guacamole protocol** (the same wire format Apache Guacamole uses, so recordings and the client are compatible).

```
Your browser ──HTTPS/WebSocket──▶ persea ──Guacamole protocol──▶ guacd ──SSH/RDP/VNC/...──▶ target machines
```

When you click "connect" on a connection entry, this happens:

1. persea checks you are allowed to use that connection (and that the session limits aren't full).
2. persea asks guacd to start a session of the right type, passing it the hostname, port, and stored credentials.
3. guacd opens the connection to the target machine.
4. Your browser connects to persea over a WebSocket; persea pipes the Guacamole protocol between you and guacd. Keystrokes go one way, screen updates come back the other, and persea can record the traffic, enforce idle timeouts, and let other people join.

## What you can do with it

**Connect to nearly anything.** Session types:

- **SSH**: a terminal into a Linux/Unix server, with password, private key, or a throwaway key generated per session. SFTP file transfer works straight from the browser.
- **RDP**: a full Windows desktop (or Linux desktop served by xrdp), including shared clipboard, audio, and file transfer through a virtual drive.
- **VNC**: any machine already running a VNC server, such as KVM/IPMI consoles or VM displays.
- **SPICE**: consoles on hosts that speak SPICE (a QEMU/KVM display protocol).
- **Proxmox VE**: virtual machines and LXC containers on a Proxmox host: SPICE or VNC consoles, and serial consoles.
- **VMware vSphere**: browse the vCenter inventory and connect to VMs; persea picks RDP for Windows guests, SSH for Linux guests, and VNC otherwise.
- **Web browser sessions**: persea launches a real Chromium browser on a virtual display (Xvnc) on the server and streams its screen to the user. Useful for sites that block automation or for letting users browse a trusted network from a locked-down browser.
- **VDI desktops**: persea starts an ephemeral Docker container running a Linux desktop (xrdp) per user and connects to it over RDP. Handy for on-demand disposable desktops without any VM infrastructure.

**Manage who can do what.** Users sign in with a local account, or with single sign-on (OIDC, SAML, LDAP, RADIUS; a second-factor app code can be required on top). There are four roles: viewer, operator, poweruser, admin, and admins can also grant or deny access per individual connection or folder, with permissions inherited down the folder tree. Sign-ins from your SSO directory groups can be mapped to roles automatically.

**Keep records.** Every session can be recorded and replayed in the browser later. A tamper-evident audit log records logins, session starts and ends, and admin actions.

**Reach isolated networks.** Connections can be routed through one or more SSH bastion hosts ("jump hosts"), so you can reach machines that are not directly on the network the server sits on.

## Running it

There are two supported ways to run persea:

- **On a Debian 13 server**: either the prebuilt `.deb` package or `sudo ./install.sh`, which builds everything from source. You get systemd services for persea and guacd, plus Xvnc and Chromium for web browser sessions.
- **In Docker**: a single image containing persea, guacd, FreeRDP, and everything else. This is the recommended path on any distribution other than Debian 13, because the FreeRDP libraries are bundled and can't clash with the host's versions.

Both paths end the same way: the first time you open the web interface, a setup wizard asks for an admin account and a few basics, and after that you log in, add connections, and connect.

A small installation runs everything on one machine: persea, guacd, and even the targets can share a host. For bigger installations, guacd is the part that uses memory (roughly 150 MB per RDP session), so it can be moved to its own machine and scaled separately.

## Ports

| Port | Service |
|------|---------|
| 8089 | persea web interface (HTTPS with a self-signed cert out of the box) |
| 4822 | guacd: protocol daemon, loopback only |
| 6100–6199 | Xvnc virtual displays for web browser sessions, loopback only |

## Where to go next

- [Installation](installation.md): requirements, install options, and the first-run setup wizard.
- [Deployment Guide](deployment-guide.md): the full production walkthrough: reverse proxy, sign-in, connections, recording, backups, updates.
- [Troubleshooting](troubleshooting.md): what to do when something doesn't work.

Other guides in this documentation set:

- [Configuration](configuration.md): every setting in `config.toml`, with defaults.
- [Roles and Access Control](roles-and-access-control.md): roles, connection permissions, SSO group mappings.
- [Integrations](integrations.md): OIDC, Vault, SSH tunnels, Kerberos, drive/LUKS, HAProxy, Knocknoc.
- [Web Browser Sessions](web-sessions.md): autofill, domain restrictions, login scripts.
- [VDI Desktop Containers](vdi.md): configuring Docker desktop sessions.
- [Security Hardening](security-hardening.md): TLS, allowlists, headers, CSRF, rate limiting, audit.
- [API Reference](api.md): the REST API, health checks, and metrics.
- [Reports](reports.md), [Themes](themes.md), [Credential Variables](credential-variables.md), [RDP Video Performance](rdp-video-performance.md), [Reverse Proxies](reverse-proxies.md), [NetBox](netbox.md), [High Availability](high-availability.md).
