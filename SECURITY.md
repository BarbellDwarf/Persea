# Security Policy

## Supported Versions

Security fixes are backported to the latest release and, where practical, the
previous minor release.

| Version | Supported |
|---------|-----------|
| 1.1.x   | ✅ Active |
| 1.0.x   | ⚠️ Security fixes only |
| < 1.0   | ❌ End of life |

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.** Report
them privately so they can be fixed before disclosure:

- **GitHub Security Advisories** — use the **"Report a vulnerability"**
  button at
  <https://github.com/persea-grove/persea/security/advisories/new>

When reporting, include:

1. The affected version(s) and how you obtained the build (Docker image tag,
   `.deb` version, or commit hash)
2. A description of the vulnerability and its impact
3. Steps to reproduce (config, deployment mode — bare metal vs Docker,
   TLS/self-signed, auth providers in use)
4. Any proof-of-concept or suggested fix, if available

You should receive an acknowledgement within **48 hours**. We aim to:

- Confirm the vulnerability and assess severity within **5 business days**
- Ship a fix in the next patch release, or within **30 days** for
  high/critical issues
- Coordinate public disclosure with you once a fix is released

If a reported issue is not reproducible or is a false positive, we will
explain why when closing the report.

## Scope

**In scope:**

- The persea server (`src/`): authentication and authorization, session
  handling, the Guacamole protocol bridge, credential storage
  (AES-256-GCM at rest, Vault integration), audit logging, web UI
  (`templates/`, `static/`)
- The Docker image and install scripts

**Out of scope:**

- Upstream dependencies: guacd (guacamole-server), Chromium, FreeRDP, Xvnc —
  report issues to their respective projects (we pin/rebuild them but do not
  maintain them)
- Deployment infrastructure (reverse proxies, networks, host OS) unless a
  persea default actively weakens it

## Security Model

The security-relevant design is documented in
[docs/security-hardening.md](docs/security-hardening.md) — TLS everywhere,
Argon2id password hashing, constant-time secret comparisons, fail-closed
authorization, CSRF double-submit protection, and SHA-256 hash-chain audit
logging. When reporting, familiarizing yourself with that document helps us
triage faster.

## Disclosure Policy

- Fixes ship in a patch release; the advisory is published once the fix is
  available
- Contributors who report valid vulnerabilities are credited in the advisory
  and changelog unless they prefer to remain anonymous
- We do not pay bounties at this time
