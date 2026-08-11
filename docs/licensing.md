# Licensing

> **Audience:** operators and admins deciding between the free and Enterprise editions.
> **Next:** [Configuration](configuration.md) for the `license_key` option, or [COMMERCIAL_LICENSE.md](../COMMERCIAL_LICENSE.md) for the commercial license template.

persea ships in two versions: a **free, self-hosted** edition that runs without a license key, and an **Enterprise** edition whose features are unlocked by a commercial license key.

## The two versions

**Free (self-hosted)** — the open-source edition, licensed under AGPL-3.0. Runs without a license key. Includes all session types (SSH, RDP, VNC, SPICE, Proxmox VE, VMware, web, VDI), OIDC/LDAP/RADIUS authentication, API keys, Vault-backed connections, session recording, and more.

**Enterprise** — the free edition plus the enterprise features below, unlocked by a commercial license key (`PSEA-<base64>`).

## Enterprise features

| Feature | Description |
|---------|-------------|
| **SAML SSO** | SAML 2.0 service provider with signature verification |
| **Fine-grained RBAC** | Connection-level permissions and group inheritance beyond the 4-tier role system |
| **TOTP / MFA enforcement** | Mandatory two-factor authentication policies (AdminsOnly / All) |
| **Audit log retention and compliance exports** | Retention policies and compliance-oriented exports of the audit log |
| **Encrypted session recording** | Session recordings encrypted at rest |
| **High availability / clustering** | Multi-instance deployments behind a load balancer |

## 30-day evaluation period

Enterprise features are available without a license key for 30 days from first start (tracked via the `persea-eval` marker file). After the evaluation period, an Enterprise license key is required to continue using them.

## Obtaining a license

For an Enterprise license key, contact **licensing@persea.dev** or visit **https://persea.dev/licensing**. See [COMMERCIAL_LICENSE.md](../COMMERCIAL_LICENSE.md) for the commercial license template and terms.

## Installing a license key

Set the `license_key` option in the config file (top-level key, before any `[section]` header):

```toml
license_key = "PSEA-XXXX-XXXX-XXXX-XXXX"
```

Or via the `PERSEA_LICENSE_KEY` environment variable:

```bash
PERSEA_LICENSE_KEY=PSEA-XXXX-XXXX-XXXX-XXXX
```

Or through the admin UI: **Admin → License** (`/admin/license.html`). The license status is also available via the API at `/api/admin/license` (GET for status, POST to set a key).

## See also

- [COMMERCIAL_LICENSE.md](../COMMERCIAL_LICENSE.md) — commercial license template and terms
- [LICENSE](../LICENSE) — AGPL-3.0 full text
- [Configuration](configuration.md) — `license_key` option reference
