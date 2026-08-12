# Licensing

> **Audience:** operators and admins deciding between the free and Enterprise editions.
> **Next:** [Configuration](configuration.md) for the `license_key` option, or [COMMERCIAL_LICENSE.md](../COMMERCIAL_LICENSE.md) for the commercial license template.

persea ships in two versions: a **free, self-hosted** edition that runs without a license key, and an **Enterprise** edition whose features are unlocked by a commercial license key.

## The two versions

**Free (self-hosted)** — the open-source edition, licensed under AGPL-3.0. Runs without a license key. Includes all session types (SSH, RDP, VNC, SPICE, Proxmox VE, VMware, web, VDI), OIDC/LDAP/RADIUS authentication, API keys, database-backed connections (Vault/OpenBao optional), session recording, and more.

**Enterprise** — the free edition plus the enterprise features below, unlocked by a commercial license key (`PSEA-<base64url-encoded JSON payload>`).

## Enterprise features

| Feature | Description |
|---------|-------------|
| **SAML SSO** | SAML 2.0 service provider with signature verification |
| **Fine-grained RBAC** | Connection-level permissions and group inheritance beyond the 4-tier role system |
| **TOTP / MFA enforcement** | Mandatory two-factor authentication policies (AdminsOnly / All) |
| **Audit log compliance exports** | Filtered CSV/JSON download of the audit log (basic audit viewing and tamper verification stay free) |
| **Encrypted session recording** | Session recordings encrypted at rest |
| **High availability (HA)** | Fleet-wide session sharing: live sessions are visible, joinable, and shadowable from any instance sharing one database (`ha` feature) |

The `ha` feature is gated by a dedicated flag in the license. It requires a
shared MySQL/PostgreSQL backend (`db_url`) on every instance, plus a unique
`instance_id` and `ha_base_url` per instance. See
[High Availability](high-availability.md) for what is and is not shareable
across instances.

## 30-day evaluation period

Enterprise features are available without a license key for 30 days from first start (tracked via the `persea-eval` marker file). After the evaluation period, an Enterprise license key is required to continue using them.

## Obtaining a license

For an Enterprise license key, contact **licensing@persea.dev** or visit **https://persea.dev/licensing**. See [COMMERCIAL_LICENSE.md](../COMMERCIAL_LICENSE.md) for the commercial license template and terms.

## Installing a license key

Set the `license_key` option in the config file (top-level key, before any `[section]` header):

```toml
license_key = "PSEA-XXXX-XXXX-XXXX-XXXX"
```

(The dashes are illustrative — real keys are a single base64url-encoded JSON payload after the `PSEA-` prefix.)

Or via the `PERSEA_LICENSE_KEY` environment variable:

```bash
PERSEA_LICENSE_KEY=PSEA-XXXX-XXXX-XXXX-XXXX
```

Or through the admin UI: **Admin → License** (`/admin/license.html`). The license status is also available via the API at `/api/admin/license` (GET for status, POST to set a key).

![License page in the admin UI](assets/screenshots/admin-license.png)

## See also

- [COMMERCIAL_LICENSE.md](../COMMERCIAL_LICENSE.md) — commercial license template and terms
- [LICENSE](../LICENSE) — AGPL-3.0 full text
- [Configuration](configuration.md) — `license_key` option reference
