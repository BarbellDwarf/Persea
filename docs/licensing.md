# Licensing

> **Audience:** operators and admins deciding between the free and Enterprise editions.
> **Next:** [Configuration](configuration.md) for the `license_key` option, or [COMMERCIAL_LICENSE.md](../COMMERCIAL_LICENSE.md) for the commercial license template.

persea ships in two editions: a **free, self-hosted** edition that runs
without a license key, and an **Enterprise** edition whose extra
features are unlocked by a commercial license key (format
`PSEA-<base64>` — the part after `PSEA-` is a base64url-encoded JSON
payload containing a signature, customer name, expiry date, and the
enabled feature flags).

## The two editions

**Free (self-hosted)** — the open-source edition, licensed under
AGPL-3.0. Runs without a license key. Includes all session types (SSH,
RDP, VNC, SPICE, Proxmox VE, VMware, web, VDI), OIDC/LDAP/RADIUS
authentication, API keys, database-backed connections (Vault/OpenBao
optional), session recording, and more.

**Enterprise** — everything in the free edition plus the features
below, unlocked by a commercial license key.

## Enterprise features

| Feature | What it unlocks |
|---------|-----------------|
| **SAML SSO** | SAML 2.0 single sign-on with signature verification |
| **Fine-grained RBAC** | Connection-level permissions and group inheritance beyond the 4-tier role system |
| **TOTP / MFA enforcement** | Mandatory two-factor authentication policies (`AdminsOnly` / `All`) |
| **Audit log compliance exports** | Filtered CSV/JSON download of the audit log (basic audit viewing and tamper verification stay free) |
| **Encrypted session recording** | Session recordings encrypted at rest |
| **High availability (HA)** | Fleet-wide session sharing: live sessions are visible, joinable and shadowable from any instance sharing one database |

The `ha` feature is gated by a dedicated flag in the license. It
requires a shared MySQL/PostgreSQL backend (`db_url`) on every
instance, plus a unique `instance_id` and `ha_base_url` per instance.
See [High Availability](high-availability.md) for what is and is not
shareable across instances.

## Evaluation period

Enterprise features are available without a license key for **30 days
from first start** (tracked via the `persea-eval` marker file). The
license page shows your remaining days; after the evaluation period
ends, an Enterprise license key is required to keep using the features.

## What happens without a license key

The license status is one of four states, shown on the license page:

| Status | Meaning |
|--------|---------|
| **Evaluating** | No key set, within the 30-day evaluation — all enterprise features enabled, with days remaining shown |
| **No License** | No key set and the evaluation period has ended — enterprise features are locked |
| **Valid** | A key is installed and unexpired — features listed in the key are enabled |
| **Expired** | A key is installed but its expiry date has passed — features are locked until it is renewed |

Without a license, enterprise features are simply unavailable: the
license page lists each one with a **Locked** badge, and their
endpoints refuse with a license error (for example, the audit-log
export returns "audit log export requires an enterprise license"). The
free edition keeps working normally.

## Obtaining a license

For an Enterprise license key, contact **licensing@persea.dev** or
visit **https://persea.dev/licensing**. See
[COMMERCIAL_LICENSE.md](../COMMERCIAL_LICENSE.md) for the commercial
license template and terms.

## Installing a license key

There are three ways, all equivalent:

**1. Config file** — set the `license_key` option (a top-level key,
before any `[section]` header):

```toml
license_key = "PSEA-XXXX-XXXX-XXXX-XXXX"
```

**2. Environment variable:**

```bash
PERSEA_LICENSE_KEY=PSEA-XXXX-XXXX-XXXX-XXXX
```

**3. Admin UI** — go to **Admin → License** (`/admin/license.html`),
paste the key into the *Update License Key* form, and click **Validate
& Save**. The page shows the current status, customer name and expiry,
and which enterprise features are enabled or locked:

![License page in the admin UI](assets/screenshots/admin-license.png)

The license status is also available via the API — `GET
/api/admin/license` for status, `POST /api/admin/license` with
`{"license_key": "PSEA-..."}` to set a key.

*How to check it worked:* the license page badge should read **Valid**
with your customer name and expiry date, and the enterprise features
you licensed should show **Enabled**. In the API:
`curl -s -H "Authorization: Bearer $API_KEY" /api/admin/license`.

## See also

- [COMMERCIAL_LICENSE.md](../COMMERCIAL_LICENSE.md) — commercial license template and terms
- [LICENSE](../LICENSE) — AGPL-3.0 full text
- [Configuration](configuration.md) — `license_key` option reference
