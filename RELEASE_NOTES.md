# persea v1.0.1

persea v1.0.1 is the first maintenance release: a full security and correctness pass over v1.0.0, new deployment documentation, and the new brand identity.

## Highlights

- **Authentication repaired**: TOTP MFA login actually works now (it was broken by the CSP/CSRF combination), SAML SSO works and has replay protection, and MFA enforcement can no longer be skipped by simply never enrolling.
- **Access control closed**: quick-connect, folder ACL inheritance, and entry-level restrictions no longer have bypasses; shadow (view-only) viewers can no longer transfer files out of a monitored session.
- **Secrets handled properly**: packages generate a unique storage encryption key at install time, the server refuses to start without one (fail closed), and config + database files are no longer world-readable.
- **Deployment docs**: runnable Docker Compose examples for SQLite/PostgreSQL/MySQL, a complete nginx reverse-proxy config, and a guided Let's Encrypt setup.
- **New logo** across the web UI.

## New

- New logo: login page, favicons, and the live state-dot variant; inline login/sidebar art updated.
- `docs/examples/`: Docker Compose for SQLite, PostgreSQL, and MySQL backends; a full `nginx.conf` (TLS termination, WebSocket upgrade headers, HSTS); a Let's Encrypt guide with a SIGHUP renew hook that uses persea's TLS hot-reload.
- Storage encryption key auto-generation in `install.sh`, the Docker entrypoint, and the deb/RPM post-install scripts (TOML-aware, unique per install).

## Fixed

- TOTP MFA login was impossible: the page script was blocked by CSP and the fallback POST failed CSRF. Enrollment modes (AdminsOnly/All) are now enforced, and no session is minted before a verified factor.
- SAML SSO was dead: the ACS endpoint rejected every IdP POST. Now rate-limited, replay-protected, and strict-mode validated (audience, NotOnOrAfter, Recipient); the deflate-bomb decompression is capped.
- Address-book ACL bypasses: quick-connect skipped entry ACLs and RBAC Connect grants; child folders under restricted parents opened up; database-provider users were denied everything; RBAC folder Connect grants now cascade to subfolders.
- Session takeover: any operator could take over another user's pending/disconnected session; ownership is now keyed on the stable identity, not the display name.
- Shadow viewers could type into and transfer files from monitored sessions; they are now read-only at both the filter and guacd join level.
- Browser-session SSRF block was inverted: localhost and cloud-metadata were reachable from web sessions; they are now always blocked.
- VDI: home bind-mount path traversal and container-name collisions across users are closed.
- Recordings: owner reconnect destroyed the previous segment (now appended); playback streamed whole files into RAM (now bounded); the streaming decrypt verifies the GCM tag before releasing plaintext.
- XSS and injection: stored XSS in the audit fragment, unescaped template reflections (autoescape now on), audit CSV formula injection, and the connection-details panel showing raw backend enum values.
- Protocol framing counted bytes where guacd counts characters, breaking non-ASCII connect arguments.
- Drive uploads: slowloris body streams (now idle-timed) and a symlink-swap write (O_NOFOLLOW + fd verification).
- Stale `tailwind.min.css` that was missing classes current templates use.

## Changed

- **Storage key required**: the server refuses to start with the DB backend and no `[storage].encryption_key` / `PERSEA_STORAGE_KEY`. Existing installs must add a key (see the deployment guide); new installs generate one automatically.
- Session targets default to loopback-only (previously RFC1918 space).
- `/api/connect` and `/auth/logout` are POST-only; logout is CSRF-protected.
- Cross-user reports/recordings exports are admin-only; powerusers see their own sessions.
- `/admin/*` page shells require the admin role; `/metrics` and `/api/docs` are admin-only.
- Folder ACL inheritance defaults to on for API-created folders.
- VDI container names carry a per-user hash; jump-host chains are capped at 8 hops.
- GitHub Actions bumped (setup-node v7, create-pull-request v8); CI boot steps supply the storage key.
- Dependencies: `config` 0.15.25, `tokio-tungstenite` 0.30, `thiserror` 2.0.20, `async-trait` 0.1.92.

## Security

The fixes above close: SAML replay and deflate-bomb denial of service, shadow-viewer file exfiltration, folder ACL and quick-connect bypasses, session hijacking, stored XSS and CSV injection, an inverted SSRF block, VDI path traversal, plaintext credential fallbacks, LDAP user enumeration, non-constant-time comparisons, OIDC fingerprint spoofing via forwarded headers, open redirects via backslash paths, and world-readable config/DB files holding the encryption key.

## Install / Upgrade

- **New installs**: `install.sh`, the Docker entrypoint, and the deb/RPM post-install scripts generate a storage key automatically. Nothing extra to do.
- **Upgrades from 1.0.0**: add a storage key before starting the new version:

  ```
  KEY=$(openssl rand -hex 32)
  # add to /opt/persea/config.toml:
  # [storage]
  # encryption_key = "<KEY>"
  ```

- The desktop shell and server remain compatible; the desktop e2e provisioning pin is removed once its provision script supplies a key (persea-desktop#15).
