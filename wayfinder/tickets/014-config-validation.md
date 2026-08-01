# Ticket: Config Validation & Hardening

**Type:** research + task
**Labels:** config, wayfinder:research

## Question

What configuration validation improvements should be made?

### Findings:

**Missing validation at startup:**
- `listen_addr` / `guacd_addr` — not validated as `SocketAddr`, fails at bind/connect time
- CIDR allowlist entries (`ssh_allowed_networks`, etc.) — not parsed, invalid entries fail silently
- `display_range_start` vs `display_range_end` — no check that start < end
- `session_pending_timeout_secs` — no check > 0
- `max_disk_percent` — no check ≤ 100

**Config gaps:**
- `config.example.toml` missing ~10 documented config keys:
  - `session_history_retention_days`, `cdp_port_range_start/end`
  - `login_script_timeout_secs`, `login_scripts_dir`
  - `user_credentials_default_scope`, `rate_limit`
  - `vault_shared` / `vault_local` blocks
  - `[rdp]` section (partially documented)
  - `[vdi]` section (headline feature, not in example)
- `recording_path` vs `[recording].path` precedence is silent — no warning when both set

**Deprecated field handling:**
- `recording_path` marked `# DEPRECATED` but no runtime warning emitted

### Decision needed:

1. Validation scope: startup-fatal errors only, or warnings for suspicious configs?
2. Config example: add all missing fields, or just the most common ones?
3. Deprecated fields: emit tracing::warn at startup?
4. CIDR parsing: validate at startup with `ipnet` or `cidr` crate?
