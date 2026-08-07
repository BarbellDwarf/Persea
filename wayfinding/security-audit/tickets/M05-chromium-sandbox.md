# Ticket: Chromium runs with --no-sandbox when root

wayfinder:task
Priority: P2
Phase: Medium

## Finding

`src/browser.rs:320-331` — Chromium runs with `--no-sandbox` whenever the process is root. Relies entirely on the container boundary for isolation. A renderer RCE escalates directly to the host process if the container isn't otherwise hardened.

## Fix

1. **Run as non-root**: Create a dedicated `persea-browser` user in the Dockerfile. Run the browser session process as this user so Chromium's own sandbox stays active. The main persea process can still run as root (it needs to manage guacd), but the Chromium child is spawned via `Command::new("su").arg("-c").arg(...)` or `Command::new("gosu")`.
2. **Document container hardening**: If running as root is unavoidable, add seccomp/AppArmor profiles and document the required container hardening in `docs/deployment-guide.md`.

Option 1 is strongly preferred.

## Files

- `src/browser.rs:320-331` — sandbox decision
- `Dockerfile` — user creation

## Deliverable

Chromium runs as non-root user with sandbox active, OR container hardening documented. `cargo check` passes. VDI sessions still work.
