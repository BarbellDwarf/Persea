# High Availability Architecture

## Overview

Persea runs as a single Rust/Axum binary with guacd as a separate C process.
The architecture separates stateless request handling from stateful session
management. With a shared backend (`db_url`) and the enterprise HA feature
licensed, multiple instances form a real cluster: live sessions are visible,
joinable, and shadowable from any instance. Without the license (or without
`db_url`), behavior is byte-for-byte the single-instance mode.

## What R110 implements (the real, working topology)

Enterprise HA (feature `ha` — included in the 30-day evaluation period) is
built from four cooperating parts, all gated on `FEAT_HA` + a configured
`db_url` pool:

### 1. Shared session registry (`session_registry` table)

Every live session mirrors into the shared backend the moment it is created
(owner instance, owner base URL, type, status, hostname, username, creator,
timestamps, guacd connection id). The in-memory `SessionManager` map remains
the fast path; the registry is the source of truth for anything any other
instance needs to know about the session. Status transitions update the row;
terminal sessions (completed/error/expired) keep their row for up to 24h so
recording rotation can still attribute the recording file, then the stale
sweep removes it.

Each instance's reaper also sweeps registry rows that can no longer be live:
rows stuck in `pending` past `2 × pending_timeout`, terminal rows older than
24h, and live rows owned by other instances older than
`max_duration + 2h` (the owner would have reaped the session at max
duration — if the row is older, the owner must be dead). The sweep never
touches this instance's own live rows. With `session_max_duration_secs = 0`
(unlimited) the live-row sweep is disabled: no age proves death, so rows of
other instances are left until their status becomes terminal.

### 2. DB-backed WS tickets (`ws_tickets` table)

`POST /api/ws-ticket` issues tickets as before, but when HA is active they
are also persisted (SHA-256 hash only, 30s TTL, single-use) to the shared
backend. Any instance can validate a ticket issued by another: the
in-memory map is the fast path, a miss falls through to the DB. Consuming on
one instance deletes the row, so a ticket cannot be replayed on another.
Expired rows are purged hourly.

### 3. Cross-instance session operations

- **List** — `GET /api/sessions` merges the local map with registry rows for
  live sessions owned by other instances. Remote sessions carry
  `"remote": true` and `"owner_instance": "<id>"` (plus
  `"owner_base_url"` when the owner advertises one).
- **Get** — `GET /api/sessions/{id}` returns the registry info for a
  remote session (with the remote flags); terminal remote sessions report
  404 like any finished session.
- **Join / shadow / owner-reconnect** — the guacd stream lives on the
  owning instance, so a WebSocket upgrade that lands on the wrong instance
  is **redirected (HTTP 307) to the owner's WS endpoint**. The redirect is
  safe because:
  - a **fresh WS ticket is minted with the already-authenticated identity**
    (tickets are DB-backed, so the owner validates it), and
  - the owner instance skips the Origin/Host match **only** when the
    request's identity came from a consumed ticket — the ticket itself is
    the anti-CSWSh credential (minted only by authenticated callers,
    single-use, 30s TTL). Ticketless upgrades still get the strict Origin
    check.
  - the share/shadow token (`?token=`) is preserved verbatim; the owner
    validates it against its in-memory session. Shadow tokens for remote
    sessions are written to the registry row (the in-memory session — and
    its token list — lives on the owner), so `POST /api/sessions/{id}/
    shadow` works from any instance.
- **Terminate** — only the owning instance can terminate a session; other
  instances get an explicit error naming the owner.
- **After the owner dies** — the registry row is the source of truth, but
  the guacd stream died with the instance: joins fail (connection refused
  at the owner's URL) and the row is swept once it is provably stale. There
  is no live session migration.

### 4. Instance coordination (filesystem state)

- **`instance_id`** config key (default `<hostname>-<pid>`) tags every
  registry row with its owner. **The reaper only reaps sessions in its own
  in-memory map; recording rotation only touches files whose session id
  the registry attributes to this instance.** Two instances never fight
  over the same files, even on a shared recordings mount.
- **Rotation leader:** there is no leader election — every instance runs
  its rotation timer, but each operates **only on its own files**
  (registry owner filter), so the union of the fleets' rotations is
  exactly the rotation a single instance would have done. Deletes are
  idempotent, so even a shared mount cannot double-delete harmfully.
- **Known limitation:** recording files of sessions whose registry rows
  were swept (or whose owner crashed without a row ever existing) become
  orphans and are never auto-rotated — clean them manually. Files of
  sessions that ended normally stay attributable for up to 24h (the
  terminal-row window), which covers the normal rotation cadence.
- Xvnc display ranges, CDP port ranges, drive directories and the per-
  instance `known_hosts` remain per-instance by design; keep the ranges
  disjoint across instances on the same host.

## What the R101 spike proved (pre-R110 baseline)

The spike (see `wayfinder/v1.1.1/R101-ha-guacd-db-spike.md`) verified the
pre-R110 reality: shared *data* (address book, users, auth, audit,
settings) already worked across instances via `db_url`, but live sessions
and WS tickets were per-process memory: instance B saw `[]` for A's
sessions, rejected A's tickets with 403, and SIGKILLing A killed its
sessions everywhere. Every one of those gaps is what R110 closes (above);
the R101 environment (two instances on one Postgres + a shared guacd) is
exactly the topology the demo below exercises.

## Component Analysis

| Component | State | Where | HA Impact |
|-----------|-------|-------|-----------|
| HTTP server (persea) | Stateless per-request | In-memory | Safe to replicate |
| Session manager | **Stateful** | In-memory (HashMap) + **shared `session_registry`** (R110) | Cross-instance visible/joinable/shadowable (R110) |
| Address book, users, auth sessions, audit, settings | Shared | Configured backend (Postgres/MySQL/SQLite via `db_url`) | Shared across instances since R102 |
| WS tickets | **Stateful** | In-memory + **DB-backed** (R110) | Any instance validates any ticket (R110) |
| Recordings | Stateless | Filesystem | Shared NFS mount; rotation is per-owner (R110) |
| guacd | **Stateful per-connection** | TCP per-session | Pooled and shared (proven in R101 spike) |

## Joining a session from another instance — the flow

```
browser on B                              instance B                instance A (owner)
─────────────                             ──────────                ────────────────
GET /client/{id} (page, on B)             registry lookup ──────────▶ row: owner=A
POST /api/ws-ticket ──────────────────▶   ticket minted (DB-backed)
WS /ws/{id}?ticket=… ──────────────────▶  ticket consumed (DB)
                                          session is remote
                                          307 Location: http://A/ws/{id}?ticket=<fresh>
WS follows redirect ─────────────────────────────────────────────────▶ ticket consumed (DB)
                                          (origin check skipped: ticket-authenticated)
                                          share token validated in-memory
                                          guacd join ──▶ stream bridged
```

The browser only ever talks to the instance it was pointed at; the 307 hop
is transparent to the Guacamole client. Cross-instance shadow works the
same way, with the shadow token written to the registry row so the owner
can validate it.

## Configuration for HA mode

```toml
# Shared data store (R102): users, address book, auth sessions, audit,
# settings, AND the R110 session registry + WS tickets all live here. Set
# the SAME db_url on every instance.
db_url = "postgres://persea:secret@pg-host:5432/persea"

# Enterprise HA (R110): unique per instance across the fleet.
instance_id = "persea-1"

# Public base URL of THIS instance — the cross-instance join/shadow
# redirect target. Set per instance.
ha_base_url = "https://persea-1.example.com"

# Session settings tuned for HA
session_pending_timeout_secs = 30
session_max_duration_secs = 28800
```

License: the HA feature activates with a license key listing `ha`, or during
the 30-day evaluation period (`LicenseManager::has_feature` returns true for
every feature while evaluating). Without either, all HA code paths are
inert: no registry writes, in-memory tickets only, local session lists —
single-instance behavior, unchanged.

## Deployment Patterns

A reverse proxy or load balancer in front of the fleet can use plain
round-robin for API traffic; the WS redirect makes session affinity
unnecessary for join/shadow (the owner instance is always reached via the
redirect). The `ha_base_url` values must be reachable from browsers.

```
LB (round-robin)
    ↳ persea-1 (instance_id=persea-1, ha_base_url=https://persea-1…)
    ↳ persea-2 (instance_id=persea-2, ha_base_url=https://persea-2…)
    ↳ guacd pool (shared guacd_addr)
    ↳ Postgres/MySQL (shared db_url — data + session registry + WS tickets)
    ↳ Vault (shared credentials, when [storage] backend = "vault")
    ↳ NFS mount (shared recordings; rotation is per-owner)
```

## Demonstration (R110 acceptance — two instances, shared Postgres)

Environment (identical to the R101 spike): `persea-test-pg` (postgres:16,
port 5433, test/test/persea_test), `spike-guacd` (guacamole/guacd:latest,
host port 4823), `spike-sshd` (alpine+openssh, 172.18.0.3:2222,
root/spiketest123). Both instances run from the repo root so the license
evaluation marker (`persea-eval`, first start 2026-08-12, eval window 30d)
grants FEAT_HA.

Instance A (8096) and B (8097), same `db_url`, `instance_id` set per
instance, `ha_base_url` set per instance, shared guacd. Full transcript:

```bash
# 1. A creates a real SSH session (guacd handshake OK, WS not yet connected)
curl -s -X POST http://127.0.0.1:8096/api/sessions \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"session_type":"ssh","hostname":"172.18.0.3","port":2222,
       "username":"root","password":"spiketest123","width":1024,"height":768}'
# → {"session_id":"<SID>","status":"pending", ...}

# 2. B lists sessions — A's session is visible, marked remote
curl -s http://127.0.0.1:8097/api/sessions?all=true -H "Authorization: Bearer $KEY"
# → [{...,"session_id":"<SID>","status":"pending","remote":true,
#      "owner_instance":"persea-a","owner_base_url":"http://127.0.0.1:8096"}]

# 3. B's WS ticket validates on A (DB-backed tickets)
curl -s -X POST http://127.0.0.1:8097/api/ws-ticket -H "Authorization: Bearer $KEY"
# → {"ticket":"wst_…"}

# 4. WS upgrade to B is redirected to the owner (A)
curl -i -N --http1.1 \
  -H "Origin: http://127.0.0.1:8097" \
  "http://127.0.0.1:8097/ws/<SID>?ticket=wst_…"
# → HTTP/1.1 307 Temporary Redirect
#    location: http://127.0.0.1:8096/ws/<SID>?ticket=wst_…&…

# 5. Following the redirect to A: upgrade accepted, session becomes active
curl -i -N --http1.1 \
  -H "Origin: http://127.0.0.1:8097" \
  "http://127.0.0.1:8096/ws/<SID>?ticket=wst_…"
# → HTTP/1.1 101 Switching Protocols   (guacd logs: SSH connection successful)

# 6. Shadow from B: token persisted on the registry row, validated on A
curl -s -X POST http://127.0.0.1:8097/api/sessions/<SID>/shadow \
  -H "Authorization: Bearer $KEY" -H "X-CSRF-Token: <csrf>" -b cookies.txt
# → {"url":"/client/<SID>?token=<raw>","expires_at":…,"ttl_seconds":600}
```

Result: cross-instance visibility, join, and shadow all work and are
demonstrated; reconnect after the owning instance dies is not possible
(the stream died with it) — the registry row is swept once provably stale.

## Scaling Limits

| Resource | Bottleneck | Mitigation |
|----------|------------|------------|
| Session count | In-memory per instance | Scale instances horizontally; sessions are visible/joinable fleet-wide (R110) |
| guacd connections | One child per session | Pool guacd instances |
| SQLite write contention | Single-writer | Use MySQL/PostgreSQL `db_url` for shared data (R102) |
| Recordings disk | Per-instance storage | Shared NFS/EFS; rotation is per-owner (R110) |
| WebSocket connections | Per-instance | Load balancer handles distribution |

## Health Check

Persea exposes `GET /api/health` (200 when running). Admin
`GET /api/system/status` reports `instance.instance_id` and
`instance.ha_enabled` so operators can confirm the fleet sees the same
registry.
