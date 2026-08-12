# High Availability

> **Audience:** operators running persea across multiple servers (a cluster) for resilience and scale.
> **Next:** [Deployment Guide](deployment-guide.md#database-backends) for shared-database setup, or [Licensing](licensing.md) for the Enterprise license that unlocks HA.

## Overview

persea normally runs as a single instance: one server process plus one guacd daemon. You can run several instances against the **same database** (`db_url`) and they already share the static data — users, the address book, auth sessions, audit log, and settings.

The **Enterprise HA feature** (feature `ha`, included in the 30-day evaluation period) goes further: live sessions become visible across the whole fleet. A session started on instance A appears in the session list on instance B, can be joined or shadowed from B, and a user who lands on the "wrong" instance is transparently redirected to the one hosting their session. Recording rotation is shared safely too, so multiple instances never fight over the same files.

Without the license (or without a shared `db_url`), every instance behaves exactly as a standalone single instance — nothing changes.

## What you need

Three things, all covered below:

1. **A shared database backend** — MySQL or PostgreSQL via `db_url`, identical on every instance (SQLite is single-writer and cannot be shared safely).
2. **An Enterprise license** that includes the `ha` feature (or the 30-day evaluation window). See [Licensing](licensing.md).
3. **A unique `instance_id` per instance** and a public base URL (`ha_base_url`) per instance, so browsers can be redirected to the right place.

## How it works

### 1. A shared session registry

The moment a session is created, a row is written to a `session_registry` table in the shared database. The row records which instance owns the session, that instance's base URL, the session type and status, the target hostname and username, who created it, and the guacd connection id. Status changes update the row as the session progresses.

Each instance keeps its fast in-memory session map for its own sessions; the registry is how *other* instances learn about them. Finished sessions keep their row for up to 24 hours so recordings can still be attributed, then a periodic sweep removes them.

Each instance also sweeps registry rows that can no longer be live:

- sessions stuck in `pending` past twice the pending timeout,
- finished sessions older than 24 hours,
- **live sessions owned by other instances** that are older than the maximum session duration plus 2 hours — if the row is that old, the owning instance must be dead.

The sweep never touches live sessions owned by this instance. With `session_max_duration_secs = 0` (unlimited duration), the third sweep is disabled: no age proves an instance dead, so other instances' rows are left alone until they finish normally.

### 2. WebSocket tickets that work across instances

persea uses short-lived, single-use WebSocket tickets to open session streams. With HA active, issued tickets are also written to the shared database (only a SHA-256 hash, 30-second lifetime, single-use). Any instance can validate a ticket issued by any other: the in-memory list is checked first, then the database. Consuming a ticket deletes its row, so a ticket cannot be replayed on a different instance. Expired rows are purged hourly.

### 3. Sessions you can see, join, and shadow from anywhere

- **List** — `GET /api/sessions` (and the Sessions page) merges local sessions with live sessions owned by other instances. Remote sessions carry `"remote": true` and the owning instance's id and base URL.

![Sessions page: sessions from the whole fleet appear here, remote ones flagged](assets/screenshots/sessions.png)
- **Join / shadow / reconnect** — the actual session stream lives on the owning instance. When a browser connects to the wrong instance, that instance answers with an **HTTP 307 redirect to the owner's WebSocket endpoint**, minting a fresh ticket for the already-authenticated user first. The browser never needs to know; the hop is transparent to the Guacamole client. The share or shadow token (`?token=`) is preserved verbatim, and shadow tokens for remote sessions are stored on the shared registry row, so `POST /api/sessions/{id}/shadow` works from any instance.
- **Terminate** — only the owning instance can terminate a session; any other instance returns an explicit error naming the owner.

### 4. Instances that don't step on each other

Every registry row is tagged with its owner's `instance_id` (default: `<hostname>-<pid>`). The session reaper only ever touches sessions in its own memory, and **recording rotation only deletes files whose session the registry attributes to this instance** — so two instances can share one recordings mount without double-deleting or stealing each other's files. There is no leader election; each instance runs its own rotation timer over its own files, which together is exactly what one instance would have done.

## Joining a session hosted on another instance

```
browser on B                              instance B                instance A (owner)
─────────────                             ──────────                ────────────────
GET /client/{id} (page, on B)             registry lookup ──────────▶ row: owner=A
POST /api/ws-ticket ──────────────────▶   ticket minted (shared DB)
WS /ws/{id}?ticket=… ──────────────────▶  ticket consumed (shared DB)
                                          session is remote
                                          307 Location: http://A/ws/{id}?ticket=<fresh>
WS follows redirect ─────────────────────────────────────────────────▶ ticket consumed (shared DB)
                                          share token validated
                                          guacd join ──▶ stream bridged
```

The 307 hop is transparent to the browser and the Guacamole client; the user simply sees their session. For security, the strict cross-origin (Origin/Host) check on the WebSocket endpoint is relaxed **only** for requests authenticated by a consumed ticket — ticketless upgrades still get the full check.

## Setting it up

Every instance needs the **same** `db_url` and its **own** `instance_id` and `ha_base_url`:

```toml
# Shared data store: users, address book, auth sessions, audit, settings,
# the session registry, and WebSocket tickets all live here. Set the SAME
# value on every instance.
db_url = "postgres://persea:secret@pg-host:5432/persea"

# Unique per instance across the fleet.
instance_id = "persea-1"

# Public base URL of THIS instance — the target of cross-instance
# join/shadow redirects. Must be reachable from users' browsers.
ha_base_url = "https://persea-1.example.com"

# Session settings tuned for HA
session_pending_timeout_secs = 30
session_max_duration_secs = 28800
```

1. Set up the shared database (see [Deployment Guide > Database backends](deployment-guide.md#database-backends)) and point every instance at it.
2. Configure `instance_id` and `ha_base_url` per instance, and make sure `ha_base_url` resolves from the browsers that use it.
3. Install the Enterprise license key on every instance (or rely on the 30-day evaluation). See [Licensing](licensing.md).
4. Restart each instance and confirm with the health check below that HA is active.

The `ha_base_url` values must be reachable from browsers — typically the same hostname/port users already use to reach each instance.

## What's supported — and the honest limitations

**Supported:**

- Fleet-wide session list: every instance shows all live sessions, remote ones flagged.
- Join and shadow from any instance, including share links and shadow tokens.
- Cross-instance owner reconnect when a browser drops (guacd keeps the session alive long enough for the redirect to route back to the owner).
- Safe recording rotation on a shared mount, per-owner.
- Load balancers can use plain round-robin — no sticky sessions needed, because join/shadow always reach the owner via the redirect.

**Limitations:**

- **No live session migration.** The session stream lives on the owning instance; if that instance dies (or is SIGKILLed), its sessions die with it. The registry row lingers until it is provably stale and is then swept. Sessions are not migrated to another instance.
- **Termination is owner-only.** Other instances refuse to terminate a remote session (with an explicit error naming the owner).
- **Orphaned recordings.** A recording whose registry row was swept — or whose owner crashed before the row existed — is never auto-rotated; clean those up manually. Normally finished sessions stay attributable for up to 24 hours, which covers the normal rotation cadence.
- **Per-instance resources stay per-instance.** Xvnc display ranges, CDP port ranges, drive directories, and the `known_hosts` file are local to each instance — keep the ranges disjoint across instances on the same host.
- **SQLite is not suitable** as the shared backend (single-writer); use MySQL or PostgreSQL.

## Deployment patterns

A reverse proxy or load balancer in front of the fleet can use plain round-robin:

```
LB (round-robin)
    ↳ persea-1 (instance_id=persea-1, ha_base_url=https://persea-1…)
    ↳ persea-2 (instance_id=persea-2, ha_base_url=https://persea-2…)
    ↳ guacd pool (shared guacd_addr)
    ↳ Postgres/MySQL (shared db_url — data + session registry + WS tickets)
    ↳ Vault (shared credentials, when [storage] backend = "vault")
    ↳ NFS mount (shared recordings; rotation is per-owner)
```

guacd is a shared resource: point every instance at the same guacd address (or a pool of guacd daemons) — guacd connections are stateless per session and can live anywhere the instances can reach them.

## Scaling limits

| Resource | Bottleneck | Mitigation |
|----------|------------|------------|
| Session count | Per-instance memory | Add instances; sessions are visible and joinable fleet-wide |
| guacd connections | One child per session | Pool guacd instances |
| Shared database writes | Registry and ticket writes | Use MySQL/PostgreSQL `db_url`; SQLite is single-writer |
| Recordings disk | Per-instance storage | Shared NFS/EFS; rotation is per-owner |
| WebSocket connections | Per-instance | Load balancer handles distribution |

## Verifying HA is active

- `GET /api/health` returns `200` when an instance is running.
- `GET /api/system/status` (admin) reports `instance.instance_id` and `instance.ha_enabled`, so you can confirm every instance sees the same registry and the license is active.
- Create a session on one instance and check the Sessions page on another — the session appears there, marked as remote. That is the whole feature working end to end.
