# High Availability Architecture

## Overview

Persea runs as a single Rust/Axum binary with guacd as a separate C process. The architecture separates stateless request handling from stateful session management, making horizontal scaling feasible with the right configuration.

## What the R101 spike proved (2026-08-12)

A live local spike (see `wayfinder/v1.1.1/R101-ha-guacd-db-spike.md` for the
full runbook) verified the current HA reality with two persea instances on a
shared PostgreSQL backend:

- **Works across instances today:** address book, users/auth (same API key
  authenticates on both), audit, settings — all stored in the configured
  backend (Postgres/MySQL/SQLite via `db_url`), immediately visible from any
  instance, surviving crash-restart. A settings `PUT` on instance A is
  visible on instance B and survives A being killed. A shared guacd serves
  both instances; sessions run through it end-to-end (plain TCP and TLS).
- **Does NOT work across instances (R110 scope, not current claims):**
  - **Live sessions are per-process memory.** A session created on A is
    invisible on B (`GET /api/sessions` returns `[]`; `GET /api/sessions/{id}`
    → 404) and dies with its instance (SIGKILL demo).
  - **WS tickets are per-instance** (in-memory `HashMap`, 30s TTL). A ticket
    issued by A is rejected by B (HTTP 403 on the WS upgrade; B's own ticket
    is accepted with 101).
  - Cross-instance join/shadow/reconnect do not exist. Session affinity is
    mandatory (below).
- **Standalone guacd is fully supported and proven:** persea connects out to
  `guacd_addr`, no startup ping (boots fine with guacd down; health reports
  `guacd: down` / overall `degraded`; session creation fails cleanly with
  502). Both plain-TCP and TLS (`[tls] guacd_cert_path`) variants verified
  with real SSH sessions. The Docker image's embedded guacd cannot be
  disabled — it just sits unused when `guacd_addr` points elsewhere.

## Component Analysis

| Component | State | Where | HA Impact |
|-----------|-------|-------|-----------|
| HTTP server (persea) | Stateless per-request | In-memory | Safe to replicate |
| Session manager | **Stateful** | In-memory (HashMap) | Requires session affinity; cross-instance sharing is R110 |
| Address book, users, auth sessions, audit, settings | Shared | Configured backend (Postgres/MySQL/SQLite via `db_url`) | **Shared across instances** since R102 |
| WS tickets | **Stateful** | Per-process in-memory (`WsTicketStore`) | DB-backed tickets are R110 |
| Recordings | Stateless | Filesystem | Per-instance or shared NFS; rotation leader election is R110 |
| guacd | **Stateful per-connection** | TCP per-session | Can be pooled and shared (proven in R101 spike) |

> **Clustering status:** persea has **no active clustering**. There is no
> shared session store, no leader election, and no cross-instance session
> migration. Shared *data* (address book, users, auth sessions, audit,
> settings) is stored in the configured backend and is visible from every
> instance. Shared *live session state* (registry, tickets, join/shadow/
> reconnect) does not exist yet — it is R110's scope. Horizontal scaling
> works only with session affinity (below).

## Session Affinity (Required)

Active sessions live in `SessionManager` (in-memory HashMap keyed by UUID). A WebSocket connection is pinned to the instance that holds the session state. When a browser reconnects, it must hit the same instance.

**Requirement**: Session affinity via sticky cookies or consistent hashing. The session cookie (`persea_session`) identifies the user but NOT the instance. Use a separate LB cookie (e.g., `SERVERID`) set on first response, or hash the session UUID for consistent routing.

**No session migration**: Sessions cannot be moved between instances. When an instance dies, its sessions are lost.

## guacd Pooling

guacd is a per-connection process (one child per protocol connection). persea
never spawns guacd itself — it always connects to a guacd daemon via
`guacd_addr`. Two deployment options:

1. **Co-located guacd** (default): guacd runs as a separate process on the
   same host as persea — the systemd `persea-guacd` service on bare metal,
   or the entrypoint-spawned guacd in the Docker image. Simple, but each
   persea instance has its own guacd.
2. **External guacd pool**: Multiple guacd instances behind a TCP load
   balancer. Each persea instance connects to a guacd via `guacd_addr`. The
   LB distributes connections. guacd is stateless per-connection — any
   instance can serve any session.

For HA, option 2 is recommended. A single guacd handles ~100-500 concurrent sessions on modest hardware, so 2-3 instances provide redundancy.

## Database Options

### SQLite (current default)
- Single-writer, multiple-reader per file
- **Cannot** be shared across instances on different machines
- Acceptable for single-instance deployments
- For HA: each instance needs its own SQLite (loses cross-instance address book)

### MySQL/PostgreSQL (via SQLx `db_url`) — real shared storage since R102
- Since R102 the `DbPool` backend (PostgreSQL, MySQL, or SQLite via
  `db_url`) **is the store**: users, auth sessions, the address book, audit
  log, settings, and password history all live there, with per-backend
  migrations run at startup. Any instance pointing at the same `db_url`
  shares all of it (proven in the R101 spike: entry created on one instance
  is immediately listable on another; settings and API keys survive
  crash-restart).
- **Still NOT shared (R110):** live sessions and WS tickets stay per-process.
  `db_url` is a config-file/env setting only — there is no UI toggle, and it
  must match across the fleet.
- Without `db_url`, persea falls back to the local SQLite file (`db_path`),
  which is per-instance by definition.

### Live session state — R110 scope (not current claims)
- Session registry, DB-backed WS tickets, cross-instance join/shadow/
  reconnect, recordings-rotation leader election, and per-instance
  filesystem paths (`instance_id`) are R110 enterprise-HA work. Until then,
  treat live sessions as pinned to one instance (session affinity below).

### Vault (credentials only)
- With `[storage] backend = "vault"`, connection **credentials** are stored
  in Vault/OpenBao; folder and entry **metadata lives in the configured
  backend** (see `src/api/address_book.rs`) — so with `db_url` set, the
  address book tree is shared across instances even in vault mode.
- Multiple persea instances can share one Vault for credentials; with a
  shared `db_url` the metadata is shared too.
- Session data is still per-instance (in-memory; see "Live session state").

## Cloud Deployment Patterns

> **Status:** the patterns below are illustrative reference architectures,
> not officially tested or supported configurations. Today a multi-instance
> deployment shares: recordings (via NFS/EFS), credentials (via Vault), and
> all app data (address book, users, audit, settings) via a shared
> `db_url` backend (R102). Live sessions and WS tickets remain
> per-instance — sticky sessions are required — until R110 lands the
> shared session registry. The "ElastiCache Redis (session tokens)"
> element is **not implemented** — there is no Redis integration in persea.

### AWS (ECS + ALB)
```
ALB (sticky sessions) → ECS Service (persea containers, min 2)
    ↳ guacd ECS Service (min 2, TCP target group)
    ↳ RDS MySQL/PostgreSQL (shared data store — db_url, R102)
    ↳ EFS (shared recordings)
    ↳ ElastiCache Redis (session tokens — not implemented)
```

### Azure (Container Apps)
```
Azure Container Apps (persea, min replicas, sticky sessions via affinity)
    ↳ Azure Database for MySQL (shared data store — db_url, R102)
    ↳ Azure Files (shared recordings)
    ↳ Container Apps guacd instances (TCP scaling)
```

### Kubernetes
```
Deployment (persea, replicas: 2+, pod anti-affinity)
StatefulSet (guacd, replicas: 2)
PVC (recordings)
ConfigMap/Secret (persea config)
Ingress (sticky sessions via annotation)
```

## Local HA (Single Server)

```
HAProxy (TCP + HTTP mode)
    ↳ persea-1 (container, port 8081)
    ↳ persea-2 (container, port 8082)
    ↳ persea-3 (container, port 8083)
    ↳ guacd-1 (container, port 4822)
    ↳ guacd-2 (container, port 4823)
    ↳ Postgres/MySQL (shared data store via db_url, R102)
    ↳ Vault (shared credentials, when [storage] backend = "vault")
    ↳ NFS mount (shared recordings)
```

HAProxy config: sticky sessions via cookie, health check on `/api/health`, TCP mode for guacd passthrough.

## Health Check

Persea exposes `GET /api/health` (check `src/main.rs` for the route). Returns 200 when the server is running. Use this for LB health checks with a 5s interval.

## Scaling Limits

| Resource | Bottleneck | Mitigation |
|----------|------------|------------|
| Session count | In-memory per instance | Scale instances horizontally (session affinity) |
| guacd connections | One child per session | Pool guacd instances |
| SQLite write contention | Single-writer | Use MySQL/PostgreSQL `db_url` for shared data (R102) |
| Recordings disk | Per-instance storage | Shared NFS/EFS for cross-instance access |
| WebSocket connections | Per-instance | Load balancer handles distribution |

## Configuration Changes for HA Mode

```toml
# Persea config for HA mode
listen_addr = "0.0.0.0:8089"
guacd_addr = "guacd-lb:4822"  # or individual guacd instances

# Shared data store (R102): users, address book, auth sessions, audit,
# settings all live here and are shared by every instance with the same
# db_url. Live sessions and WS tickets are still per-instance (R110) —
# session affinity is required. Set the same db_url on every instance.
db_url = "mysql://persea:secret@mysql-host:3306/persea"

# Recordings on shared storage
[recording]
path = "/mnt/nfs/recordings"

# TLS (required for production)
[tls]
cert_path = "/etc/persea/tls/cert.pem"
key_path = "/etc/persea/tls/key.pem"

# Session settings tuned for HA
session_pending_timeout_secs = 30
session_max_duration_secs = 28800
```
