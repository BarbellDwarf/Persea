# High Availability Architecture

## Overview

Persea runs as a single Rust/Axum binary with guacd as a separate C process. The architecture separates stateless request handling from stateful session management, making horizontal scaling feasible with the right configuration.

## Component Analysis

| Component | State | Where | HA Impact |
|-----------|-------|-------|-----------|
| HTTP server (persea) | Stateless per-request | In-memory | Safe to replicate |
| Session manager | **Stateful** | In-memory (HashMap) | Requires session affinity |
| Auth sessions | **Stateful** | Local SQLite (rusqlite) | Per-instance — not shared |
| Address book | **Stateful** | Local SQLite (metadata) + optional Vault (credentials) | Metadata per-instance; only credentials shared via Vault |
| Audit log | Stateless | SQLite | Per-instance (acceptable) |
| Recordings | Stateless | Filesystem | Per-instance or shared NFS |
| guacd | **Stateful per-connection** | TCP per-session | Can be pooled and shared |

> **Clustering status:** persea has **no active clustering**. There is no
> shared session store, no leader election, and no cross-instance session
> migration. Horizontal scaling works only with session affinity (below),
> and anything that must be shared across instances (address book metadata,
> auth sessions, audit log) is currently per-instance. Features that would
> change this are roadmap items, not shipped behaviour.

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

### MySQL/PostgreSQL (via SQLx) — roadmap, not implemented for data storage
- The `DbPool` enum (`src/db_pool.rs`) can connect to PostgreSQL, MySQL, or
  SQLite via `db_url`, but **no application data is stored there yet** — it
  is currently only pinged by the `/api/health` deep check. Users, sessions,
  audit log, and the address book all live in the per-instance rusqlite DB.
- **Not implemented:** storing the address book (or any other data) in
  MySQL/PostgreSQL so instances can share it. Do not configure `db_url`
  expecting shared state today.

### Vault (credentials only)
- With `[storage] backend = "vault"`, connection **credentials** are stored
  in Vault/OpenBao; folder and entry **metadata always stays in the local
  DB** (see `src/api/address_book.rs`).
- Multiple persea instances can share one Vault for credentials, but each
  instance's address book tree (folders, entries, ACLs) is its own local
  copy — changes do not propagate between instances.
- Session data is still per-instance (in-memory + local DB).

## Cloud Deployment Patterns

> **Status:** the patterns below are illustrative reference architectures,
> not officially tested or supported configurations. They assume the
> roadmap items above (shared address book storage) exist. Today, a
> multi-instance deployment shares only recordings (via NFS/EFS) and
> credentials (via Vault); everything else is per-instance. The
> "ElastiCache Redis (session tokens)" element is **not implemented** —
> there is no Redis integration in persea.

### AWS (ECS + ALB)
```
ALB (sticky sessions) → ECS Service (persea containers, min 2)
    ↳ guacd ECS Service (min 2, TCP target group)
    ↳ RDS MySQL/PostgreSQL (shared address book — roadmap)
    ↳ EFS (shared recordings)
    ↳ ElastiCache Redis (session tokens — not implemented)
```

### Azure (Container Apps)
```
Azure Container Apps (persea, min replicas, sticky sessions via affinity)
    ↳ Azure Database for MySQL (shared address book)
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
    ↳ Vault (shared credentials only — address book metadata stays per-instance)
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
| SQLite write contention | Single-writer | Switch to MySQL/PostgreSQL for HA |
| Recordings disk | Per-instance storage | Shared NFS/EFS for cross-instance access |
| WebSocket connections | Per-instance | Load balancer handles distribution |

## Configuration Changes for HA Mode

```toml
# Persea config for HA mode
listen_addr = "0.0.0.0:8089"
guacd_addr = "guacd-lb:4822"  # or individual guacd instances

# NOTE: db_url (MySQL/PostgreSQL) is NOT used for address book storage yet —
# it is only pinged by the health check. Address book metadata stays in the
# per-instance SQLite DB. See "Database Options" above.
# db_url = "mysql://persea:secret@mysql-host:3306/persea"

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
