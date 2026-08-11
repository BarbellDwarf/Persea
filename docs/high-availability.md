# High Availability Architecture

## Overview

Persea runs as a single Rust/Axum binary with guacd as a separate C process. The architecture separates stateless request handling from stateful session management, making horizontal scaling feasible with the right configuration.

## Component Analysis

| Component | State | Where | HA Impact |
|-----------|-------|-------|-----------|
| HTTP server (persea) | Stateless per-request | In-memory | Safe to replicate |
| Session manager | **Stateful** | In-memory (HashMap) | Requires session affinity |
| Auth sessions | Stateless | SQLite/DB | Shared across instances |
| Address book | Stateless | SQLite or Vault | Shared across instances |
| Audit log | Stateless | SQLite | Per-instance (acceptable) |
| Recordings | Stateless | Filesystem | Per-instance or shared NFS |
| guacd | **Stateful per-connection** | TCP per-session | Each persea needs its own guacd |

## Session Affinity (Required)

Active sessions live in `SessionManager` (in-memory HashMap keyed by UUID). A WebSocket connection is pinned to the instance that holds the session state. When a browser reconnects, it must hit the same instance.

**Requirement**: Session affinity via sticky cookies or consistent hashing. The session cookie (`persea_session`) identifies the user but NOT the instance. Use a separate LB cookie (e.g., `SERVERID`) set on first response, or hash the session UUID for consistent routing.

**No session migration**: Sessions cannot be moved between instances. When an instance dies, its sessions are lost.

## guacd Pooling

Each persea instance needs its own guacd. guacd is a per-connection process (one child per protocol connection). Two options:

1. **Embedded guacd** (default): persea spawns guacd as a child. Each instance gets its own. Simple but no pooling.
2. **External guacd pool**: Multiple guacd instances behind a TCP load balancer. Each persea instance connects to a guacd via `guacd_addr`. The LB distributes connections. guacd is stateless per-connection — any instance can serve any session.

For HA, option 2 is recommended. A single guacd handles ~100-500 concurrent sessions on modest hardware, so 2-3 instances provide redundancy.

## Database Options

### SQLite (current default)
- Single-writer, multiple-reader per file
- **Cannot** be shared across instances on different machines
- Acceptable for single-instance deployments
- For HA: each instance needs its own SQLite (loses cross-instance address book)

### MySQL/PostgreSQL (via SQLx)
- SQLx support exists (`DbPool` enum in `src/db_pool.rs`) but is not the primary tested path
- Use for HA deployments where address book must be shared across instances
- Config: `db_url = "mysql://user:pass@host/persea"` or `"postgres://..."`

### Vault (address book only)
- Vault-backed address book is already supported (`[storage] backend = "vault"`)
- Multiple persea instances can share one Vault address book
- Credentials stored in Vault, address book metadata in Vault
- Session data still per-instance (in-memory + local DB)

## Cloud Deployment Patterns

### AWS (ECS + ALB)
```
ALB (sticky sessions) → ECS Service (persea containers, min 2)
    ↳ guacd ECS Service (min 2, TCP target group)
    ↳ RDS MySQL/PostgreSQL (shared address book)
    ↳ EFS (shared recordings)
    ↳ ElastiCache Redis (session tokens, optional)
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
    ↳ MySQL/PostgreSQL (shared address book) or Vault
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

# Shared address book via MySQL
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
