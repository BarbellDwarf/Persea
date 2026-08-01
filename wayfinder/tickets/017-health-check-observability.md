# Ticket: Deep Health Check & Observability

**Type:** grilling
**Labels:** observability, wayfinder:grilling

## Question

What health check and observability improvements should be made?

### Current state:
- `GET /api/health` returns `{"status": "ok"}` without checking guacd, DB, or Vault
- No `/metrics` Prometheus endpoint
- No request logging middleware
- No structured JSON logging option
- `bench/collect-metrics.sh` reads from `/proc` — not suitable for production

### Missing health checks:
- guacd connectivity (can we reach 127.0.0.1:4822?)
- SQLite database accessibility
- Vault connectivity (if configured)
- Active session count vs limit
- Disk usage vs `max_disk_percent`

### Missing observability:
- Prometheus metrics: session counts, request durations, error rates
- Request logging: method, path, status, duration
- Structured JSON logging for log aggregation (ELK, Loki)
- Alerting guidance in docs

### Decision needed:

1. Health check: shallow (keep as-is) + deep (new endpoint), or replace shallow?
2. Prometheus: add `/metrics` endpoint, or use tracing metrics?
3. Request logging: `tower-http::TraceLayer` or custom middleware?
4. JSON logging: feature flag or `RUST_LOG_FORMAT=json` env var?
