# Ticket: High Availability architecture documentation

wayfinder:research
Priority: P3

## Question

Research and document a high-availability architecture for Persea that covers:

1. **Stateless frontend scaling**: Can multiple persea instances sit behind a load balancer? What state is in-memory vs DB? Session cookies need to be shared.
2. **guacd pooling**: Can multiple guacd instances be pooled? Does persea support pointing at a guacd load balancer? What happens when a guacd instance dies mid-session?
3. **Database HA**: SQLite is single-writer. For multi-instance HA, the DB would need to be either MySQL/PostgreSQL (SQLx support exists but is this mature enough?) or per-instance SQLite with shared address book via Vault.
4. **Cloud deployment patterns**: AWS ALB + ECS, Azure Container Apps, k8s with StatefulSet for guacd + Deployment for persea.
5. **Local HA**: HAProxy/Nginx + multiple persea containers + shared guacd + NFS for recordings.

## Deliverable

A markdown document (`docs/high-availability.md`) covering:
- Architecture diagrams (text-based)
- Configuration requirements for each pattern
- Session affinity requirements
- Storage considerations (recordings, address book, database)
- Health check endpoints
- Scaling limits and bottlenecks
