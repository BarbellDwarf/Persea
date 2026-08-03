# Ticket: DevOps & Deployment Improvements

**Type:** research + grilling
**Labels:** devops, wayfinder:research

## Question

What DevOps and deployment improvements should be made?

### Findings:

**Build script issues:**
- `build-rpm.sh` missing `--with-spice` and `--disable-guacclip` flags (present in .deb and Docker)
- `build-rpm.sh` doesn't pin guacd commit (unlike .deb and Docker)
- Docker BuildKit cache mounts missing for cargo registry/target
- `git clone` without `--depth 1` in guacd-builder stage

**Systemd service:**
- Missing `LimitNOFILE=65535` (bench docs warn about this explicitly)
- No hardening directives (`ProtectSystem`, `NoNewPrivileges`, etc.)
- `install.sh` creates different service file than `debian/persea.service` — can drift

**Health check:**
- `GET /api/health` returns `{"status": "ok"}` without checking guacd, DB, or Vault
- No readiness vs liveness distinction

**Monitoring:**
- No Prometheus/metrics endpoint
- No request logging middleware (no HTTP access logs)
- No structured JSON logging option
- Rate limit docs contradict code (`docs/security.md:140` vs `src/main.rs:947`)

**CI/CD:**
- No integration tests in CI
- No container image scanning (Trivy/Grype)
- No artifact attestation or signing
- No request logging in CI test runs

**Backup/Recovery:**
- No automated backup script
- No restore procedure documented
- SQLite backup while running is risky (raw `cp` can corrupt)

### Decision needed:

1. RPM build: sync flags and commit pin with .deb/Docker?
2. Systemd: add hardening directives?
3. Health check: deep check (guacd + DB + Vault) or shallow?
4. Monitoring: Prometheus endpoint or structured logging first?
5. CI: integration tests or container scanning first?
