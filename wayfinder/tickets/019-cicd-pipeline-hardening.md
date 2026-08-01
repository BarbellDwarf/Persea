# Ticket: CI/CD Pipeline Hardening

**Type:** task
**Labels:** devops, wayfinder:task

## Question

What CI/CD improvements should be made?

### Current state:
- CI runs on push to main + all PRs
- CI includes: formatting, clippy, build, `cargo audit`
- Release builds amd64 + arm64, multi-arch Docker
- Dependabot for Cargo and GitHub Actions

### Missing:
- **No integration tests** — `tests/test_browser_session.sh` not run in CI
- **No container image scanning** — Trivy, Grype, or Snyk not scanning Docker images
- **No artifact attestation** — release artifacts not signed with cosign/sigstore
- **No smoke test** — server never started and hit with health check in CI
- **No changelog generation** from conventional commits (uses GitHub PR titles)

### Security implications:
- OS-level CVEs in runtime image not caught
- Supply chain integrity relies solely on GitHub HTTPS transport
- No verification that built binary matches source

### Decision needed:

1. Integration tests in CI: full server startup or just unit tests?
2. Container scanning: Trivy, Grype, or Snyk?
3. Artifact signing: cosign/sigstore, or GPG?
4. Smoke test scope: health check only, or basic session lifecycle?
