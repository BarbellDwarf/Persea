# Ticket: H06 gap — Docker TLS key still baked in + admin key on stdout

wayfinder:task
Priority: P1
Phase: High

## Gap

Completely untouched despite prior commit claiming otherwise.

- `Dockerfile:213` still runs `persea generate-cert` at build time (key baked into every image layer)
- `Dockerfile:265-267` still prints admin API key to stdout on first run

## Fix

1. Remove `RUN persea generate-cert ...` from Dockerfile
2. Move cert generation into entrypoint script: if `/opt/persea/tls/cert.pem` doesn't exist, generate self-signed cert at container start (mounted certs respected, each deployment gets unique key)
3. Write admin key to file with `chmod 600` instead of stdout — or require rotation via `persea rotate-admin-key`

## Files

- `Dockerfile:213` — cert generation
- `Dockerfile:265-267` — admin key output
- Entrypoint script — first-run cert logic

## Deliverable

Docker image has no baked-in key. Entrypoint generates cert if none mounted. Admin key saved to file. `docker build` succeeds.
