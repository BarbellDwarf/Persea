# Ticket: Shared TLS key baked into Docker image + admin key on stdout

wayfinder:task
Priority: P1
Phase: High

## Finding

`Dockerfile:213,228-231` — TLS private key is baked into every Docker image at build time. The public HTTPS listener and guacd loopback both default to it. `Dockerfile:261-269` (entrypoint script) prints the admin API key to container stdout on first run (captured by `docker logs`).

## Fix

1. **TLS key**: Remove the baked-in key from the Dockerfile. At first container start, if no cert is mounted at the expected path, generate a self-signed cert (using `rcgen` or `rustls` cert generation) and store it in a persistent volume. If no volume is mounted, fail the healthcheck with a clear warning.
2. **Admin key**: Write the admin API key to a file with `chmod 600` permissions instead of stdout. Or require the operator to supply it via environment variable / mounted secret file.
3. **Config**: Add comments to `config.example.toml` documenting that operators should supply their own TLS cert for production.

## Files

- `Dockerfile:213,228-231` — baked-in TLS key
- `Dockerfile:261-269` — entrypoint admin key output
- `docker-entrypoint.sh` or equivalent — first-run logic

## Deliverable

Docker image does not contain a baked-in TLS key. First-run generates a self-signed cert or fails until operator supplies one. Admin key written to file (not stdout). `docker build` succeeds. Container starts with mounted cert.
