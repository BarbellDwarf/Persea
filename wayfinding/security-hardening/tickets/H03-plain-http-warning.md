# Ticket: Plain-HTTP mode documentation + warning

wayfinder:task
Priority: P3

## Question

The app works over plain HTTP for LAN development. This is intentional (the conditional `Secure` cookie flag enables it), but the risks are not documented. Users running in plain HTTP mode over a LAN have unencrypted credentials and session tokens.

Add a startup log warning when `listen_addr` is not behind TLS and `[tls]` is absent: "WARNING: running without TLS — credentials and session tokens travel unencrypted. Use [tls] or a reverse proxy with TLS for production." Also add this to the config.example.toml comments and the deployment guide.

## Deliverable

Startup warning in `main.rs` when no TLS configured. Updated config.example.toml comments. Updated `docs/deployment-guide.md` section.
