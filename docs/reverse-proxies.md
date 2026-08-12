# Reverse Proxy Configuration

> **Audience:** operators placing persea behind nginx, Caddy, Apache, or Traefik.
> **Next:** [Deployment Guide](deployment-guide.md) for the full production setup.

## What a reverse proxy is, and why put one in front

A **reverse proxy** is a server that sits in front of persea and
forwards web traffic to it, so visitors talk to the proxy instead of to
persea directly. Typical reasons to use one:

- **TLS termination**: the proxy holds a real CA-issued certificate
  (Let's Encrypt, etc.) and handles HTTPS; persea can stay on plain
  HTTP on the loopback interface.
- **A friendly hostname and port**: one public address can host
  persea alongside other services, with routing by hostname.
- **Rate limiting, access control, and request filtering** at the edge,
  where HAProxy/Knocknoc-style gateways integrate with your network
  policies.
- **Protection from exposure**: persea listens only on loopback
  (`127.0.0.1:8089` by default), so it is never directly reachable.

persea is designed for this: it runs happily behind a TLS-terminating
proxy, honours `X-Forwarded-For`/`X-Forwarded-Proto` from proxies you
trust, and forwards WebSocket connections for session streams. The
primary supported path is **HAProxy + Knocknoc** (see
[`haproxy.example.cfg`](../haproxy.example.cfg) and
[`integrations.md`](integrations.md)), which is what persea runs in
production. This document covers nginx, Caddy, Apache, and Traefik,
and one gotcha that affects nested folder paths across several of them.

## Tell persea about the proxy

However you proxy, add the proxy's source address to `trusted_proxies`
in `config.toml` (usually `127.0.0.1/32` for a same-host proxy):

```toml
trusted_proxies = ["127.0.0.1/32"]
```

This does two things:

1. **Correct client IPs.** persea trusts `X-Forwarded-For` only from
   those addresses, so audit logs, session history and rate limiting
   see the real client IP instead of the proxy's.
2. **Correct `Secure` cookies.** persea only treats a request as HTTPS
   based on `X-Forwarded-Proto: https` when the immediate peer is
   trusted. A client-supplied header from an untrusted source is
   ignored. This matters because the session cookie gets the `Secure`
   attribute only when persea believes the connection is HTTPS, and a
   `Secure` cookie over plain HTTP would never be sent by the browser.

Without `trusted_proxies`, every request appears to come from the
proxy's own IP, and cookies may miss `Secure` even though the browser
is on HTTPS.

## WebSocket support

Session streams run over WebSockets (paths `/ws/{id}` and
`/client/{id}`), so the proxy must:

- Forward the `Upgrade`/`Connection` headers (nginx and Apache need
  explicit directives; Caddy and Traefik handle it automatically).
- Allow long-lived connections. A session can run for hours: proxy
  timeouts that are too short kill sessions mid-stream. Match persea's
  `session_max_duration_secs` (default 8 hours) where possible.

## nginx

**Affected by a URI-normalisation gotcha by default** (see
[Common mistakes](#common-mistakes-the-2f-gotcha)): nginx decodes `%2F`
in the path when `proxy_pass` has a URI component, including just a
trailing slash. Use a `proxy_pass` URL with **no path component**:

```nginx
server {
    listen 443 ssl http2;
    server_name console.example.com;

    ssl_certificate     /etc/letsencrypt/live/console.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/console.example.com/privkey.pem;

    location / {
        # CRITICAL: no trailing slash or path on the upstream URL.
        # "https://localhost:8089/" would cause nginx to decode %2F to /
        # before forwarding, which breaks nested folder paths.
        proxy_pass https://localhost:8089;

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support for session streams.
        proxy_http_version 1.1;
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Long-lived WebSocket sessions; match persea's session_max_duration_secs.
        proxy_read_timeout  8h;
        proxy_send_timeout  8h;
    }
}
```

Notes:

- The example forwards to `https://localhost:8089` because persea
  itself serves HTTPS with a self-signed loopback certificate. If you
  run persea on plain HTTP (no `[tls]` section), use
  `proxy_pass http://localhost:8089;` instead.
- WebSocket timeouts: set `proxy_read_timeout`/`proxy_send_timeout` to
  at least persea's `session_max_duration_secs` (default 8 h).
- persea config: `trusted_proxies = ["127.0.0.1/32"]`.

## Caddy

Caddy's `reverse_proxy` directive forwards the raw request URI by
default, so nested folders work out of the box, and WebSocket support
is automatic; no extra directives needed:

```caddyfile
console.example.com {
    reverse_proxy https://localhost:8089 {
        transport http {
            tls_insecure_skip_verify  # persea's self-signed loopback cert
        }
        header_up X-Real-IP       {remote_host}
        header_up X-Forwarded-For {remote_host}
    }
}
```

persea `config.toml`:

```toml
trusted_proxies = ["127.0.0.1/32"]
```

If you run persea on plain HTTP, drop the `transport` block and use
`reverse_proxy http://localhost:8089`.

## Apache (mod_proxy)

**Affected by the `%2F` gotcha by default.** Apache's `ProxyPass`
canonicalises the URI (decodes `%2F`) unless you add `nocanon`:

```apache
<VirtualHost *:443>
    ServerName console.example.com
    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/console.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/console.example.com/privkey.pem

    # The nocanon flag stops Apache from decoding %2F in the path.
    # Without it, nested folder paths 404.
    ProxyPass        / https://localhost:8089/ nocanon
    ProxyPassReverse / https://localhost:8089/

    # persea uses a self-signed cert on loopback.
    SSLProxyEngine on
    SSLProxyVerify none
    SSLProxyCheckPeerCN off
    SSLProxyCheckPeerName off

    # WebSocket support requires mod_proxy_wstunnel and an explicit
    # ws:// upgrade rule; exact syntax depends on Apache version.
    # See https://httpd.apache.org/docs/current/mod/mod_proxy_wstunnel.html

    RequestHeader set X-Forwarded-Proto "https"
</VirtualHost>
```

You may also need `AllowEncodedSlashes NoDecode` at the server or
vhost level on some Apache versions to stop the core URI parser
rejecting `%2F` before it reaches mod_proxy.

persea `config.toml`:

```toml
trusted_proxies = ["127.0.0.1/32"]
```

## Traefik

Traefik forwards the raw request URI by default, so nested folders work
without special configuration, and WebSocket upgrades pass through
automatically:

```yaml
# traefik dynamic config (file provider)
http:
  routers:
    persea:
      rule: "Host(`console.example.com`)"
      entryPoints: [websecure]
      service: persea
      tls:
        certResolver: letsencrypt

  services:
    persea:
      loadBalancer:
        servers:
          - url: "https://localhost:8089"
        serversTransport: insecure-backend

  serversTransports:
    insecure-backend:
      insecureSkipVerify: true
```

persea `config.toml`:

```toml
trusted_proxies = ["127.0.0.1/32"]
```

## HAProxy

Default HAProxy forwards the request URI unchanged, so it is unaffected
by the `%2F` issue. The shipped `haproxy.example.cfg` doesn't rewrite
paths. See [`integrations.md`](integrations.md) for the full config
including Knocknoc.

## Common mistakes: the `%2F` gotcha

persea's connections tree uses URL path segments for folder names. When
a folder is nested (e.g. `Clients/Acme/Prod`), the client encodes the
internal `/` as `%2F` so the whole path fits one segment:

```
GET /api/addressbook/folders/shared/Clients%2FAcme%2FProd/subfolders
```

persea's router captures `Clients%2FAcme%2FProd` as a single `{folder}`
parameter and percent-decodes it inside the handler. This works
correctly when the reverse proxy passes the request URI through
unchanged.

Some reverse proxies **normalise the URI** before forwarding by
default: they decode `%2F` to `/` in the path, which turns the single
segment into three. persea's route definition no longer matches, and
you get a 404 on every subfolder click. Top-level folders work fine
because they have no `%2F` in their URLs.

**Symptom:** HTTP 404 from persea specifically for nested subfolder
operations; top-level folders work, subfolders don't.

**Fix per proxy:** nginx: `proxy_pass` with no path component (above).
Apache: `nocanon` (above). Caddy, Traefik, HAProxy: nothing needed;
they pass the URI through by default.

**Verify the fix:**

```bash
curl -sk -o /dev/null -w '%{http_code}\n' \
    -H "Authorization: Bearer $YOUR_API_KEY" \
    'https://console.example.com/api/addressbook/folders/shared/nonexistent%2Fsub/subfolders'
```

A correctly configured proxy returns **200** (empty array from persea,
since the folder doesn't exist but the route matches). A broken proxy
returns **404** from axum's router (because the URL was decoded into
extra path segments along the way).

## Other common mistakes

- **Forgetting `trusted_proxies`.** Client IPs show up as the proxy's
  IP in logs, and cookies miss the `Secure` attribute (see
  [Tell persea about the proxy](#tell-persea-about-the-proxy)).
- **Missing `X-Forwarded-Proto`.** If persea sees plain HTTP behind a
  TLS proxy, the session cookie lacks `Secure`. nginx sets it with
  `proxy_set_header X-Forwarded-Proto $scheme;`. (Apache's example
  above sets it with `RequestHeader`.)
- **WebSocket timeouts too short.** Sessions die mid-stream when the
  proxy's read timeout is a few minutes. Set it to match persea's
  `session_max_duration_secs` (8 h default).
- **TLS mismatch on the upstream.** The examples above use
  `https://localhost:8089` because a self-signed loopback cert is the
  common setup, so the proxy must skip verification
  (`tls_insecure_skip_verify` in Caddy, `SSLProxyVerify none` in
  Apache, `insecureSkipVerify` in Traefik). If you run persea on plain
  HTTP, use `http://localhost:8089` instead and drop those directives.
- **Exposing `/metrics`.** It is unauthenticated: restrict it via the
  proxy's ACL rules (see [API Reference](api.md#get-metrics--prometheus-metrics)).

## Self-signed certs and `secure_cookies`

When persea serves HTTPS with a self-signed certificate (or you set
`tls.secure_cookies = false` for any other reason), the `Secure`
attribute is omitted from all cookies regardless of headers, and
`X-Forwarded-Proto` is not consulted. Browsers block `Secure` cookies
over untrusted connections, so this is what makes login work behind a
self-signed loopback cert. With a real CA-issued certificate, leave
`secure_cookies` at its default (`true`): see
[Security Hardening](security-hardening.md#cookies-and-the-secure-attribute).
