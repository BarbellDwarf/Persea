# Ticket: Security Hardening — API Key Hashing & Auth Fixes

**Type:** research + task
**Labels:** security, wayfinder:research

## Question

What is the right approach to fix the security findings in the auth layer?

### Findings to resolve:

**H1. SHA-256 without salt for API key hashing** (`src/db.rs:289-293`)
- Keys are 256-bit random hex (rainbow tables impractical), but DB breach allows offline brute-force
- `validate_api_key` iterates ALL stored hashes — O(N) per auth attempt
- Recommendation: Add per-key random salt, or migrate to Argon2id/bcrypt

**H2. API key in query parameter** (`src/auth.rs:374-389`)
- `?key=` fallback allows keys in URLs (browser history, server logs)
- WebSocket ticket system exists specifically to avoid this
- Recommendation: Deprecate and remove `?key=` path

**H3. OIDC state cookie not bound to session fingerprint** (`src/oidc.rs:148-151`)
- State cookie not bound to IP/user-agent hash
- PKCE protects token exchange but state cookie comparison is plain equality
- Recommendation: Bind state to client-bound nonce or signed cookie

**H4. No CSRF protection on state-changing REST endpoints** (`src/api.rs`)
- Bearer tokens + session cookies only, no CSRF tokens
- `SameSite=Lax` mitigates most POST CSRF but GET-based state changes still vulnerable
- Recommendation: Add CSRF token header check for state-changing operations

**M1. VDI chpasswd command injection** (`src/vdi/docker.rs:339`)
- Shell interpolation with single quotes: `printf '%s:%s' '{}' '{}' | chpasswd`
- Username from Vault entries could contain single quote
- Recommendation: Use stdin-piped approach instead of shell interpolation

**M5. Vault token stored without zeroing** (`src/vault.rs:582`)
- Token as plain `String` in memory, not zeroed on drop
- Recommendation: Use `zeroize::Zeroizing<String>`

**M7. Origin check allows empty Origin/Host** (`src/websocket.rs:587-600`)
- Empty Origin/Host silently bypasses CSWSH protection
- Recommendation: Reject WebSocket upgrades when Origin is missing

**M8. No rate limiting on WebSocket connections** (`src/main.rs`)
- Rate limiting applies to API but not `/ws/:session_id` upgrade
- Recommendation: Add per-IP rate limiting on WebSocket upgrade requests

**L7. No Content-Security-Policy headers** (all static HTML)
- CSP allows `'unsafe-inline'` for scripts due to inline JS
- Recommendation: Add nonce-based CSP or extract JS to external files

### Decision needed:

1. Salt strategy for API keys: per-key random salt stored alongside hash, or migrate to Argon2id?
2. Remove `?key=` fallback entirely, or deprecate with warning period?
3. CSRF protection approach: double-submit cookie, synchronizer token, or header-based?
4. Should `zeroize` become a hard dependency?
5. WebSocket rate limit values and config options?
