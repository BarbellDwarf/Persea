# Research: Database-Backed Authentication with Enterprise Password Policies

Source: Ticket 004-database-auth.md
Date: 2026-08-01
Status: Complete

---

## 1. Argon2id Parameters for NIST 800-63B Compliance

### What NIST 800-63B Rev 4 Requires (August 2025)

From SP 800-63B §3.1.1.2 (Password Verifiers):

- Passwords **SHALL** be salted and hashed using a suitable password hashing scheme
- Salt **SHALL** be at least 32 bits in length, chosen to minimize collisions
- Both salt and hash **SHALL** be stored
- A reference to the hashing scheme and cost factor **SHOULD** be stored per password (for migration)
- Cost factor **SHOULD** be as high as practical without negative performance impact
- Cost factor **SHOULD** increase over time to account for hardware improvements

NIST does not mandate specific Argon2id parameters but requires "approved" schemes. Argon2id is the PHC winner and is explicitly recommended by OWASP.

### OWASP Recommended Parameters

| Parameter | OWASP Minimum | OWASP Recommended | Notes |
|-----------|--------------|-------------------|-------|
| Memory    | 19 MiB (19456 KiB) | 46 MiB (47104 KiB) or higher | GPU/ASIC resistance |
| Iterations (time) | 1 | 2-3 | CPU cost |
| Parallelism | 1 | 1 | Threads (match CPU cores for server) |
| Salt length | N/A | 16 bytes (128 bits) | NIST says ≥32 bits; OWASP says 16 bytes |
| Tag length  | N/A | 32 bytes | Default output |

### Recommended Production Parameters

```rust
use argon2::Params;

// Production parameters — target ~500ms on server hardware
// Adjust based on benchmarking on your deployment target
let params = Params::new(
    46_104,  // m_cost: 46 MiB in KiB (OWASP recommended minimum)
    3,       // t_cost: 3 iterations
    1,       // p_cost: 1 parallelism thread
    Some(32) // output_len: 32 bytes
).expect("valid params");
```

### Tuning Strategy

Run this benchmark at deployment to find optimal `m_cost`:

```rust
use argon2::{Argon2, Algorithm, Version, Params};
use std::time::Instant;

fn benchmark_argon2(target_ms: u64) -> Params {
    let password = b"hunter42";
    let salt = [0u8; 16];

    // Start low, double memory until we hit target time
    for m_cost in [19_456, 32_768, 46_108, 65_536, 131_072, 262_144] {
        let params = Params::new(m_cost, 3, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let start = Instant::now();
        for _ in 0..5 {
            let mut output = [0u8; 32];
            argon2.hash_password_into(password, &salt, &mut output).unwrap();
        }
        let elapsed = start.elapsed().as_millis() as u64 / 5;

        if elapsed >= target_ms {
            return params;
        }
    }
    // Fallback: highest tested
    Params::new(262_144, 3, 1, Some(32)).unwrap()
}
```

**Target**: ~500ms for password hashing on production hardware. Login verification can be slower (users expect latency on login but not on every API call).

### PHC String Format

The `argon2` crate stores parameters in the PHC hash string format:
```
$argon2id$v=19$m=46108,t=3,p=1$<base64-salt>$<base64-hash>
```

This is self-describing — parameters are embedded in the hash. Verification reads params from the stored hash, not from runtime config. This means parameter migration is free: just store the new hash on next password change.

---

## 2. Password Verification Flow

### Core Verification Pattern

```rust
use argon2::{
    password_hash::{
        self, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
        rand_core::OsRng,
    },
    Argon2, Algorithm, Version, Params,
};

/// Hash a new password with production parameters.
pub fn hash_password(password: &str) -> Result<String, password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(46_108, 3, 1, Some(32))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())  // PHC string — self-describing
}

/// Verify a password against a stored PHC hash.
/// Returns Ok(()) on match, Err on mismatch or parse failure.
pub fn verify_password(password: &str, stored_hash: &str) -> Result<(), password_hash::Error> {
    let parsed = PasswordHash::new(stored_hash)?;
    Argon2::default().verify_password(password.as_bytes(), &parsed)
}
```

**Critical**: `Argon2::default()` in verify reads params from `parsed_hash`, not from the `Argon2` instance. This means old hashes with different params verify correctly.

### Hash Migration (SHA-256 → Argon2id)

The existing codebase uses SHA-256 for API keys (`src/db.rs:289-329`). For user passwords:

1. **Dual-hash on login**: When user authenticates, try Argon2id first. If that fails, try SHA-256 (existing). If SHA-256 succeeds, re-hash with Argon2id and store the new hash.
2. **Store hash version prefix** in the `password_hash` column:
   - `$argon2id$...` — modern PHC format
   - `sha256:<hex>` — legacy (migration only, deprecate)
   - `null` / empty — no local password (SSO-only user)

```rust
pub enum PasswordHashVersion {
    Argon2id(String),  // PHC string
    LegacySha256(String),  // hex hash
    None,
}

pub fn parse_stored_hash(raw: &str) -> PasswordHashVersion {
    if raw.starts_with("$argon2") {
        PasswordHashVersion::Argon2id(raw.to_string())
    } else if let Some(hex) = raw.strip_prefix("sha256:") {
        PasswordHashVersion::LegacySha256(hex.to_string())
    } else {
        PasswordHashVersion::None
    }
}
```

---

## 3. Account Lockout: Progressive Delay

### CIS Benchmark Requirements

- Lock after 5 failed attempts
- Progressive delay: 30s → 5min → 30min
- Reset on successful login
- Do NOT permanently lock accounts (NIST 800-63B §3.2.2: rate-limiting, not permanent lockout)

### DB Schema Addition

```sql
ALTER TABLE users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN lockout_until TEXT;  -- ISO 8601 timestamp, NULL = not locked
```

### Progressive Delay Algorithm

```rust
/// Calculate lockout duration based on consecutive failed attempts.
/// Returns None if no lockout needed.
fn lockout_duration(failed_count: u32) -> Option<Duration> {
    match failed_count {
        0..=4 => None,  // No lockout for first 5 attempts (0-4)
        5 => Some(Duration::from_secs(30)),        // 30 seconds
        6 => Some(Duration::from_secs(300)),       // 5 minutes
        _ => Some(Duration::from_secs(1800)),      // 30 minutes (cap)
    }
}

/// Record a failed login attempt. Returns the lockout duration if locked.
pub fn record_failed_login(db: &Db, user_id: i64) -> Result<Option<Duration>, AuthError> {
    let db = db.lock().unwrap();

    // Increment counter and calculate lockout
    db.execute(
        "UPDATE users SET failed_login_count = failed_login_count + 1 WHERE id = ?1",
        params![user_id],
    )?;

    let count: u32 = db.query_row(
        "SELECT failed_login_count FROM users WHERE id = ?1",
        params![user_id],
        |row| row.get(0),
    )?;

    let duration = lockout_duration(count);
    if let Some(dur) = duration {
        let lockout_until = Utc::now() + dur;
        db.execute(
            "UPDATE users SET lockout_until = ?1 WHERE id = ?2",
            params![lockout_until.to_rfc3339(), user_id],
        )?;
    }

    Ok(duration)
}

/// Reset lockout on successful login.
pub fn reset_lockout(db: &Db, user_id: i64) -> Result<(), AuthError> {
    let db = db.lock().unwrap();
    db.execute(
        "UPDATE users SET failed_login_count = 0, lockout_until = NULL WHERE id = ?1",
        params![user_id],
    )?;
    Ok(())
}

/// Check if account is currently locked.
pub fn is_locked(db: &Db, user_id: i64) -> Result<bool, AuthError> {
    let db = db.lock().unwrap();
    let lockout: Option<String> = db.query_row(
        "SELECT lockout_until FROM users WHERE id = ?1",
        params![user_id],
        |row| row.get(0),
    )?;

    match lockout {
        None => Ok(false),
        Some(ts) => {
            let until = DateTime::parse_from_rfc3339(&ts)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now() - Duration::from_secs(1));
            Ok(Utc::now() < until)
        }
    }
}
```

### Login Flow Integration

```rust
pub fn authenticate_local(db: &Db, email: &str, password: &str) -> Result<User, AuthError> {
    let db = db.lock().unwrap();

    let user = db.query_row(
        "SELECT id, email, password_hash FROM users WHERE email = ?1 AND disabled = 0",
        params![email],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?)),
    ).map_err(|_| AuthError::InvalidCredentials)?;

    let (user_id, _, password_hash) = user;
    let password_hash = password_hash.ok_or(AuthError::NoLocalPassword)?;

    // Check lockout BEFORE attempting hash verification (constant-time not needed for lockout check)
    if is_locked(&db_lock, user_id)? {
        return Err(AuthError::AccountLocked);
    }

    // Verify password
    match verify_password(password, &password_hash) {
        Ok(()) => {
            reset_lockout(&db_lock, user_id)?;
            // ... return user
        }
        Err(_) => {
            let lockout_dur = record_failed_login(&db_lock, user_id)?;
            if lockout_dur.is_some() {
                Err(AuthError::AccountLocked)
            } else {
                Err(AuthError::InvalidCredentials)
            }
        }
    }
}
```

### Security Notes

- **Don't reveal whether lockout or wrong password** — return the same error for both (timing-safe)
- Use `subtle::ConstantTimeEq` for hash comparison (already in codebase for API keys)
- Rate-limit at the HTTP layer too (per-IP) to prevent lockout-based DoS
- Log lockout events to `token_audit_log` for admin visibility

---

## 4. Password Change Flow

### Self-Service Change (User Authenticated)

```sql
-- API: POST /api/auth/change-password
-- Requires: current_password, new_password
-- Flow:
-- 1. Verify current_password against stored hash
-- 2. Check password_history (last 24 passwords per CIS)
-- 3. Check HIBP breach screening
-- 4. Hash new_password with Argon2id
-- 5. Store new hash, push old hash to history
-- 6. Reset failed_login_count
```

### Admin Reset (No Old Password Required)

```sql
-- API: POST /api/admin/users/{id}/reset-password
-- Requires: admin auth, new_password
-- Flow:
-- 1. Admin must be authenticated (role = admin)
-- 2. Hash new_password with Argon2id
-- 3. Store new hash (skip history check — admin override)
-- 4. Clear lockout state
-- 5. Audit log the reset
```

### Password History (CIS: 24 passwords)

```sql
CREATE TABLE IF NOT EXISTS password_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    password_hash TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ph_user ON password_history(user_id, created_at DESC);
```

**Retention**: Keep last 24 hashes per user. On password change:

```rust
pub fn change_password(db: &Db, user_id: i64, new_hash: &str) -> Result<(), AuthError> {
    let db = db.lock().unwrap();

    // 1. Insert current hash into history BEFORE updating
    db.execute(
        "INSERT INTO password_history (user_id, password_hash)
         SELECT id, password_hash FROM users WHERE id = ?1 AND password_hash IS NOT NULL",
        params![user_id],
    )?;

    // 2. Trim history to last 24
    db.execute(
        "DELETE FROM password_history WHERE user_id = ?1 AND id NOT IN (
            SELECT id FROM password_history WHERE user_id = ?1
            ORDER BY created_at DESC LIMIT 24
        )",
        params![user_id],
    )?;

    // 3. Update current hash
    db.execute(
        "UPDATE users SET password_hash = ?1 WHERE id = ?2",
        params![new_hash, user_id],
    )?;

    // 4. Reset lockout
    db.execute(
        "UPDATE users SET failed_login_count = 0, lockout_until = NULL WHERE id = ?1",
        params![user_id],
    )?;

    Ok(())
}
```

**Check against history** before allowing new password:

```rust
pub fn is_password_reused(db: &Db, user_id: i64, new_password: &str) -> Result<bool, AuthError> {
    let db = db.lock().unwrap();
    let mut stmt = db.prepare(
        "SELECT password_hash FROM password_history WHERE user_id = ?1
         ORDER BY created_at DESC LIMIT 24"
    )?;

    let rows = stmt.query_map(params![user_id], |row| row.get::<_, String>(0))?;
    for row in rows {
        let old_hash = row?;
        if verify_password(new_password, &old_hash).is_ok() {
            return Ok(true); // Password was previously used
        }
    }
    Ok(false)
}
```

### NIST Guidance on Password Expiry

NIST 800-63B §3.1.1.1 **explicitly says**: "Verifiers and CSPs SHALL NOT require subscribers to change passwords periodically." However, forced rotation may be required by other compliance frameworks. Make it configurable:

```toml
[auth]
# NIST-compliant default: no forced rotation
# Set to 90d, 180d, etc. only if compliance requires it
password_max_age = null  # or "90d" for PCI-DSS compatibility
```

---

## 5. HIBP Breach Screening (k-Anonymity)

### How It Works

1. Hash password with SHA-1 (not Argon2id — this is for API lookup, not storage)
2. Take first 5 characters of SHA-1 hex as prefix
3. Send prefix to `https://api.pwnedpasswords.com/range/{prefix}`
4. API returns all hash suffixes with that prefix + breach count
5. Client matches full hash suffix locally
6. If match found with count > 0, password is breached

**No API key required** for Pwned Passwords. No PII is sent (k-anonymity with 5-char prefix = 16^5 = ~1M possible suffixes per response).

### Implementation

```rust
use sha1::{Sha1, Digest as Sha1Digest};
use std::collections::HashMap;

/// Check if a password has been breached via HIBP Pwned Passwords API.
/// Returns the number of times the password appeared in breaches, or 0 if clean.
pub async fn check_hibp_password(password: &str) -> Result<u32, reqwest::Error> {
    // 1. SHA-1 hash the password
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let hash_hex = format!("{:X}", hasher.finalize());  // uppercase hex

    // 2. Split: first 5 chars = prefix, rest = suffix
    let (prefix, suffix) = hash_hex.split_at(5);

    // 3. Query HIBP API (no API key needed for Pwned Passwords)
    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
    let client = reqwest::Client::builder()
        .user_agent("persea-auth")  // Required by HIBP
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let response = client.get(&url).send().await?;
    let body = response.text().await?;

    // 4. Parse response: each line is "SUFFIX:COUNT"
    for line in body.lines() {
        if let Some((suffix_part, count_str)) = line.split_once(':') {
            if suffix_part.eq_ignore_ascii_case(suffix) {
                return Ok(count_str.trim().parse::<u32>().unwrap_or(0));
            }
        }
    }

    Ok(0)  // Not found in any breach
}
```

### Integration Points

**On password creation/change**:
```rust
pub async fn validate_new_password(password: &str, email: &str) -> Result<(), ValidationError> {
    // 1. Minimum length (NIST: 15 chars for single-factor, 8 for MFA)
    if password.len() < 15 {
        return Err(ValidationError::TooShort(15));
    }

    // 2. Maximum length (NIST: at least 64)
    if password.len() > 128 {
        return Err(ValidationError::TooLong(128));
    }

    // 3. No composition rules (NIST: "SHALL NOT impose composition rules")
    // (Don't force uppercase/lowercase/symbols — just length)

    // 4. Blocklist check (NIST: "compare against blocklist")
    // Check against common passwords list (embed a subset or use HIBP)
    if is_common_password(password) {
        return Err(ValidationError::TooCommon);
    }

    // 5. Context-specific check (NIST: "context-specific words")
    let email_local = email.split('@').next().unwrap_or("");
    if password.to_lowercase().contains(&email_local.to_lowercase()) {
        return Err(ValidationError::ContainsUsername);
    }

    // 6. HIBP breach check
    let breach_count = check_hibp_password(password).await
        .unwrap_or(0);  // Fail open on network error
    if breach_count > 0 {
        return Err(ValidationError::BreachedPassword(breach_count));
    }

    Ok(())
}
```

### Rate Limiting HIBP

HIBP Pwned Passwords has no strict rate limit but is backed by Cloudflare. Respect reasonable usage:
- Check on password creation/change only (not on every login)
- Cache results for 24h per password hash prefix
- Add circuit breaker: if HIBP is down, log warning and allow (fail open)

---

## 6. Auto-Create Accounts on SSO Login

### When This Happens

User authenticates via OIDC but has no DB record yet. The system should auto-create a `users` row so the user can:
- Have a stable `user_id` for TOTP enrollment
- Be managed via role/group mappings
- Have audit trail linkage

### Fields to Populate

```sql
INSERT INTO users (email, name, oidc_subject, role, oidc_groups, created_at, last_login_at)
VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'), datetime('now'));
```

| Field | Source | Value |
|-------|--------|-------|
| `email` | OIDC `email` claim | Required |
| `name` | OIDC `preferred_username` or `name` claim | Fallback to email prefix |
| `oidc_subject` | OIDC `sub` claim | For identity binding |
| `role` | Config default + group mapping | `"viewer"` default |
| `oidc_groups` | OIDC `groups` claim | Comma-separated |
| `password_hash` | NULL | No local password — SSO only |
| `disabled` | false | Active |

### Default Role Assignment

```rust
/// Determine role for auto-created user from OIDC claims.
/// Priority: group-role-mapping > config default > "viewer"
pub fn resolve_initial_role(
    oidc_groups: &[String],
    group_role_mappings: &[(String, String)],
    default_role: &str,
) -> String {
    // Check group-role-mappings (admin-configured)
    for (group, role) in group_role_mappings {
        if oidc_groups.iter().any(|g| g == group) {
            return role.clone();
        }
    }
    default_role.to_string()
}
```

### Code Pattern (in OIDC callback handler)

```rust
// After OIDC token validation...
let user = db.get_user_by_email(&email)?;

let user = match user {
    Some(u) => {
        // Update last_login_at and oidc_groups
        db.update_user_login(&u.id, &oidc_groups)?;
        u
    }
    None => {
        // Auto-create
        let role = resolve_initial_role(&oidc_groups, &mappings, &config.default_role);
        db.create_user(&email, &name, &oidc_sub, &role, &oidc_groups)?
    }
};
```

### Post-Creation Enforcement

- Auto-created users have `password_hash = NULL` → cannot log in with local password
- Can only authenticate via OIDC until they set a local password (optional)
- Role is updatable via admin or group-role-mappings on each login

---

## 7. Password Hash Migration (SHA-256 → Argon2id)

### Strategy: Transparent Upgrade-on-Login

Users with legacy SHA-256 hashes (if migrating from a system that used them) get re-hashed transparently:

```rust
pub fn authenticate_with_migration(
    db: &Db,
    email: &str,
    password: &str,
) -> Result<User, AuthError> {
    let db = db.lock().unwrap();

    let (user_id, password_hash): (i64, Option<String>) = db.query_row(
        "SELECT id, password_hash FROM users WHERE email = ?1 AND disabled = 0",
        params![email],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(|_| AuthError::InvalidCredentials)?;

    let stored = password_hash.ok_or(AuthError::NoLocalPassword)?;

    // Check lockout first
    if is_locked(&db, user_id)? {
        return Err(AuthError::AccountLocked);
    }

    match parse_stored_hash(&stored) {
        PasswordHashVersion::Argon2id(hash) => {
            // Standard verification
            verify_password(password, &hash)
                .map_err(|_| record_failed_login(db, user_id))?;
            reset_lockout(db, user_id)?;
        }
        PasswordHashVersion::LegacySha256(hex) => {
            // Legacy: verify against SHA-256
            if !validate_sha256_legacy(password, &hex) {
                record_failed_login(db, user_id)?;
                return Err(AuthError::InvalidCredentials);
            }
            // SUCCESS: Re-hash with Argon2id
            let new_hash = hash_password(password)?;
            db.execute(
                "UPDATE users SET password_hash = ?1 WHERE id = ?2",
                params![new_hash, user_id],
            )?;
            reset_lockout(db, user_id)?;
            tracing::info!(user_id, "migrated password hash from SHA-256 to Argon2id");
        }
        PasswordHashVersion::None => {
            return Err(AuthError::NoLocalPassword);
        }
    }

    // Return user
    // ...
}
```

### Batch Migration (Optional Background Job)

For large deployments, pre-migrate hashes without requiring login:

```rust
/// Background task: migrate all SHA-256 hashes to Argon2id.
/// Requires all users to be fetched, but cannot re-hash without knowing
/// the plaintext password. This is WHY transparent upgrade-on-login is
/// the primary strategy — you cannot migrate a hash without the password.
///
/// The only batch operation possible is:
/// - Identify accounts with legacy hashes
/// - Force password reset for those accounts
/// - Or: run a script that accepts a CSV of email:password pairs
///   (from a previous export) and re-hashes them
```

**Key insight**: You cannot batch-migrate password hashes without the plaintext. The transparent upgrade-on-login is the correct approach. For a forced migration scenario (e.g., decommissioning old system), provide a "force password reset" admin action that emails users a reset link.

### Migration SQL Schema Changes

```sql
-- New columns for database auth
ALTER TABLE users ADD COLUMN password_hash TEXT;  -- PHC string (Argon2id) or NULL
ALTER TABLE users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN lockout_until TEXT;
ALTER TABLE users ADD COLUMN password_changed_at TEXT;

-- Password history table
CREATE TABLE IF NOT EXISTS password_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id),
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ph_user ON password_history(user_id, created_at DESC);

-- Local auth credentials (for users who have both SSO and local password)
-- password_hash column on users table covers this — no separate table needed.
```

---

## 8. Schema Summary

### Modified `users` Table

```sql
CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    email               TEXT NOT NULL UNIQUE,
    name                TEXT NOT NULL DEFAULT '',
    oidc_subject        TEXT,
    password_hash       TEXT,           -- NEW: PHC string (Argon2id) or NULL
    failed_login_count  INTEGER NOT NULL DEFAULT 0,  -- NEW
    lockout_until       TEXT,           -- NEW: ISO 8601 or NULL
    password_changed_at TEXT,           -- NEW: for password age tracking
    role                TEXT NOT NULL DEFAULT 'viewer',
    disabled            INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    last_login_at       TEXT,
    oidc_groups         TEXT NOT NULL DEFAULT ''
);
```

### New `password_history` Table

```sql
CREATE TABLE IF NOT EXISTS password_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id),
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
```

---

## 9. Dependencies

Add to `Cargo.toml`:

```toml
argon2 = "0.5"    # Password hashing (Argon2id)
sha1 = "0.10"     # HIBP k-anonymity lookup only (NOT for password storage)
reqwest = { version = "0.12", features = ["json"] }  # HIBP API client (likely already present)
```

The existing `sha2` crate (SHA-256) is used for API key hashing — leave it as-is. The `argon2` crate replaces it for user password hashing only.

---

## 10. References

- **NIST SP 800-63B Rev 4** (August 2025): https://pages.nist.gov/800-63-4/sp800-63b.html — §3.1.1 Passwords
- **OWASP Password Storage Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- **OWASP Authentication Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- **HIBP Pwned Passwords API**: https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange
- **Troy Hunt: k-Anonymity explanation**: https://www.troyhunt.com/understanding-have-i-been-pwneds-use-of-sha-1-and-k-anonymity/
- **Rust `argon2` crate**: https://docs.rs/argon2/latest/argon2/
- **Password Hashing Competition**: https://password-hashing.net/
- **CIS Benchmarks**: Account lockout after 5 failures, progressive delay, 24-password history
