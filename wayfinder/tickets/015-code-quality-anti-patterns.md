# Ticket: Code Quality Anti-Patterns

**Type:** grilling
**Labels:** code-quality, wayfinder:grilling

## Question

Which code quality anti-patterns should be addressed first?

### Findings:

**Duplicated logic:**
- `role_level()` defined identically in `auth.rs:116` and `db.rs:1430`
- Cookie extraction duplicated across `auth.rs:159` and `oidc.rs:522`
- VDI username sanitization duplicated in 3 places (`session.rs:1280`, `api.rs:491`, `api.rs:541`)
- Admin role validation string `["admin","poweruser","operator","viewer"]` repeated in 4 places
- `applyThemeColors()`, `escapeHtml()`, `apiHeaders()` copy-pasted across all HTML files

**Magic values:**
- Session types as string literals instead of enum
- Roles as string literals instead of enum
- Hardcoded rate limit values (`per_second(2).burst_size(10)`)
- Hardcoded 1 MiB protocol buffer cap
- Hardcoded 100,000 row CSV export limit

**Structural issues:**
- `CreateSessionRequest` has 60+ optional fields
- `AddressBookEntry` has 80+ fields
- `ThemeColors` has 33 fields duplicated as `Option<String>` in `ThemeConfig`
- 30+ default functions in `config.rs` that could use `#[serde(default)]`
- `#[allow(clippy::too_many_arguments)]` in 10+ places

**Missing traits:**
- `SessionType` missing `Eq` (all fieldless variants)
- `SessionStatus` missing `Eq` and `Hash`
- `ParseError` missing `PartialEq`
- Error types missing `#[must_use]`

### Decision needed:

1. Priority: duplicated logic first, or structural issues?
2. Role handling: create `Role` enum with `FromStr` and `is_valid()`?
3. Session types: create `TryFrom<&str>` for `SessionType`?
4. Should clippy pedantic warnings be enabled?
