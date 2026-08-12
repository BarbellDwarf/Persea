//! Audit logging with SHA-256 hash chain for tamper evidence.
//!
//! # Tamper-Evidence, Not Tamper-Proof
//!
//! The hash chain makes tampering *detectable* but not *impossible*. An attacker
//! with direct database-write access can delete or rewrite a range of rows and
//! regenerate a valid chain from that point forward (each row stores only the
//! previous hash, so a new anchor trivially chains). The chain therefore provides
//! **tamper-evidence** — it lets honest parties detect that something was altered —
//! but does **not** provide tamper-proofing.
//!
//! For enterprise deployments that require stronger guarantees, consider one or
//! more of the following countermeasures:
//!
//! - **Periodic external anchoring** — after each rotation, publish a signed
//!   timestamp of the latest `event_hash` to an external system (e.g. a
//!   notarisation service, append-only log, or blockchain).
//! - **Write-Once-Read-Many (WORM) storage** — replicate audit rows to
//!   append-only storage that prevents in-place modification.
//! - **Immutable replication** — stream audit events to a separate,
//!   access-controlled replica as soon as they are written.

use crate::db::Db;
use chrono::{DateTime, Utc};
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Filters for querying audit events.
#[derive(Debug, Clone, Default)]
pub struct AuditFilters {
    /// Match events for this user ID.
    pub user_id: Option<String>,
    /// Match events of this type, e.g. login or session_start.
    pub event_type: Option<String>,
    /// Match events with this outcome.
    pub outcome: Option<String>,
    /// Include events at or after this RFC3339 timestamp.
    pub from: Option<String>,
    /// Include events at or before this RFC3339 timestamp.
    pub to: Option<String>,
}

/// A single audit event stored in the hash chain.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEvent {
    /// Database row ID; 0 for events not yet logged.
    pub id: i64,
    /// Event type name, e.g. login or session_start.
    pub event_type: String,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// ID of the user the event concerns, when applicable.
    pub user_id: Option<String>,
    /// Client IP address the event came from, when known.
    pub source_ip: Option<String>,
    /// Success or failure outcome.
    pub outcome: String,
    /// Free-form event payload.
    pub details: serde_json::Value,
    /// ID of the session the event belongs to, when applicable.
    pub session_id: Option<String>,
    /// SHA-256 hash of the preceding event; chains this event to it.
    pub prev_hash: String,
    /// SHA-256 hash of this event's own fields.
    pub event_hash: String,
}

/// Result of chain verification.
#[derive(Debug, Clone)]
pub struct ChainVerification {
    /// Overall verdict of the scan.
    pub status: ChainStatus,
    /// How many events were scanned.
    pub events_scanned: u64,
    /// Individual failures; empty when the chain verifies.
    pub errors: Vec<ChainError>,
}

/// Overall verdict of a chain verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStatus {
    /// Every scanned event chained and hashed correctly.
    Verified,
    /// At least one event failed its hash or chain check.
    Broken,
}

/// One failed check found during chain verification.
#[derive(Debug, Clone)]
pub struct ChainError {
    /// ID of the event that failed.
    pub event_id: i64,
    /// Why the check failed.
    pub message: String,
}

/// Convenience builder for creating audit events.
pub struct EventBuilder {
    event_type: String,
    user_id: Option<String>,
    source_ip: Option<String>,
    outcome: String,
    details: serde_json::Value,
    session_id: Option<String>,
}

impl EventBuilder {
    /// Start building an event with its type and outcome; every other
    /// field is optional.
    pub fn new(event_type: impl Into<String>, outcome: impl Into<String>) -> Self {
        Self {
            event_type: event_type.into(),
            user_id: None,
            source_ip: None,
            outcome: outcome.into(),
            details: serde_json::Value::Null,
            session_id: None,
        }
    }

    /// Set the user the event concerns.
    pub fn user_id(mut self, id: impl Into<String>) -> Self {
        self.user_id = Some(id.into());
        self
    }

    /// Set the client IP the event came from.
    pub fn source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self
    }

    /// Set the event payload.
    pub fn details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }

    /// Attach the event to a session.
    pub fn session_id(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    /// Produce the final event, stamped with the current time and empty
    /// hash fields (filled in by [`log_event`]).
    pub fn build(self) -> AuditEvent {
        AuditEvent {
            id: 0,
            event_type: self.event_type,
            timestamp: Utc::now(),
            user_id: self.user_id,
            source_ip: self.source_ip,
            outcome: self.outcome,
            details: self.details,
            session_id: self.session_id,
            prev_hash: String::new(),
            event_hash: String::new(),
        }
    }
}

/// Compute the SHA-256 hash of an audit event using canonical JSON (sorted keys, no whitespace).
/// The hash covers: event_type, timestamp, user_id, source_ip, outcome, details, session_id.
pub fn compute_event_hash(event: &AuditEvent) -> String {
    let mut fields: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
    fields.insert(
        "event_type",
        serde_json::Value::String(event.event_type.clone()),
    );
    fields.insert(
        "timestamp",
        serde_json::Value::String(event.timestamp.to_rfc3339()),
    );
    if let Some(ref uid) = event.user_id {
        fields.insert("user_id", serde_json::Value::String(uid.clone()));
    }
    if let Some(ref ip) = event.source_ip {
        fields.insert("source_ip", serde_json::Value::String(ip.clone()));
    }
    fields.insert("outcome", serde_json::Value::String(event.outcome.clone()));
    fields.insert("details", event.details.clone());
    if let Some(ref sid) = event.session_id {
        fields.insert("session_id", serde_json::Value::String(sid.clone()));
    }

    let canonical = serde_json::to_string(&fields).expect("BTreeMap serialization cannot fail");
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

/// Log an audit event: compute its hash, chain it to the previous event, insert, and return the
/// event's database ID.
pub fn log_event(db: &Db, event: &mut AuditEvent) -> rusqlite::Result<i64> {
    if crate::db::pool_active() {
        let owned = event.clone();
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::audit_log_event_pool(pool, owned)
        });
    }
    let conn = db.lock().unwrap();

    // Fetch previous event's hash for chaining
    let prev_hash: String = conn
        .query_row(
            "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|_| "0".repeat(64)); // Genesis hash: 64 zeros

    event.prev_hash = prev_hash;
    event.event_hash = compute_event_hash(event);

    let details_str = if event.details.is_null() {
        None
    } else {
        Some(event.details.to_string())
    };

    conn.execute(
        "INSERT INTO audit_events (event_type, timestamp, user_id, source_ip, outcome, details, session_id, prev_hash, event_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            event.event_type,
            event.timestamp.to_rfc3339(),
            event.user_id,
            event.source_ip,
            event.outcome,
            details_str,
            event.session_id,
            event.prev_hash,
            event.event_hash,
        ],
    )?;

    Ok(conn.last_insert_rowid())
}

/// Verify the integrity of the audit hash chain.
///
/// Scans events from `from` (inclusive) to `to` (inclusive) timestamp. Pass `None` to scan from
/// the beginning or to the end. Each event's `prev_hash` must match the preceding event's
/// `event_hash`, and `event_hash` must recompute correctly.
///
/// **What this checks:** that consecutive events form a valid SHA-256 chain and that every
/// event's hash matches its recomputed value.
///
/// **What this does NOT protect against:** an attacker with DB-write access who truncates the
/// chain at a chosen point and appends freshly forged events — the new tail will verify
/// correctly because it only chains against itself. For stronger guarantees, combine with
/// external anchoring or WORM storage (see module docs).
pub fn verify_chain(
    db: &Db,
    from: Option<&str>,
    to: Option<&str>,
) -> rusqlite::Result<ChainVerification> {
    if crate::db::pool_active() {
        let from_s = from.map(str::to_string);
        let to_s = to.map(str::to_string);
        let events = crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::audit_events_pool(pool, from_s, to_s)
        })?;
        let first_id = crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::audit_first_id_pool(pool)
        })?;
        return Ok(verify_events(events, first_id));
    }
    let conn = db.lock().unwrap();

    let mut conditions = Vec::new();
    let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

    if let Some(f) = from {
        conditions.push("timestamp >= ?1".to_string());
        param_values.push(Box::new(f.to_string()));
    }
    if let Some(t) = to {
        let pos = param_values.len() + 1;
        conditions.push(format!("timestamp <= ?{}", pos));
        param_values.push(Box::new(t.to_string()));
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let sql = format!(
        "SELECT id, event_type, timestamp, user_id, source_ip, outcome, details, session_id, prev_hash, event_hash
         FROM audit_events {} ORDER BY id ASC",
        where_clause
    );

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(param_values.iter()), |row| {
        let details_str: Option<String> = row.get(6)?;
        let details: serde_json::Value = match details_str {
            Some(s) => serde_json::from_str(&s).unwrap_or(serde_json::Value::Null),
            None => serde_json::Value::Null,
        };
        Ok((
            row.get::<_, i64>(0)?,
            AuditEvent {
                id: row.get::<_, i64>(0)?,
                event_type: row.get(1)?,
                timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(2)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                user_id: row.get(3)?,
                source_ip: row.get(4)?,
                outcome: row.get(5)?,
                details,
                session_id: row.get(7)?,
                prev_hash: row.get(8)?,
                event_hash: row.get(9)?,
            },
        ))
    })?;

    let mut events = Vec::new();
    for row in rows {
        events.push(row?);
    }
    let first_id: Option<i64> = conn
        .query_row("SELECT MIN(id) FROM audit_events", [], |row| row.get(0))
        .ok()
        .flatten();
    Ok(verify_events(events, first_id))
}

/// Verify the hash chain over an in-memory event list (shared by the
/// rusqlite and SQLx backends so both produce byte-identical verdicts).
fn verify_events(events: Vec<(i64, AuditEvent)>, first_id: Option<i64>) -> ChainVerification {
    let mut events_scanned: u64 = 0;
    let mut errors = Vec::new();
    let mut prev_event_hash: Option<String> = None;

    for (id, event) in events {
        events_scanned += 1;

        if let Some(ref expected) = prev_event_hash {
            if event.prev_hash != *expected {
                errors.push(ChainError {
                    event_id: id,
                    message: format!(
                        "prev_hash mismatch: expected {}, got {}",
                        expected, event.prev_hash
                    ),
                });
            }
        } else if event.prev_hash != "0".repeat(64) && first_id != Some(id) {
            errors.push(ChainError {
                event_id: id,
                message: format!(
                    "prev_hash {} does not match genesis hash or preceding event",
                    event.prev_hash
                ),
            });
        }

        let computed = compute_event_hash(&event);
        if computed != event.event_hash {
            errors.push(ChainError {
                event_id: id,
                message: format!(
                    "event_hash mismatch: stored={}, recomputed={}",
                    event.event_hash, computed
                ),
            });
        }

        prev_event_hash = Some(event.event_hash.clone());
    }

    ChainVerification {
        status: if errors.is_empty() {
            ChainStatus::Verified
        } else {
            ChainStatus::Broken
        },
        events_scanned,
        errors,
    }
}

/// Build a WHERE clause and parameter list from optional filters.
fn build_filter_clause(filters: &AuditFilters) -> (String, Vec<Box<dyn rusqlite::types::ToSql>>) {
    let mut conditions = Vec::new();
    let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

    if let Some(ref user_id) = filters.user_id {
        let pos = param_values.len() + 1;
        conditions.push(format!("user_id = ?{}", pos));
        param_values.push(Box::new(user_id.clone()));
    }
    if let Some(ref event_type) = filters.event_type {
        let pos = param_values.len() + 1;
        conditions.push(format!("event_type = ?{}", pos));
        param_values.push(Box::new(event_type.clone()));
    }
    if let Some(ref outcome) = filters.outcome {
        let pos = param_values.len() + 1;
        conditions.push(format!("outcome = ?{}", pos));
        param_values.push(Box::new(outcome.clone()));
    }
    if let Some(ref from) = filters.from {
        let pos = param_values.len() + 1;
        conditions.push(format!("timestamp >= ?{}", pos));
        param_values.push(Box::new(from.clone()));
    }
    if let Some(ref to) = filters.to {
        let pos = param_values.len() + 1;
        conditions.push(format!("timestamp <= ?{}", pos));
        param_values.push(Box::new(to.clone()));
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    (where_clause, param_values)
}

/// List audit events with optional filters, pagination, and ordering (newest first).
pub fn list_events(
    db: &Db,
    limit: u64,
    offset: u64,
    filters: &AuditFilters,
) -> rusqlite::Result<Vec<AuditEvent>> {
    if crate::db::pool_active() {
        let filters = filters.clone();
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::audit_list_events_pool(pool, limit, offset, filters)
        });
    }
    let conn = db.lock().unwrap();
    let (where_clause, param_values) = build_filter_clause(filters);

    let sql = format!(
        "SELECT id, event_type, timestamp, user_id, source_ip, outcome, details, session_id, prev_hash, event_hash
         FROM audit_events {} ORDER BY id DESC LIMIT ?{} OFFSET ?{}",
        where_clause,
        param_values.len() + 1,
        param_values.len() + 2,
    );

    let mut stmt = conn.prepare(&sql)?;
    let mut all_params: Vec<Box<dyn rusqlite::types::ToSql>> = param_values;
    all_params.push(Box::new(limit));
    all_params.push(Box::new(offset));

    let rows = stmt.query_map(rusqlite::params_from_iter(all_params.iter()), |row| {
        let details_str: Option<String> = row.get(6)?;
        let details: serde_json::Value = match details_str {
            Some(s) => serde_json::from_str(&s).unwrap_or(serde_json::Value::Null),
            None => serde_json::Value::Null,
        };
        Ok(AuditEvent {
            id: row.get(0)?,
            event_type: row.get(1)?,
            timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(2)?)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            user_id: row.get(3)?,
            source_ip: row.get(4)?,
            outcome: row.get(5)?,
            details,
            session_id: row.get(7)?,
            prev_hash: row.get(8)?,
            event_hash: row.get(9)?,
        })
    })?;

    let mut events = Vec::new();
    for row in rows {
        events.push(row?);
    }
    Ok(events)
}

/// Count audit events matching optional filters.
pub fn count_events(db: &Db, filters: &AuditFilters) -> rusqlite::Result<u64> {
    if crate::db::pool_active() {
        let filters = filters.clone();
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::audit_count_events_pool(pool, filters)
        });
    }
    let conn = db.lock().unwrap();
    let (where_clause, param_values) = build_filter_clause(filters);

    let sql = format!("SELECT COUNT(*) FROM audit_events {}", where_clause);

    let count: u64 = conn.query_row(
        &sql,
        rusqlite::params_from_iter(param_values.iter()),
        |row| row.get(0),
    )?;
    Ok(count)
}

/// Export audit events as CSV with optional filters.
pub fn export_events_csv(db: &Db, filters: &AuditFilters) -> rusqlite::Result<String> {
    let events = list_events(db, 100000, 0, filters)?; // large limit for export
    let mut out = String::new();
    out.push_str(
        "id,timestamp,event_type,user_id,source_ip,outcome,details,session_id,event_hash\n",
    );

    for event in &events {
        let details_str = if event.details.is_null() {
            String::new()
        } else {
            event.details.to_string()
        };
        // Escape fields that might contain commas or quotes
        let escape_csv = |s: &str| -> String {
            if s.contains(',') || s.contains('"') || s.contains('\n') {
                format!("\"{}\"", s.replace('"', "\"\""))
            } else {
                s.to_string()
            }
        };

        out.push_str(&escape_csv(&event.id.to_string()));
        out.push(',');
        out.push_str(&escape_csv(&event.timestamp.to_rfc3339()));
        out.push(',');
        out.push_str(&escape_csv(&event.event_type));
        out.push(',');
        out.push_str(&escape_csv(event.user_id.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&escape_csv(event.source_ip.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&escape_csv(&event.outcome));
        out.push(',');
        out.push_str(&escape_csv(&details_str));
        out.push(',');
        out.push_str(&escape_csv(event.session_id.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&escape_csv(&event.event_hash));
        out.push('\n');
    }
    Ok(out)
}
