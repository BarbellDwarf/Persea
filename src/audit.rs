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

/// A single audit event stored in the hash chain.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub user_id: Option<String>,
    pub source_ip: Option<String>,
    pub outcome: String,
    pub details: serde_json::Value,
    pub session_id: Option<String>,
    pub prev_hash: String,
    pub event_hash: String,
}

/// Result of chain verification.
#[derive(Debug, Clone)]
pub struct ChainVerification {
    pub status: ChainStatus,
    pub events_scanned: u64,
    pub errors: Vec<ChainError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStatus {
    Verified,
    Broken,
}

#[derive(Debug, Clone)]
pub struct ChainError {
    pub event_id: i64,
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

    pub fn user_id(mut self, id: impl Into<String>) -> Self {
        self.user_id = Some(id.into());
        self
    }

    pub fn source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self
    }

    pub fn details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }

    pub fn session_id(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent {
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

    let mut events_scanned: u64 = 0;
    let mut errors = Vec::new();
    let mut prev_event_hash: Option<String> = None;

    for row in rows {
        let (id, event) = row?;
        events_scanned += 1;

        // Verify hash chain linkage
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
        } else {
            // First event in range: prev_hash should be the genesis hash (64 zeros) or match
            if event.prev_hash != "0".repeat(64) {
                // Not the very first event — possible gap, flag it
                // Only flag if this isn't the absolute first event in the table
                let first_id: Option<i64> = conn
                    .query_row("SELECT MIN(id) FROM audit_events", [], |row| row.get(0))
                    .ok()
                    .flatten();
                if first_id != Some(id) {
                    errors.push(ChainError {
                        event_id: id,
                        message: format!(
                            "prev_hash {} does not match genesis hash or preceding event",
                            event.prev_hash
                        ),
                    });
                }
            }
        }

        // Verify event hash recomputation
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

    Ok(ChainVerification {
        status: if errors.is_empty() {
            ChainStatus::Verified
        } else {
            ChainStatus::Broken
        },
        events_scanned,
        errors,
    })
}
