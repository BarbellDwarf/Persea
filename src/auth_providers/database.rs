//! Database auth provider — local username/password authentication.
//!
//! Looks up users in the SQLite `users` table by email and verifies
//! an Argon2id password hash.  Requires a `password_hash` column
//! (added automatically on first use).

use async_trait::async_trait;
use rusqlite::params;

use crate::auth_provider::{AuthProvider, AuthRequest, AuthResult, Capabilities};
use crate::db::Db;
use crate::password::verify_password;

/// Local database authentication provider.
pub struct DatabaseProvider {
    db: Db,
}

impl DatabaseProvider {
    /// Create a new database provider and ensure the schema is up to date.
    pub fn new(db: Db) -> Self {
        Self::ensure_schema(&db);
        Self { db }
    }

    /// Add the `password_hash` column to the `users` table if it doesn't exist.
    fn ensure_schema(db: &Db) {
        let conn = db.lock().unwrap();
        let has_col: bool = conn
            .prepare("SELECT password_hash FROM users LIMIT 0")
            .is_ok();
        if !has_col {
            conn.execute_batch("ALTER TABLE users ADD COLUMN password_hash TEXT")
                .expect("failed to add password_hash column");
        }
    }
}

#[async_trait]
impl AuthProvider for DatabaseProvider {
    fn id(&self) -> &str {
        "database"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::AUTHENTICATE | Capabilities::STORE_PASSWORDS
    }

    fn has_inline_login_form(&self) -> bool {
        true
    }

    async fn authenticate(&self, request: &AuthRequest) -> AuthResult {
        let username = match &request.username {
            Some(u) if !u.is_empty() => u.clone(),
            _ => return AuthResult::Failure("missing username".into()),
        };
        let password = match &request.password {
            Some(p) if !p.is_empty() => p.clone(),
            _ => return AuthResult::Failure("missing password".into()),
        };

        // Query user by email (= username for local auth)
        let result = {
            let conn = self.db.lock().unwrap();
            conn.query_row(
                "SELECT id, email, name, role, disabled, password_hash
                 FROM users WHERE email = ?1",
                params![username],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i32>(4)? != 0,
                        row.get::<_, Option<String>>(5)?,
                    ))
                },
            )
        };

        let (id, email, name, role, disabled, password_hash) = match result {
            Ok(r) => r,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                // Constant-time dummy hash to prevent user enumeration
                let _ = verify_password(
                    "dummy",
                    "$argon2id$v=19$m=47104,t=3,p=1$c2FsdHNhbHRzYWx0$hashhashhashhashhashhash",
                );
                return AuthResult::Failure("invalid credentials".into());
            }
            Err(e) => return AuthResult::Unavailable(format!("database error: {e}")),
        };

        if disabled {
            return AuthResult::Failure("account is disabled".into());
        }

        let hash = match password_hash {
            Some(h) if !h.is_empty() => h,
            _ => return AuthResult::Failure("no password set for this account".into()),
        };

        match verify_password(&password, &hash) {
            Ok(true) => {
                // Update last_login_at
                let _ = {
                    let conn = self.db.lock().unwrap();
                    conn.execute(
                        "UPDATE users SET last_login_at = datetime('now') WHERE id = ?1",
                        params![id],
                    )
                };

                AuthResult::Success {
                    subject: email.clone(),
                    display_name: name,
                    groups: vec![],
                    role: Some(role),
                }
            }
            Ok(false) => AuthResult::Failure("invalid credentials".into()),
            Err(e) => AuthResult::Unavailable(format!("password verify error: {e}")),
        }
    }

    async fn lookup_user(&self, subject: &str) -> Option<crate::auth_provider::UserInfo> {
        let conn = self.db.lock().unwrap();
        conn.query_row(
            "SELECT id, email, name, role, disabled, oidc_groups
             FROM users WHERE email = ?1",
            params![subject],
            |row| {
                let disabled: bool = row.get::<_, i32>(4)? != 0;
                if disabled {
                    return Err(rusqlite::Error::QueryReturnedNoRows);
                }
                let groups_raw: String = row.get(5)?;
                let groups = if groups_raw.is_empty() {
                    vec![]
                } else {
                    groups_raw.split(',').map(|s| s.to_string()).collect()
                };
                Ok(crate::auth_provider::UserInfo {
                    subject: row.get(1)?,
                    display_name: row.get(2)?,
                    email: None,
                    groups,
                })
            },
        )
        .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn test_db() -> Db {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                email         TEXT NOT NULL UNIQUE,
                name          TEXT NOT NULL DEFAULT '',
                oidc_subject  TEXT,
                role          TEXT NOT NULL DEFAULT 'viewer',
                disabled      INTEGER NOT NULL DEFAULT 0,
                created_at    TEXT NOT NULL DEFAULT (datetime('now')),
                last_login_at TEXT,
                oidc_groups   TEXT NOT NULL DEFAULT '',
                password_hash TEXT
            );",
        )
        .unwrap();
        std::sync::Arc::new(std::sync::Mutex::new(conn))
    }

    #[tokio::test]
    async fn authenticate_success() {
        use crate::password::hash_password;

        let db = test_db();
        let pw_hash = hash_password("secret123").unwrap();
        {
            let conn = db.lock().unwrap();
            conn.execute(
                "INSERT INTO users (email, name, password_hash) VALUES ('alice@example.com', 'Alice', ?1)",
                params![pw_hash],
            )
            .unwrap();
        }

        let provider = DatabaseProvider::new(db);
        let req = AuthRequest {
            username: Some("alice@example.com".into()),
            password: Some("secret123".into()),
            ..Default::default()
        };
        match provider.authenticate(&req).await {
            AuthResult::Success { subject, .. } => assert_eq!(subject, "alice@example.com"),
            other => panic!("expected Success, got {other}"),
        }
    }

    #[tokio::test]
    async fn authenticate_wrong_password() {
        use crate::password::hash_password;

        let db = test_db();
        let pw_hash = hash_password("correct").unwrap();
        {
            let conn = db.lock().unwrap();
            conn.execute(
                "INSERT INTO users (email, name, password_hash) VALUES ('bob@example.com', 'Bob', ?1)",
                params![pw_hash],
            )
            .unwrap();
        }

        let provider = DatabaseProvider::new(db);
        let req = AuthRequest {
            username: Some("bob@example.com".into()),
            password: Some("wrong".into()),
            ..Default::default()
        };
        assert!(matches!(
            provider.authenticate(&req).await,
            AuthResult::Failure(_)
        ));
    }

    #[tokio::test]
    async fn authenticate_unknown_user() {
        let db = test_db();
        let provider = DatabaseProvider::new(db);
        let req = AuthRequest {
            username: Some("nobody@example.com".into()),
            password: Some("pw".into()),
            ..Default::default()
        };
        assert!(matches!(
            provider.authenticate(&req).await,
            AuthResult::Failure(_)
        ));
    }

    #[tokio::test]
    async fn authenticate_disabled_user() {
        use crate::password::hash_password;

        let db = test_db();
        let pw_hash = hash_password("pw").unwrap();
        {
            let conn = db.lock().unwrap();
            conn.execute(
                "INSERT INTO users (email, name, role, disabled, password_hash)
                 VALUES ('dis@example.com', 'Dis', 'viewer', 1, ?1)",
                params![pw_hash],
            )
            .unwrap();
        }

        let provider = DatabaseProvider::new(db);
        let req = AuthRequest {
            username: Some("dis@example.com".into()),
            password: Some("pw".into()),
            ..Default::default()
        };
        assert!(matches!(
            provider.authenticate(&req).await,
            AuthResult::Failure(_)
        ));
    }

    #[test]
    fn capabilities_include_password_store() {
        let db = test_db();
        let provider = DatabaseProvider::new(db);
        assert!(provider.capabilities().contains(Capabilities::AUTHENTICATE));
        assert!(provider
            .capabilities()
            .contains(Capabilities::STORE_PASSWORDS));
    }

    #[test]
    fn has_inline_login_form() {
        let db = test_db();
        let provider = DatabaseProvider::new(db);
        assert!(provider.has_inline_login_form());
    }

    #[tokio::test]
    async fn missing_fields_fail() {
        let db = test_db();
        let provider = DatabaseProvider::new(db);

        let req = AuthRequest {
            username: None,
            password: Some("pw".into()),
            ..Default::default()
        };
        assert!(matches!(
            provider.authenticate(&req).await,
            AuthResult::Failure(_)
        ));

        let req = AuthRequest {
            username: Some("user".into()),
            password: None,
            ..Default::default()
        };
        assert!(matches!(
            provider.authenticate(&req).await,
            AuthResult::Failure(_)
        ));
    }
}
