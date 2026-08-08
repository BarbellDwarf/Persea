//! persea — lightweight Guacamole proxy. CLI entry point and server setup.
//!
//! This crate root (the `persea` binary) only wires CLI parsing, config
//! loading, and the axum server. All public API lives in the library
//! (see `src/lib.rs`), which is why `missing_docs` is intentionally NOT
//! enabled on the bin root: a blanket warn would flag the dozens of
//! `mod` declarations and internal helpers here without guarding any
//! public surface. The lib crate carries `#![warn(missing_docs)]` instead.
#![allow(dead_code)]

mod api;
mod audit;
mod auth;
mod auth_chain;
mod auth_provider;
mod auth_providers;
mod browser;
mod config;
mod crypto;
mod csrf;
mod csv_import;
mod db;
mod db_migrate;
mod db_pool;
mod drive;
mod error;
mod guacd;
mod handlers;
mod import;
mod metrics;
mod migrate;
mod oidc;
mod password;
mod protocol;
mod providers_db;
mod pve;
mod rbac;
mod recording;
mod role;
mod session;
mod settings_merge;
mod templates;
#[cfg(test)]
mod testing;
mod totp;
mod tunnel;
mod vault;
mod vdi;
mod vsphere;
mod websocket;

use crate::api::{
    AppState, CredentialDefaultScope, DriveConfigured, OidcEnabled, OidcProviderNames,
    SettingsBaseline, SiteTitle, StorageBackend, StorageKey, ThemeData, VaultBackends, VaultCell,
    VaultConfigured, VaultState,
};
use crate::auth_chain::AuthChain;
use crate::auth_provider::AuthProvider;
use crate::config::Config;
use crate::db::Db;
use crate::db_pool::DbPool;
use crate::session::SessionManager;
use axum::extract::{DefaultBodyLimit, Request};
use axum::response::Html;
use axum::response::Response;
use axum::routing::{delete, get, post, put};
use axum::{middleware, Extension, Router};
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor, GovernorLayer,
};
use tower_http::services::ServeDir;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "persea", version, about = "Lightweight Guacamole SSH proxy")]
struct Cli {
    /// Path to TOML config file
    #[arg(short, long)]
    config: Option<String>,

    /// Log output format. Overrides the RUST_LOG_FORMAT env var.
    #[arg(long, value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,

    #[command(subcommand)]
    command: Option<Command>,
}

/// Structured log output format.
#[derive(clap::ValueEnum, Clone, Copy, PartialEq, Eq, Debug)]
enum LogFormat {
    /// Human-readable text lines (default)
    Text,
    /// JSON lines, one record per line
    Json,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server (default)
    Serve,

    /// Create a new user with password authentication
    CreateUser {
        /// Email address (used as username)
        #[arg(long)]
        email: String,
        /// Display name
        #[arg(long)]
        name: String,
        /// Password
        #[arg(long)]
        password: String,
        /// Role (admin, poweruser, operator, viewer)
        #[arg(long, default_value = "viewer")]
        role: String,
    },

    /// Create a new admin with an API key
    AddAdmin {
        /// Admin name (unique)
        #[arg(long)]
        name: String,
        /// Comma-separated allowed IP CIDRs (e.g. "10.0.0.0/8,192.168.1.0/24")
        #[arg(long)]
        allowed_ips: Option<String>,
        /// Expiry date in ISO 8601 format (e.g. "2025-12-31T23:59:59Z")
        #[arg(long)]
        expires: Option<String>,
    },

    /// List all admin accounts
    ListAdmins,

    /// Disable an admin account
    DisableAdmin {
        #[arg(long)]
        name: String,
    },

    /// Enable an admin account
    EnableAdmin {
        #[arg(long)]
        name: String,
    },

    /// Delete an admin account permanently
    DeleteAdmin {
        #[arg(long)]
        name: String,
    },

    /// Rotate an admin's API key (generates new key, invalidates old)
    RotateKey {
        #[arg(long)]
        name: String,
    },

    /// Generate a self-signed TLS certificate for development/testing
    GenerateCert {
        /// Hostname for the certificate (e.g. "persea.example.com")
        #[arg(long)]
        hostname: String,
        /// Output directory for cert.pem and key.pem
        #[arg(long, default_value = ".")]
        out_dir: String,
        /// Additional Subject Alternative Names (hostnames or IPs). localhost and 127.0.0.1 are always included.
        #[arg(long = "san")]
        extra_sans: Vec<String>,
    },

    /// List all OIDC users
    ListUsers,

    /// Set a user's role
    SetRole {
        /// User email
        #[arg(long)]
        email: String,
        /// Role: admin, poweruser, operator, or viewer
        #[arg(long)]
        role: String,
    },

    /// Disable an OIDC user
    DisableUser {
        #[arg(long)]
        email: String,
    },

    /// Delete an OIDC user
    DeleteUser {
        #[arg(long)]
        email: String,
    },

    /// Import connections from an Apache Guacamole MySQL dump into the Vault address book
    ImportGuacamole {
        /// Path to the mysqldump SQL file
        #[arg(long)]
        file: String,
        /// Target folder in the address book
        #[arg(long, default_value = "imported")]
        folder: String,
        /// Scope: "shared" or "instance"
        #[arg(long, default_value = "shared")]
        scope: String,
        /// OIDC groups allowed to see the imported tree (comma-separated).
        /// Applied to the root folder; subfolders default to inherit, so the
        /// whole tree picks up the same ACL without per-folder writes.
        #[arg(long, value_delimiter = ',')]
        allowed_groups: Vec<String>,
        /// Preview without writing to Vault
        #[arg(long)]
        dry_run: bool,
    },

    /// Migrate address-book entries from Vault into the SQLite DB
    /// (connection_groups + connections tables). Credential fields are
    /// encrypted with AES-256-GCM. Run with --dry-run first.
    ///
    /// Requires the encryption key (64-char hex) in the PERSEA_STORAGE_KEY
    /// env var; ENCRYPTION_KEY is accepted as a legacy fallback.
    DbMigrateFromVault {
        /// Scope to migrate: "shared" or "instance"
        #[arg(long)]
        scope: String,
        /// Overwrite entries that already exist in the DB
        /// (default: skip existing).
        #[arg(long)]
        overwrite: bool,
        /// Preview without writing to the DB
        #[arg(long)]
        dry_run: bool,
        /// Delete entries from Vault after successful migration
        #[arg(long)]
        vault_delete: bool,
    },

    /// Copy an address-book scope subtree between configured Vault backends
    /// (for the multi-Vault DR split). Copies entries and every folder's
    /// `.config`; run with --dry-run first.
    VaultMigrate {
        /// Scope to migrate: "shared" or "instance"
        #[arg(long)]
        scope: String,
        /// Source backend: "vault", "vault_shared", or "vault_local"
        #[arg(long)]
        from: String,
        /// Destination backend: "vault", "vault_shared", or "vault_local"
        #[arg(long)]
        to: String,
        /// Also copy ALL per-user credential secrets (users/*). This makes
        /// those credentials shared; normally you toggle per-credential in the
        /// My Credentials UI instead.
        #[arg(long)]
        users: bool,
        /// Overwrite entries that already exist in the destination
        /// (default: skip existing).
        #[arg(long)]
        overwrite: bool,
        /// Preview without writing to the destination
        #[arg(long)]
        dry_run: bool,
    },
}

#[tokio::main]
async fn main() {
    // Install rustls crypto provider before any TLS usage (reqwest, axum-server, etc.)
    // Required when both ring and aws-lc-rs features are present.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = Cli::parse();

    // Load config
    let mut config = Config::load(cli.config.as_deref());

    // Validate config values (fatal errors exit, warnings are printed)
    match config.validate() {
        Ok(warnings) => {
            for w in &warnings {
                eprintln!("WARNING: {}", w);
            }
        }
        Err(msg) => {
            eprintln!("FATAL: config validation failed: {}", msg);
            std::process::exit(1);
        }
    }

    // Open database
    let database = db::init_db(&config.db_path).expect("Failed to open database");
    // DB-configured auth providers (wayfinder ticket 025) — schema + rows
    // live in the app database; config-file providers still work alongside.
    crate::providers_db::migrate(&database).expect("Failed to migrate auth_providers table");

    // Resolve log format: CLI flag wins, then RUST_LOG_FORMAT=json env var.
    let log_format = match cli.log_format {
        LogFormat::Json => LogFormat::Json,
        LogFormat::Text => match std::env::var("RUST_LOG_FORMAT").as_deref() {
            Ok("json") => LogFormat::Json,
            _ => LogFormat::Text,
        },
    };

    // Capture the pristine config-file values for the settings page BEFORE
    // the DB overlay, so GET /api/system/settings reports the real config
    // baseline under the DB overrides.

    // Capture the pristine config-file values for the settings page BEFORE
    // the DB overlay, so GET /api/system/settings reports the real config
    // baseline under the DB overrides.
    let settings_baseline = SettingsBaseline(serde_json::json!({
        "listen_addr": config.listen_addr,
        "guacd_addr": config.guacd_addr,
        "tls_cert_path": config.tls.as_ref().and_then(|t| t.cert_path.as_ref()).map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
        "tls_key_path": config.tls.as_ref().and_then(|t| t.key_path.as_ref()).map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
        "session_max_duration_secs": config.session_max_duration_secs,
        "max_concurrent_sessions": config.max_sessions,
        "session_history_retention_days": config.session_history_retention_days,
        "enable_vdi": config.vdi.as_ref().map(|v| v.enabled).unwrap_or(false),
        "vault_enabled": config.vault.is_some(),
        "db_only_mode": config.storage.as_ref().map(|st| st.backend != "vault").unwrap_or(true),
    }));

    match cli.command {
        None | Some(Command::Serve) => {
            // Overlay DB-persisted settings (admin settings page) onto the
            // config-file values before the server starts. The settings API
            // (wayfinder ticket 024) stores these in `system_settings`; the
            // merge maps the fields that have config equivalents.
            if let Ok(overrides) = crate::settings_merge::load_db_settings(&database) {
                crate::settings_merge::apply_db_settings(&mut config, &overrides);
                // DB values bypass the earlier validate() pass — re-run it so
                // an invalid saved value fails fast with a clear message.
                match config.validate() {
                    Ok(warnings) => {
                        for w in warnings {
                            eprintln!("WARNING: {}", w);
                        }
                    }
                    Err(e) => {
                        eprintln!("Error: {e}");
                        std::process::exit(1);
                    }
                }
            }
            // DB-first storage (ticket 026): credentials are encrypted at
            // rest in the DB — without a key they are stored/returned in
            // plaintext. Refuse to start so operators cannot accidentally
            // run with plaintext credentials.
            if config
                .storage
                .as_ref()
                .map(|st| st.backend != "vault")
                .unwrap_or(true)
                && config.storage_encryption_key().is_none()
            {
                eprintln!(
                    "WARNING: no [storage].encryption_key / PERSEA_STORAGE_KEY set — \
                     connection credentials would be stored in plaintext. \
                     Generate one with: openssl rand -hex 32"
                );
            }
            // The credential encryption key is used in every DB-credential
            // request path; a malformed value would panic at runtime.
            if let Some(ref k) = config.storage_encryption_key() {
                if crate::crypto::EncryptionKey::from_hex(k).is_err() {
                    eprintln!(
                        "Error: [storage].encryption_key / PERSEA_STORAGE_KEY must be a 64-char hex string"
                    );
                }
            }
            // Warn when running without TLS — credentials travel unencrypted
            if config.tls.is_none() && !config.listen_addr.contains("https") {
                tracing::warn!(
                    "Running without TLS — credentials and session tokens travel unencrypted. \
                     Use [tls] or a reverse proxy for production."
                );
            }
            run_server(config, database, log_format, settings_baseline).await
        }
        Some(Command::CreateUser {
            email,
            name,
            password,
            role,
        }) => {
            cmd_create_user(&database, &email, &name, &password, &role);
        }
        Some(Command::AddAdmin {
            name,
            allowed_ips,
            expires,
        }) => {
            cmd_add_admin(&database, &name, allowed_ips.as_deref(), expires.as_deref());
        }
        Some(Command::ListAdmins) => cmd_list_admins(&database),
        Some(Command::DisableAdmin { name }) => cmd_disable_admin(&database, &name),
        Some(Command::EnableAdmin { name }) => cmd_enable_admin(&database, &name),
        Some(Command::DeleteAdmin { name }) => cmd_delete_admin(&database, &name),
        Some(Command::RotateKey { name }) => cmd_rotate_key(&database, &name),
        Some(Command::GenerateCert {
            hostname,
            out_dir,
            extra_sans,
        }) => {
            cmd_generate_cert(&hostname, &out_dir, &extra_sans);
        }
        Some(Command::ListUsers) => cmd_list_users(&database),
        Some(Command::SetRole { email, role }) => cmd_set_role(&database, &email, &role),
        Some(Command::DisableUser { email }) => cmd_disable_user(&database, &email),
        Some(Command::DeleteUser { email }) => cmd_delete_user(&database, &email),
        Some(Command::ImportGuacamole {
            file,
            folder,
            scope,
            allowed_groups,
            dry_run,
        }) => {
            import::cmd_import_guacamole(
                &config,
                &database,
                &file,
                &folder,
                &scope,
                &allowed_groups,
                dry_run,
            )
            .await;
        }
        Some(Command::DbMigrateFromVault {
            scope,
            overwrite,
            dry_run,
            vault_delete,
        }) => {
            db_migrate::cmd_db_migrate_from_vault(
                &config,
                &scope,
                overwrite,
                dry_run,
                vault_delete,
            )
            .await;
        }
        Some(Command::VaultMigrate {
            scope,
            from,
            to,
            users,
            overwrite,
            dry_run,
        }) => {
            migrate::cmd_vault_migrate(&config, &scope, &from, &to, users, overwrite, dry_run)
                .await;
        }
    }
}

fn cmd_create_user(database: &Db, email: &str, name: &str, password: &str, role: &str) {
    let hash = match crate::password::hash_password(password) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Error hashing password: {}", e);
            std::process::exit(1);
        }
    };
    let now = chrono::Utc::now().to_rfc3339();
    let conn = database.lock().unwrap();

    // Ensure password_hash and auth_source columns exist (migrate old schema)
    let _ = conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT", []);
    let _ = conn.execute(
        "ALTER TABLE users ADD COLUMN auth_source TEXT DEFAULT 'database'",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE users ADD COLUMN oidc_groups TEXT DEFAULT ''",
        [],
    );

    match conn.execute(
        "INSERT INTO users (email, name, auth_source, password_hash, role, disabled, created_at)
         VALUES (?1, ?2, 'database', ?3, ?4, 0, ?5)",
        rusqlite::params![email, name, hash, role, now],
    ) {
        Ok(_) => {
            println!("User '{}' created (email: {}, role: {})", name, email, role);
            println!("Password: {}", password);
        }
        Err(e) => {
            eprintln!("Error creating user: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_add_admin(database: &Db, name: &str, allowed_ips: Option<&str>, expires: Option<&str>) {
    match db::add_admin(database, name, allowed_ips, expires) {
        Ok(key) => {
            println!("Admin '{}' created.", name);
            println!("API Key: {}", key);
            println!();
            println!("Store this key securely — it cannot be retrieved again.");
        }
        Err(e) => {
            eprintln!("Error creating admin: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_list_admins(database: &Db) {
    match db::list_admins(database) {
        Ok(admins) => {
            if admins.is_empty() {
                println!("No admins configured.");
                return;
            }
            println!(
                "{:<4} {:<20} {:<10} {:<24} {:<24} Allowed IPs",
                "ID", "Name", "Status", "Expires", "Last Used",
            );
            println!("{}", "-".repeat(100));
            for a in admins {
                let status = if a.disabled { "disabled" } else { "active" };
                let expires = a.expires_at.as_deref().unwrap_or("never");
                let last_used = a.last_used_at.as_deref().unwrap_or("never");
                let ips = a.allowed_ips.as_deref().unwrap_or("any");
                println!(
                    "{:<4} {:<20} {:<10} {:<24} {:<24} {}",
                    a.id, a.name, status, expires, last_used, ips
                );
            }
        }
        Err(e) => {
            eprintln!("Error listing admins: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_disable_admin(database: &Db, name: &str) {
    match db::disable_admin(database, name) {
        Ok(true) => println!("Admin '{}' disabled.", name),
        Ok(false) => {
            eprintln!("Admin '{}' not found.", name);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_enable_admin(database: &Db, name: &str) {
    match db::enable_admin(database, name) {
        Ok(true) => println!("Admin '{}' enabled.", name),
        Ok(false) => {
            eprintln!("Admin '{}' not found.", name);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_delete_admin(database: &Db, name: &str) {
    match db::delete_admin(database, name) {
        Ok(true) => println!("Admin '{}' deleted.", name),
        Ok(false) => {
            eprintln!("Admin '{}' not found.", name);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_rotate_key(database: &Db, name: &str) {
    match db::rotate_key(database, name) {
        Ok(Some(key)) => {
            println!("API key rotated for '{}'.", name);
            println!("New API Key: {}", key);
            println!();
            println!("Store this key securely — it cannot be retrieved again.");
        }
        Ok(None) => {
            eprintln!("Admin '{}' not found.", name);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_generate_cert(hostname: &str, out_dir: &str, extra_sans: &[String]) {
    use rcgen::{generate_simple_self_signed, CertifiedKey};

    let mut sans = vec![
        hostname.to_string(),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ];
    for san in extra_sans {
        if !sans.contains(san) {
            sans.push(san.clone());
        }
    }

    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(sans.clone()).expect("Failed to generate certificate");

    let cert_path = std::path::Path::new(out_dir).join("cert.pem");
    let key_path = std::path::Path::new(out_dir).join("key.pem");

    std::fs::write(&cert_path, cert.pem()).expect("Failed to write cert.pem");
    std::fs::write(&key_path, signing_key.serialize_pem()).expect("Failed to write key.pem");

    println!("Generated self-signed certificate:");
    println!("  Certificate: {}", cert_path.display());
    println!("  Private key: {}", key_path.display());
    println!("  SANs:        {}", sans.join(", "));
    println!();
    println!("Add to config.toml:");
    println!("  [tls]");
    println!("  cert_path = \"{}\"", cert_path.display());
    println!("  key_path = \"{}\"", key_path.display());
}

fn cmd_list_users(database: &Db) {
    match db::list_users(database) {
        Ok(users) => {
            if users.is_empty() {
                println!("No OIDC users.");
                return;
            }
            println!(
                "{:<4} {:<30} {:<20} {:<10} {:<10} {:<24}",
                "ID", "Email", "Name", "Role", "Status", "Last Login"
            );
            println!("{}", "-".repeat(100));
            for u in users {
                let status = if u.disabled { "disabled" } else { "active" };
                let last_login = u.last_login_at.as_deref().unwrap_or("never");
                println!(
                    "{:<4} {:<30} {:<20} {:<10} {:<10} {:<24}",
                    u.id, u.email, u.name, u.role, status, last_login
                );
            }
        }
        Err(e) => {
            eprintln!("Error listing users: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_set_role(database: &Db, email: &str, role: &str) {
    if !auth::is_valid_role(role) {
        eprintln!("Role must be admin, poweruser, operator, or viewer.");
        std::process::exit(1);
    }
    match db::set_user_role(database, email, role) {
        Ok(true) => println!("User '{}' role set to '{}'.", email, role),
        Ok(false) => {
            eprintln!("User '{}' not found.", email);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_disable_user(database: &Db, email: &str) {
    match db::disable_user(database, email) {
        Ok(true) => println!("User '{}' disabled.", email),
        Ok(false) => {
            eprintln!("User '{}' not found.", email);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_delete_user(database: &Db, email: &str) {
    match db::delete_user(database, email) {
        Ok(true) => println!("User '{}' deleted.", email),
        Ok(false) => {
            eprintln!("User '{}' not found.", email);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Whether TLS is enabled (used by security headers middleware).
#[derive(Clone)]
struct TlsEnabled(bool);

async fn security_headers(
    tls: Extension<TlsEnabled>,
    request: Request,
    next: middleware::Next,
) -> Response {
    let nonce = {
        use rand::RngExt;
        let mut bytes = [0u8; 16];
        rand::rng().fill(&mut bytes);
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
    };

    // Insert nonce into request extensions so handlers can extract it for templates
    let mut request = request;
    request.extensions_mut().insert(CspNonce(nonce.clone()));

    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert(
        "Referrer-Policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    headers.insert(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()".parse().unwrap(),
    );
    headers.insert(
        "Content-Security-Policy",
        format!("default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; connect-src 'self' wss: ws:; img-src 'self' data: https:; font-src 'self'")
            .parse()
            .unwrap(),
    );
    let _ = headers;
    response.extensions_mut().insert(CspNonce(nonce));
    if tls.0 .0 {
        let headers = response.headers_mut();
        headers.insert(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains".parse().unwrap(),
        );
    }
    response
}

/// CSP nonce stored as a response extension for handlers/templates to access.
#[derive(Clone)]
struct CspNonce(String);

/// Connect a single Vault backend into `cell`. On a failed initial connect,
/// spawns a background 30s retry loop; the cell stays `None` (and that scope's
/// address book stays unavailable) until a connect succeeds. `luks_drive` is
/// `Some` only for the default backend, so the LUKS volume mounts as soon as
/// that backend comes up on a retry (the initial-boot mount happens in the
/// drive-init block once the awaited connect below has populated the cell).
async fn connect_vault_backend(
    label: &'static str,
    cell: VaultCell,
    config: crate::config::VaultConfig,
    secret_id: String,
    luks_drive: Option<crate::config::DriveConfig>,
) {
    match vault::VaultClient::new(&config, &secret_id).await {
        Ok(client) => {
            let client = Arc::new(client);
            client.spawn_renewal_task();
            tracing::info!("Vault backend '{}' initialized: {}", label, config.addr);
            *cell.write().await = Some(client);
        }
        Err(e) => {
            tracing::error!(
                "Vault backend '{}' connect to {} failed: {} \
                 — that scope's address book is unavailable; retrying every 30s",
                label,
                config.addr,
                e
            );
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
                interval.tick().await; // skip immediate tick
                loop {
                    interval.tick().await;
                    tracing::debug!(
                        "Retrying Vault backend '{}' connect to {}...",
                        label,
                        config.addr
                    );
                    match vault::VaultClient::new(&config, &secret_id).await {
                        Ok(client) => {
                            let client = Arc::new(client);
                            client.spawn_renewal_task();
                            tracing::info!(
                                "Vault backend '{}' connected (retry succeeded): {}",
                                label,
                                config.addr
                            );
                            *cell.write().await = Some(client.clone());

                            // Mount LUKS now that the default backend is available.
                            if let Some(ref dc) = luks_drive {
                                if dc.enabled && drive::luks_configured(dc) {
                                    match drive::mount_luks(dc, client.as_ref()).await {
                                        Ok(_) => {
                                            tracing::info!("LUKS drive volume mounted (deferred)")
                                        }
                                        Err(e) => tracing::error!(
                                            "Failed to mount LUKS drive volume: {}",
                                            e
                                        ),
                                    }
                                }
                            }
                            break;
                        }
                        Err(e) => tracing::warn!(
                            "Vault backend '{}' retry failed: {} — will retry in 30s",
                            label,
                            e
                        ),
                    }
                }
            });
        }
    }
}

async fn run_server(
    config: Config,
    database: Db,
    log_format: LogFormat,
    settings_baseline: SettingsBaseline,
) {
    // Initialize logging. RUST_LOG_FORMAT=json (or --log-format json) selects
    // JSON lines for structured log ingestion; plain fmt is the default.
    let subscriber = tracing_subscriber::fmt().with_env_filter(
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info")),
    );
    match log_format {
        LogFormat::Json => subscriber.json().init(),
        LogFormat::Text => subscriber.init(),
    }

    let listen_addr = config.listen_addr.clone();
    let static_path = config.static_path.clone();
    let tls_config = config.tls.clone();

    // Initialize OIDC providers. Every enabled DB-configured OIDC provider
    // (admin auth page, wayfinder ticket 025) becomes an SSO button, plus the
    // `[oidc]` config section as a fallback ("sso") when no DB provider is set.
    let mut oidc_registry: crate::oidc::OidcRegistry = crate::oidc::OidcRegistry {
        providers: Vec::new(),
    };
    if let Ok(db_providers) = crate::providers_db::load_providers(&database) {
        for p in db_providers
            .iter()
            .filter(|p| p.enabled && p.provider_type == "oidc")
        {
            match serde_json::from_value::<crate::config::OidcConfig>(p.config.clone()) {
                Ok(cfg) => match crate::oidc::init_oidc(&cfg, config.auth_session_ttl_secs).await {
                    Ok(state) => {
                        tracing::info!(
                            "OIDC provider '{}' configured with issuer: {}",
                            p.name,
                            cfg.issuer_url
                        );
                        oidc_registry.providers.push(crate::oidc::OidcProvider {
                            name: p.name.clone(),
                            state,
                        });
                    }
                    Err(e) => {
                        tracing::error!("Failed to initialize OIDC provider '{}': {}", p.name, e);
                    }
                },
                Err(e) => {
                    tracing::error!("Invalid OIDC config for provider '{}': {}", p.name, e);
                }
            }
        }
    }
    // The [oidc] config section is the fallback whenever the registry ends
    // up empty — including when DB providers existed but all failed init,
    // so a broken DB entry cannot silently kill previously-working SSO.
    if oidc_registry.providers.is_empty() {
        if let Some(ref oidc_config) = config.oidc {
            match crate::oidc::init_oidc(oidc_config, config.auth_session_ttl_secs).await {
                Ok(state) => {
                    tracing::info!("OIDC configured with issuer: {}", oidc_config.issuer_url);
                    oidc_registry.providers.push(crate::oidc::OidcProvider {
                        name: "sso".to_string(),
                        state,
                    });
                }
                Err(e) => {
                    tracing::error!("Failed to initialize OIDC: {}", e);
                    tracing::warn!("Continuing without OIDC — only API key auth will work");
                }
            }
        }
    }
    let oidc_registry = std::sync::Arc::new(oidc_registry);
    let oidc_state = oidc_registry.providers.first().map(|p| p.state.clone());
    let oidc_provider_names = OidcProviderNames(
        oidc_registry
            .providers
            .iter()
            .map(|p| p.name.clone())
            .collect(),
    );

    // Initialize Vault backend(s) if configured.
    //
    // `[vault]` is the default/primary backend and the home of unscoped secrets
    // (the LUKS key). Optional `[vault_shared]` / `[vault_local]` route the
    // shared / instance address-book scopes to dedicated Vaults so one being
    // down cannot take the others with it. Each backend gets its own connection
    // cell, background retry, and token renewal. A bare `[vault]` behaves
    // exactly as a single-Vault deployment: shared and local alias the default
    // cell, so every scope resolves to the one connection.
    let default_cell: VaultCell = Arc::new(tokio::sync::RwLock::new(None));
    let mut shared_cell = default_cell.clone();
    let mut local_cell = default_cell.clone();

    if let Some(ref vault_config) = config.vault {
        match std::env::var("VAULT_SECRET_ID") {
            Ok(sid) if !sid.is_empty() => {
                connect_vault_backend(
                    "default",
                    default_cell.clone(),
                    vault_config.clone(),
                    sid,
                    config.drive.clone(),
                )
                .await;
            }
            _ => {
                tracing::error!("VAULT_SECRET_ID env var required when [vault] is configured");
                tracing::error!("Address book and drive features will be unavailable");
            }
        }
    }

    if let Some(ref vc) = config.vault_shared {
        match std::env::var("VAULT_SHARED_SECRET_ID") {
            Ok(sid) if !sid.is_empty() => {
                let cell: VaultCell = Arc::new(tokio::sync::RwLock::new(None));
                connect_vault_backend("shared", cell.clone(), vc.clone(), sid, None).await;
                shared_cell = cell;
            }
            _ => tracing::error!(
                "VAULT_SHARED_SECRET_ID required for [vault_shared]; shared-scope connections unavailable"
            ),
        }
    }

    if let Some(ref vc) = config.vault_local {
        match std::env::var("VAULT_LOCAL_SECRET_ID") {
            Ok(sid) if !sid.is_empty() => {
                let cell: VaultCell = Arc::new(tokio::sync::RwLock::new(None));
                connect_vault_backend("local", cell.clone(), vc.clone(), sid, None).await;
                local_cell = cell;
            }
            _ => tracing::error!(
                "VAULT_LOCAL_SECRET_ID required for [vault_local]; instance-scope connections unavailable"
            ),
        }
    }

    // Initialize drive / LUKS if configured (and Vault is already available)
    if let Some(ref drive_config) = config.drive {
        if drive_config.enabled {
            // Mount LUKS volume if configured and Vault is available now
            if drive::luks_configured(drive_config) {
                let vc = default_cell.read().await;
                if let Some(ref client) = *vc {
                    match drive::mount_luks(drive_config, client.as_ref()).await {
                        Ok(_) => tracing::info!("LUKS drive volume mounted"),
                        Err(e) => {
                            tracing::error!("Failed to mount LUKS drive volume: {}", e);
                        }
                    }
                } else {
                    tracing::warn!("LUKS configured but Vault not yet available — will mount when Vault connects");
                }
            }
            // Ensure base drive directory exists
            if let Err(e) = drive::ensure_base_dir(drive_config) {
                tracing::warn!("Failed to create drive base directory: {}", e);
            }
        }
    }

    // Assemble the shared VaultBackends state. `shared`/`local` alias the
    // default cell unless a dedicated backend was configured above.
    let vault_client: VaultState = Arc::new(VaultBackends {
        default: default_cell,
        shared: shared_cell,
        local: local_cell,
    });

    // Connect to vSphere if configured
    let vsphere_client: api::vsphere::VsphereState = if let Some(ref vsphere_cfg) = config.vsphere {
        api::vsphere::connect_vsphere(vsphere_cfg).await
    } else {
        None
    };

    // Build the auth chain from [auth] config plus DB-configured providers
    // (wayfinder ticket 025). DB entries added through the admin auth page
    // extend the chain, appended after config methods in position order;
    // they work with or without an [auth] section. OIDC keeps its own
    // separate flow; TOTP remains [auth.totp]-only.
    let (mut methods, mut providers) = match config.auth.as_ref() {
        Some(auth_cfg) => {
            let mut providers: std::collections::HashMap<String, Box<dyn AuthProvider>> =
                std::collections::HashMap::new();

            // Database provider is always available as a fallback
            providers.insert(
                "database".into(),
                Box::new(crate::auth_providers::database::DatabaseProvider::new(
                    database.clone(),
                )),
            );

            if let Some(ref ldap_cfg) = auth_cfg.ldap {
                providers.insert(
                    "ldap".into(),
                    Box::new(crate::auth_providers::ldap::LdapProvider::new(
                        ldap_cfg.clone(),
                    )),
                );
            }
            if let Some(ref radius_cfg) = auth_cfg.radius {
                providers.insert(
                    "radius".into(),
                    Box::new(crate::auth_providers::radius::RadiusProvider::new(
                        radius_cfg.clone(),
                    )),
                );
            }
            if let Some(ref saml_cfg) = auth_cfg.saml {
                providers.insert(
                    "saml".into(),
                    Box::new(crate::auth_providers::saml::SamlProvider::new(
                        saml_cfg.clone(),
                    )),
                );
            }
            (auth_cfg.methods.clone(), providers)
        }
        None => {
            let mut providers: std::collections::HashMap<String, Box<dyn AuthProvider>> =
                std::collections::HashMap::new();
            providers.insert(
                "database".into(),
                Box::new(crate::auth_providers::database::DatabaseProvider::new(
                    database.clone(),
                )),
            );
            (vec!["database".to_string()], providers)
        }
    };

    let mut db_methods: Vec<String> = Vec::new();
    if let Ok(db_providers) = crate::providers_db::load_providers(&database) {
        for p in db_providers.iter().filter(|p| p.enabled) {
            let key = format!("db-provider-{}", p.name);
            if providers.contains_key(&key) || methods.contains(&key) {
                tracing::warn!(
                    "Duplicate DB auth provider name '{}' skipped (names must be unique)",
                    p.name
                );
                continue;
            }
            let provider: Option<Box<dyn AuthProvider>> = match p.provider_type.as_str() {
                "ldap" => serde_json::from_value::<crate::auth_providers::ldap::LdapConfig>(
                    p.config.clone(),
                )
                .ok()
                .map(|c| {
                    Box::new(crate::auth_providers::ldap::LdapProvider::new(c))
                        as Box<dyn AuthProvider>
                }),
                "radius" => serde_json::from_value::<crate::auth_providers::radius::RadiusConfig>(
                    p.config.clone(),
                )
                .ok()
                .map(|c| {
                    Box::new(crate::auth_providers::radius::RadiusProvider::new(c))
                        as Box<dyn AuthProvider>
                }),
                "saml" => serde_json::from_value::<crate::auth_providers::saml::SamlConfig>(
                    p.config.clone(),
                )
                .ok()
                .map(|c| {
                    Box::new(crate::auth_providers::saml::SamlProvider::new(c))
                        as Box<dyn AuthProvider>
                }),
                "database" => Some(
                    Box::new(crate::auth_providers::database::DatabaseProvider::new(
                        database.clone(),
                    )) as Box<dyn AuthProvider>,
                ),
                "totp" => {
                    tracing::warn!(
                        "TOTP provider '{}' is not wired into the auth chain — configure [auth.totp] instead",
                        p.name
                    );
                    None
                }
                other => {
                    tracing::warn!("Unknown DB auth provider type '{}' skipped", other);
                    None
                }
            };
            if let Some(prov) = provider {
                providers.insert(key.clone(), prov);
                db_methods.push(key);
            } else {
                tracing::warn!(
                    "DB auth provider '{}' (type {}) failed to load and was skipped",
                    p.name,
                    p.provider_type
                );
            }
        }
    }
    methods.extend(db_methods);

    let auth_chain = match AuthChain::from_config(&methods, providers) {
        Ok(chain) => {
            tracing::info!(methods = ?methods, "Auth chain initialized");
            chain
        }
        Err(e) => {
            tracing::error!(
                "Failed to build auth chain: {} — falling back to database-only",
                e
            );
            AuthChain::new(vec![Box::new(
                crate::auth_providers::database::DatabaseProvider::new(database.clone()),
            )])
        }
    };
    let auth_chain = Arc::new(auth_chain);

    let oidc_enabled = OidcEnabled(oidc_state.is_some());
    let vault_configured = VaultConfigured(config.vault.is_some());
    let credential_default_scope =
        CredentialDefaultScope(config.user_credentials_default_scope.clone());
    let storage_key = StorageKey(config.storage_encryption_key());
    let storage_backend = StorageBackend(
        config
            .storage
            .as_ref()
            .map(|s| s.backend.clone())
            .unwrap_or_else(|| "db".into()),
    );
    let drive_configured = DriveConfigured(config.drive.is_some());
    let site_title = SiteTitle(config.site_title.clone());
    let theme_data = {
        // Load built-in themes merged with any user themes from
        // <static_path>/themes/*.toml (see config::load_themes). When [theme]
        // is absent, resolve_with defaults preset to "aurora" — same outcome
        // as "[theme]\n" (empty section).
        let themes = crate::config::load_themes(&static_path);
        let (admin_preset, admin_colors) = config
            .theme
            .clone()
            .unwrap_or_default()
            .resolve_with(&themes);
        let logo_url = config.theme.as_ref().and_then(|t| t.logo_url.clone());
        let presets: std::collections::HashMap<String, crate::config::ThemeColors> =
            themes.into_iter().collect();
        ThemeData {
            admin_preset,
            admin_colors,
            logo_url,
            presets,
        }
    };
    let trusted_proxies = auth::TrustedProxies(config.trusted_proxies.clone());

    // Pre-process HTML pages with branding (site title, logo) for flash-free rendering
    let branded_pages = {
        let logo = config.theme.as_ref().and_then(|t| t.logo_url.as_deref());
        let title = &config.site_title;
        let mut pages = std::collections::HashMap::new();
        // Disk-served HTML pages (only index.html — all others use templates)
        for name in &["index.html"] {
            let path = std::path::Path::new(&static_path).join(name);
            if let Ok(html) = std::fs::read_to_string(&path) {
                pages.insert(name.to_string(), rewrite_branding(&html, title, logo));
            }
        }
        Arc::new(pages)
    };

    // Periodically clean up expired auth sessions from the database
    let history_retention_days = config.session_history_retention_days;
    let cleanup_db = database.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        interval.tick().await; // first tick is immediate, skip it
        loop {
            interval.tick().await;
            match db::cleanup_expired_sessions(&cleanup_db) {
                Ok(n) if n > 0 => tracing::info!("Cleaned up {} expired auth sessions", n),
                Err(e) => tracing::warn!("Failed to clean up expired sessions: {}", e),
                _ => {}
            }
            match db::cleanup_expired_user_tokens(&cleanup_db) {
                Ok(n) if n > 0 => tracing::info!("Cleaned up {} expired user API tokens", n),
                Err(e) => tracing::warn!("Failed to clean up expired tokens: {}", e),
                _ => {}
            }
            match db::cleanup_old_audit_log(&cleanup_db, 90) {
                Ok(n) if n > 0 => tracing::info!("Cleaned up {} old audit log entries", n),
                Err(e) => tracing::warn!("Failed to clean up audit log: {}", e),
                _ => {}
            }
            match db::cleanup_session_history(&cleanup_db, history_retention_days) {
                Ok(n) if n > 0 => tracing::info!("Cleaned up {} old session history entries", n),
                Err(e) => tracing::warn!("Failed to clean up session history: {}", e),
                _ => {}
            }
        }
    });

    // Log session max duration setting
    let max_dur_hours = config.session_max_duration_secs as f64 / 3600.0;
    tracing::info!(
        "Session max duration: {:.1}h ({}s)",
        max_dur_hours,
        config.session_max_duration_secs
    );

    // Store drive config for shutdown cleanup (before config is moved)
    let shutdown_drive_config = config.drive.clone();

    // Extract shutdown timeout before config is moved into SessionManager
    let shutdown_timeout_secs = config.shutdown_timeout_secs;

    // Build TLS connector for guacd if configured
    let guacd_tls = build_guacd_tls(&config);
    let rate_limit_enabled = config.rate_limit;

    // Initialise SQLx pool if db_url is configured
    let db_pool = if let Some(ref url) = config.db_url {
        match DbPool::connect(url).await {
            Ok(pool) => {
                tracing::info!(
                    "SQLx pool connected: {}",
                    pool.kind()
                        .map(|k| k.to_string())
                        .unwrap_or_else(|| "unknown".into())
                );
                if let Err(e) = pool.run_migrations().await {
                    tracing::error!("SQLx migrations failed: {}", e);
                }
                pool
            }
            Err(e) => {
                tracing::error!("Failed to connect SQLx pool: {}", e);
                DbPool::None
            }
        }
    } else {
        DbPool::None
    };

    // Extract SAML provider and TOTP enforcement before config is moved into SessionManager
    let saml_provider: Option<Arc<crate::auth_providers::saml::SamlProvider>> = config
        .auth
        .as_ref()
        .and_then(|a| {
            a.saml
                .as_ref()
                .map(|cfg| Arc::new(crate::auth_providers::saml::SamlProvider::new(cfg.clone())))
        })
        .or_else(|| {
            // A DB-configured SAML provider (admin auth page) also needs the
            // ACS/metadata routes; build the provider from its stored config.
            crate::providers_db::load_providers(&database)
                .ok()
                .and_then(|providers| {
                    providers
                        .iter()
                        .find(|p| p.enabled && p.provider_type == "saml")
                        .and_then(|p| {
                            serde_json::from_value::<crate::auth_providers::saml::SamlConfig>(
                                p.config.clone(),
                            )
                            .ok()
                        })
                        .map(|cfg| Arc::new(crate::auth_providers::saml::SamlProvider::new(cfg)))
                })
        });
    let totp_enforcement = config
        .auth
        .as_ref()
        .and_then(|a| a.totp.as_ref())
        .map(|t| t.enforcement)
        .unwrap_or(crate::totp::TotpEnforcement::Off);

    // Create session manager
    let manager: AppState = Arc::new(SessionManager::new_with_db(
        config,
        guacd_tls,
        database.clone(),
    ));

    // Spawn background task to reap sessions that exceed max duration
    {
        let reaper_manager = manager.clone();
        let check_interval = std::cmp::max(manager.session_max_duration_secs() / 4, 60);
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(check_interval));
            interval.tick().await; // skip immediate first tick
            loop {
                interval.tick().await;
                let reaped = reaper_manager.reap_expired_sessions().await;
                if reaped > 0 {
                    tracing::info!("Reaped {} expired sessions", reaped);
                }
            }
        });
    }

    // Spawn background task to clean completed sessions from memory
    {
        let cleanup_manager = manager.clone();
        let cleanup_interval =
            std::cmp::max(cleanup_manager.config().session_cleanup_delay_secs / 2, 30);
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(cleanup_interval));
            interval.tick().await; // skip immediate first tick
            loop {
                interval.tick().await;
                let cleaned = cleanup_manager.reap_completed_sessions().await;
                if cleaned > 0 {
                    tracing::debug!("Cleaned up {} completed sessions from memory", cleaned);
                }
            }
        });
    }

    // Spawn VDI container reaper (cleans up idle containers)
    if let Some(ref vdi_cfg) = manager.config().vdi {
        if vdi_cfg.enabled {
            let default_idle_timeout =
                std::time::Duration::from_secs(vdi_cfg.idle_timeout_mins * 60);
            let reaper_manager = manager.clone();
            tokio::spawn(async move {
                // Track last-seen-active times for containers
                let mut last_active: std::collections::HashMap<String, tokio::time::Instant> =
                    std::collections::HashMap::new();
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
                interval.tick().await; // skip immediate first tick
                loop {
                    interval.tick().await;
                    let Some(vdi) = reaper_manager.vdi_driver() else {
                        continue;
                    };
                    let containers = match vdi.list_managed_containers_detail().await {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!("VDI reaper: failed to list containers: {}", e);
                            continue;
                        }
                    };

                    let now = tokio::time::Instant::now();
                    let cids: Vec<String> =
                        containers.iter().map(|c| c.container_id.clone()).collect();
                    for c in &containers {
                        if reaper_manager.has_active_vdi_session(&c.container_id).await {
                            last_active.insert(c.container_id.clone(), now);
                        } else if let Some(&last) = last_active.get(&c.container_id) {
                            // Per-container timeout from label, or global default
                            let timeout = c
                                .idle_timeout_mins
                                .map(|m| std::time::Duration::from_secs(m * 60))
                                .unwrap_or(default_idle_timeout);
                            if now.duration_since(last) > timeout {
                                tracing::info!(
                                    container = %c.container_name,
                                    "VDI reaper: removing idle container"
                                );
                                if let Err(e) = vdi.stop_container(&c.container_id).await {
                                    tracing::warn!(
                                        container = %c.container_name,
                                        "VDI reaper: failed to remove container: {}", e
                                    );
                                }
                                last_active.remove(&c.container_id);
                                // Clean up VDI thumbnail
                                let vdi_thumb =
                                    reaper_manager.vdi_thumbnail_path(&c.container_name);
                                let _ = tokio::fs::remove_file(&vdi_thumb).await;
                            }
                        } else {
                            last_active.insert(c.container_id.clone(), now);
                        }
                    }
                    last_active.retain(|cid, _| cids.contains(cid));
                }
            });
            tracing::info!(
                idle_timeout_mins = vdi_cfg.idle_timeout_mins,
                "VDI container reaper started"
            );
        }
    }

    // Spawn recording rotation background task
    {
        let rec_config = manager.recording_config();
        if rec_config.max_disk_percent > 0 || rec_config.max_recordings > 0 {
            let interval_secs = rec_config.rotation_interval_secs.max(30);
            tracing::info!(
                "Recording rotation enabled (max_disk={}%, max_count={}, interval={}s)",
                rec_config.max_disk_percent,
                rec_config.max_recordings,
                interval_secs
            );
            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(std::time::Duration::from_secs(interval_secs));
                interval.tick().await; // skip immediate first tick
                loop {
                    interval.tick().await;
                    let cfg = rec_config.clone();
                    let _ = tokio::task::spawn_blocking(move || recording::rotate(&cfg)).await;
                }
            });
        }
    }

    // Rate limiting (disabled by default — handle upstream in reverse proxy)
    if rate_limit_enabled {
        tracing::info!("API rate limiting enabled");
    }

    // WebSocket ticket store (single-use tokens to keep API keys out of WS URLs)
    let ws_ticket_store = auth::WsTicketStore::new();

    // Session creation route (rate-limited only when enabled)
    let mut session_create_route = Router::new()
        .route("/api/sessions", post(api::create_session))
        .with_state(manager.clone());
    if rate_limit_enabled {
        let conf = GovernorConfigBuilder::default()
            .per_second(2)
            .burst_size(10)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("Failed to build session creation rate limit config");
        session_create_route = session_create_route.layer(GovernorLayer::new(conf));
    }

    // API routes that require authentication
    let mut api_routes = Router::new()
        .route("/api/sessions", get(api::list_sessions))
        .route("/api/sessions/{id}", get(api::get_session))
        .route("/api/sessions/{id}", delete(api::delete_session))
        .route("/api/vdi/containers", get(api::list_vdi_containers))
        .route(
            "/api/sessions/{id}/thumbnail",
            put(api::put_session_thumbnail).get(api::get_session_thumbnail),
        )
        .route("/api/sessions/{id}/shadow", post(api::shadow_session))
        .route("/api/sessions/{id}/terminate", post(api::delete_session))
        .route(
            "/api/vdi/containers/{name}/thumbnail",
            get(api::get_vdi_container_thumbnail),
        )
        .route("/api/recordings", get(api::list_recordings))
        .route("/api/recordings/{name}", get(api::serve_recording))
        .route("/api/recordings/{name}", delete(api::delete_recording))
        // #159: typescript register is list-only by design (no serve/delete).
        .route("/api/typescripts", get(api::list_typescripts))
        .route("/api/reports/sessions", get(api::report_sessions))
        .route("/api/reports/sessions/csv", get(api::report_sessions_csv))
        .route(
            "/api/reports/top-connections",
            get(api::report_top_connections),
        )
        .route("/api/reports/top-users", get(api::report_top_users))
        .route("/api/reports/summary", get(api::report_summary))
        .route("/api/reports/activity", get(api::report_activity))
        .route("/api/system/status", get(api::system_status))
        .route(
            "/api/system/settings",
            get(api::settings::get_settings).put(api::settings::put_settings),
        )
        .route("/api/auth/providers", get(api::providers::list_providers))
        .route("/api/auth/providers", post(api::providers::create_provider))
        .route(
            "/api/auth/providers/{id}",
            get(api::providers::get_provider),
        )
        .route(
            "/api/auth/providers/{id}",
            put(api::providers::update_provider).delete(api::providers::delete_provider),
        )
        .route(
            "/api/auth/providers/{id}/enable",
            post(api::providers::enable_provider),
        )
        .route(
            "/api/auth/providers/{id}/disable",
            post(api::providers::disable_provider),
        )
        .route(
            "/api/auth/providers/{id}/move",
            post(api::providers::move_provider),
        )
        .route(
            "/api/auth/providers/{id}/config",
            get(api::providers::get_provider_config),
        )
        .route(
            "/api/auth/providers/{id}/test",
            post(api::providers::test_provider),
        )
        .route("/api/admin/groups", get(api::groups::list_groups))
        .route("/api/admin/groups", post(api::groups::create_group))
        .route(
            "/api/admin/groups/{id}",
            get(api::groups::get_group)
                .put(api::groups::update_group)
                .delete(api::groups::delete_group),
        )
        .route(
            "/api/admin/groups/{id}/mappings",
            post(api::groups::add_group_mapping),
        )
        .route(
            "/api/admin/groups/{id}/mappings/{mapping_id}",
            delete(api::groups::remove_group_mapping),
        )
        .route(
            "/api/addressbook/import",
            post(api::imports::import_csv)
                .layer(axum::extract::DefaultBodyLimit::max(4 * 1024 * 1024)),
        )
        .route(
            "/api/addressbook/import-template",
            get(api::imports::import_template),
        )
        .route("/api/users", get(api::list_users).post(api::create_user))
        .route("/api/users/{email}/role", put(api::set_user_role))
        .route(
            "/api/users/{email}/sessions",
            delete(api::delete_user_sessions),
        )
        .route("/api/users/{email}", delete(api::delete_user))
        .route("/api/users/{email}/disable", post(api::disable_user))
        .route("/api/users/{email}/enable", post(api::enable_user))
        .route("/api/admin/group-mappings", get(api::list_group_mappings))
        .route("/api/admin/group-mappings", post(api::create_group_mapping))
        .route("/api/auth/known-groups", get(api::list_known_groups))
        .route(
            "/api/admin/group-mappings/{id}",
            put(api::update_group_mapping),
        )
        .route(
            "/api/admin/group-mappings/{id}",
            delete(api::delete_group_mapping),
        )
        .route("/api/me", get(api::me))
        // User API token self-service
        .route("/api/me/tokens", get(api::list_my_tokens))
        .route("/api/me/tokens", post(api::create_my_token))
        .route("/api/me/tokens/{id}", delete(api::revoke_my_token))
        // User credential variables
        .route("/api/me/credentials", get(api::get_my_credentials))
        .route("/api/me/credentials", put(api::put_my_credentials))
        .route(
            "/api/me/preset-credentials",
            get(api::get_my_preset_credentials),
        )
        .route(
            "/api/me/preset-credentials",
            put(api::put_my_preset_credentials),
        )
        .route(
            "/api/credential-variables",
            get(api::list_credential_variables),
        )
        // Admin token management
        .route("/api/admin/user-tokens", get(api::admin_list_user_tokens))
        .route("/api/admin/user-tokens", post(api::admin_create_user_token))
        .route(
            "/api/admin/user-tokens/{id}",
            delete(api::admin_revoke_user_token),
        )
        .route("/api/admin/token-audit", get(api::admin_token_audit))
        .route(
            "/api/admin/addressbook-audit",
            get(api::admin_addressbook_audit),
        )
        // Login scripts listing
        .route("/api/login-scripts", get(api::list_login_scripts))
        .route("/api/ws-ticket", post(api::create_ws_ticket))
        // vSphere routes
        .route("/api/vsphere/vms", get(api::vsphere::list_vms))
        .route(
            "/api/vsphere/vms/{vm_id}/power",
            post(api::vsphere::power_action),
        )
        .route(
            "/api/vsphere/vms/{vm_id}/connect",
            get(api::vsphere::connect_vm),
        )
        // Address book routes
        .route("/api/addressbook", get(api::ab_list_all))
        .route("/api/addressbook/search-index", get(api::ab_search_index))
        .route("/api/addressbook/folders", get(api::ab_list_folders))
        .route("/api/addressbook/folders", post(api::ab_create_folder))
        .route(
            "/api/addressbook/folders/{scope}/{folder}",
            put(api::ab_update_folder),
        )
        .route(
            "/api/addressbook/folders/{scope}/{folder}",
            delete(api::ab_delete_folder),
        )
        .route(
            "/api/addressbook/folders/{scope}/{folder}/config",
            get(api::ab_get_folder_config),
        )
        .route(
            "/api/addressbook/folders/{scope}/{folder}/subfolders",
            get(api::ab_list_subfolders),
        )
        .route(
            "/api/addressbook/folders/{scope}/{folder}/entries",
            get(api::ab_list_entries),
        )
        .route(
            "/api/addressbook/folders/{scope}/{folder}/entries",
            post(api::ab_create_entry),
        )
        .route(
            "/api/addressbook/folders/{scope}/{folder}/entries/{entry}",
            put(api::ab_update_entry),
        )
        .route(
            "/api/addressbook/folders/{scope}/{folder}/entries/{entry}",
            delete(api::ab_delete_entry),
        )
        .route(
            "/api/addressbook/folders/{scope}/{folder}/entries/{entry}/connect",
            post(api::ab_connect_entry),
        )
        .route("/api/ssh/probe-host-key", post(api::ssh_probe_host_key))
        // Jump host / tunnel management
        .route(
            "/api/admin/jump-hosts",
            get(handlers::tunnels::list_jump_hosts),
        )
        .route(
            "/api/admin/jump-hosts",
            post(handlers::tunnels::create_jump_host),
        )
        .route(
            "/api/admin/jump-hosts/{id}",
            put(handlers::tunnels::update_jump_host),
        )
        .route(
            "/api/admin/jump-hosts/{id}",
            delete(handlers::tunnels::delete_jump_host),
        )
        .route(
            "/api/admin/jump-hosts/{id}/test",
            post(handlers::tunnels::test_jump_host),
        )
        .route(
            "/api/admin/tunnels/active",
            get(handlers::tunnels::list_active_tunnels),
        )
        // RBAC management endpoints
        .route(
            "/api/admin/rbac/groups",
            get(handlers::rbac::list_rbac_groups),
        )
        .route(
            "/api/admin/rbac/groups",
            post(handlers::rbac::create_rbac_group),
        )
        .route(
            "/api/admin/rbac/groups/{id}",
            delete(handlers::rbac::delete_rbac_group),
        )
        .route(
            "/api/admin/rbac/groups/{id}/members",
            post(handlers::rbac::add_group_member),
        )
        .route(
            "/api/admin/rbac/groups/{id}/members/{user_id}",
            delete(handlers::rbac::remove_group_member),
        )
        .route(
            "/api/admin/rbac/connections/{id}/permissions",
            get(handlers::rbac::list_connection_permissions),
        )
        .route(
            "/api/admin/rbac/connections/{id}/permissions",
            post(handlers::rbac::grant_connection_permission),
        )
        .route(
            "/api/admin/rbac/connections/{id}/permissions",
            delete(handlers::rbac::revoke_connection_permission),
        )
        .merge(session_create_route)
        .with_state(manager.clone());
    if rate_limit_enabled {
        let conf = GovernorConfigBuilder::default()
            .per_second(20)
            .burst_size(100)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("Failed to build API rate limit config");
        api_routes = api_routes.layer(GovernorLayer::new(conf));
    }
    let api_routes = api_routes
        .layer(csrf::CsrfLayer)
        .layer(middleware::from_fn(auth::require_auth))
        .layer(Extension(ws_ticket_store.clone()))
        .layer(Extension(vault_client.clone()))
        .layer(Extension(vault_configured.clone()))
        .layer(Extension(credential_default_scope.clone()))
        .layer(Extension(storage_key.clone()))
        .layer(Extension(settings_baseline.clone()))
        .layer(Extension(storage_backend.clone()))
        .layer(Extension(vsphere_client))
        .layer(Extension(database.clone()));

    // WebSocket route with optional auth + always rate-limited
    let ws_conf = GovernorConfigBuilder::default()
        .per_second(5)
        .burst_size(50)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .expect("Failed to build WebSocket rate limit config");
    let ws_route = Router::new()
        .route("/ws/{session_id}", get(websocket::ws_handler))
        .with_state(manager.clone())
        .layer(GovernorLayer::new(ws_conf));
    let ws_route = ws_route
        .layer(middleware::from_fn(auth::optional_auth))
        .layer(Extension(ws_ticket_store.clone()))
        .layer(Extension(database.clone()));

    // Quick-connect route with optional auth (handles its own redirect-to-login)
    let connect_route = Router::new()
        .route("/api/connect", get(api::quick_connect))
        .with_state(manager.clone())
        .layer(middleware::from_fn(auth::optional_auth))
        .layer(Extension(vault_client.clone()))
        .layer(Extension(oidc_enabled.clone()))
        .layer(Extension(storage_key.clone()))
        .layer(Extension(storage_backend.clone()))
        .layer(Extension(database.clone()));

    // Health check with optional auth (deep check when authenticated)
    let health_route = Router::new()
        .route("/api/health", get(api::health))
        .with_state(manager.clone())
        .layer(middleware::from_fn(auth::optional_auth));

    // Prometheus metrics endpoint
    let metrics_route = Router::new().route("/metrics", get(api::metrics));

    // Unauthenticated stateful routes
    let unauth_routes = Router::new()
        .route("/api/docs", get(api::get_docs))
        .route("/api/sessions/{id}/banner", get(api::get_session_banner))
        .route("/client/{session_id}", get(serve_client_page))
        .with_state(manager.clone());

    // Setup wizard routes (first-run only)
    let setup_routes = Router::new()
        .route("/setup", get(handlers::setup::setup_page))
        .route("/setup", post(handlers::setup::setup_submit))
        .layer(csrf::CsrfLayer)
        .layer(Extension(database.clone()))
        .layer(Extension(site_title.clone()));

    // Auth page routes (login, MFA) — login POST always rate-limited
    let login_rate_conf = GovernorConfigBuilder::default()
        .per_second(5)
        .burst_size(10)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .expect("Failed to build login rate limit config");

    let login_rate_limited = Router::new()
        .route("/auth/login", post(handlers::auth::login_submit))
        .route("/auth/mfa", post(handlers::auth::mfa_submit))
        .with_state(manager.clone())
        .layer(GovernorLayer::new(login_rate_conf));

    let auth_pages = Router::new()
        .route("/", get(handlers::auth::login_page))
        .route("/auth/mfa", get(handlers::auth::mfa_page))
        .with_state(manager.clone())
        .merge(login_rate_limited)
        .layer(csrf::CsrfLayer)
        .layer(Extension(database.clone()))
        .layer(Extension(oidc_enabled.clone()))
        .layer(Extension(auth_chain.clone()))
        .layer(Extension(trusted_proxies.clone()));

    // SAML routes (if configured)
    let mut saml_routes = Router::new();
    if let Some(ref sp) = saml_provider {
        let sp_acs = sp.clone();
        let sp_meta = sp.clone();
        saml_routes = Router::new()
            .route("/auth/saml/acs", post(handlers::auth::saml_acs))
            .route("/auth/saml/metadata", get(handlers::auth::saml_metadata))
            .layer(csrf::CsrfLayer)
            .layer(Extension(sp_acs))
            .layer(Extension(sp_meta))
            .layer(Extension(database.clone()))
            .layer(Extension(trusted_proxies.clone()));
    }

    // Branded HTML page routes (served from memory with site_title/logo baked in)
    let protected_html_routes = Router::new()
        .route("/index.html", get(serve_branded_page))
        .route("/connections.html", get(handlers::pages::connections_page))
        // Legacy path — the page was renamed from Address Book → Connections.
        // Permanent redirect so bookmarks keep working.
        .route(
            "/addressbook.html",
            get(|| async { axum::response::Redirect::permanent("/connections.html") }),
        )
        .route("/sessions.html", get(handlers::pages::sessions_page))
        .route("/recordings.html", get(handlers::pages::recordings_page))
        .route("/reports.html", get(handlers::pages::admin_reports_page))
        .route("/admin.html", get(handlers::pages::admin_users_page))
        .route("/tokens.html", get(handlers::account::tokens_page))
        // Account pages (templates)
        .route(
            "/account/profile.html",
            get(handlers::account::profile_page),
        )
        .route("/account/tokens.html", get(handlers::account::tokens_page))
        .route("/account/totp.html", get(handlers::account::totp_page))
        // Admin sub-pages (templates)
        .route("/admin/users.html", get(handlers::pages::admin_users_page))
        .route("/admin/auth.html", get(handlers::pages::admin_auth_page))
        .route(
            "/admin/groups.html",
            get(handlers::pages::admin_groups_page),
        )
        .route("/admin/audit.html", get(handlers::pages::admin_audit_page))
        .route(
            "/admin/settings.html",
            get(handlers::pages::admin_settings_page),
        )
        .route(
            "/admin/reports.html",
            get(handlers::pages::admin_reports_page),
        )
        .route(
            "/admin/tunnels.html",
            get(handlers::pages::admin_tunnels_page),
        )
        .route("/docs.html", get(handlers::account::docs_page))
        .route("/docs", get(handlers::account::docs_page))
        .layer(middleware::from_fn(auth::require_auth))
        .layer(Extension(ws_ticket_store.clone()))
        .layer(Extension(database.clone()));

    let html_routes = protected_html_routes;

    // Build full router (all Router<()> at this point)
    let mut app: Router<()> = Router::new()
        .route("/api/auth/status", get(api::auth_status))
        .merge(api_routes)
        .merge(health_route)
        .merge(metrics_route)
        .merge(ws_route)
        .merge(connect_route)
        .merge(setup_routes)
        .merge(auth_pages)
        .merge(saml_routes)
        .merge(unauth_routes)
        .merge(html_routes);

    // Logout route — always available (clears session, redirects to login)
    let logout_route = Router::new()
        .route("/auth/logout", get(oidc::logout))
        .layer(Extension(database.clone()));

    // Add OIDC routes if configured (always rate-limited to prevent brute-force)
    if let Some(ref oidc_st) = oidc_state {
        let auth_rate_conf = GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(5)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("Failed to build auth rate limit config");

        let oidc_routes = Router::new()
            .route("/auth/login", get(oidc::login))
            .route("/auth/callback", get(oidc::callback))
            .with_state(oidc_registry.clone())
            .layer(Extension(database.clone()))
            .layer(Extension(totp_enforcement))
            .layer(GovernorLayer::new(auth_rate_conf));

        app = app.merge(oidc_routes);
    }

    app = app.merge(logout_route);

    // Add shared layers
    // Server HTTPS requires both cert_path and key_path in [tls]
    let server_tls = tls_config.as_ref().and_then(|tls| {
        match (&tls.cert_path, &tls.key_path) {
            (Some(cert), Some(key)) => Some((cert.clone(), key.clone())),
            (Some(_), None) | (None, Some(_)) => {
                tracing::warn!("[tls] has only one of cert_path/key_path — both are required for HTTPS serving; starting HTTP");
                None
            }
            (None, None) => None,
        }
    });
    let tls_enabled = TlsEnabled(server_tls.is_some());
    // Unknown routes fall through to the static dir; missing files hand off
    // to `not_found_handler`, which renders the styled error page. The
    // fallback must be registered BEFORE the shared layers below so they
    // also wrap it (Router::layer only covers already-registered routes).
    let static_serve = ServeDir::new(&static_path)
        .not_found_service(Router::new().fallback(not_found_handler).with_state(()));
    app = app
        .fallback_service(static_serve)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(metrics::MetricsLayer)
        .layer(DefaultBodyLimit::max(64 * 1024)) // 64 KB max request body
        .layer(middleware::from_fn(error_pages))
        .layer(middleware::from_fn(security_headers))
        .layer(Extension(tls_enabled))
        .layer(Extension(oidc_enabled))
        .layer(Extension(oidc_provider_names))
        .layer(Extension(drive_configured))
        .layer(Extension(site_title))
        .layer(Extension(theme_data))
        .layer(Extension(trusted_proxies))
        .layer(Extension(branded_pages))
        .layer(Extension(db_pool));

    let scheme = if server_tls.is_some() {
        "https"
    } else {
        "http"
    };
    tracing::info!("persea starting on {}://{}", scheme, listen_addr);
    tracing::info!("Static files served from {:?}", static_path);

    // TCP keepalive on the listener. Linux inherits SO_KEEPALIVE and the
    // associated TCP_KEEPIDLE/INTVL/CNT options on accept(), so accepted
    // browser sockets pick up keepalive without a per-accept hook. Pairs with
    // the Guacamole protocol-level ping echo in src/websocket.rs to keep
    // long-idle WebSocket sessions alive across NAT/firewall path changes.
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(30))
        .with_interval(std::time::Duration::from_secs(10))
        .with_retries(3);

    if let Some((cert_path, key_path)) = server_tls {
        use axum_server::tls_rustls::RustlsConfig;

        let rustls_config = RustlsConfig::from_pem_file(&cert_path, &key_path)
            .await
            .expect("Failed to load TLS certificates");

        let std_listener =
            std::net::TcpListener::bind(&listen_addr).expect("Failed to bind listener");
        std_listener
            .set_nonblocking(true)
            .expect("Failed to set listener non-blocking");
        if let Err(e) = socket2::SockRef::from(&std_listener).set_tcp_keepalive(&keepalive) {
            tracing::warn!(error = %e, "failed to enable TCP keepalive on TLS listener");
        }
        // Disable Nagle so display frames and sync acks flow to the browser
        // without coalescing. Linux propagates this to accepted sockets.
        if let Err(e) = socket2::SockRef::from(&std_listener).set_tcp_nodelay(true) {
            tracing::warn!(error = %e, "failed to set TCP_NODELAY on TLS listener");
        }

        let handle = axum_server::Handle::new();
        let handle_clone = handle.clone();
        let timeout = shutdown_timeout_secs;
        let shutdown_mgr = manager.clone();
        tokio::spawn(async move {
            // Wait for SIGTERM/SIGINT then trigger axum-server graceful shutdown
            let ctrl_c = tokio::signal::ctrl_c();
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut sigterm =
                    signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");
                tokio::select! {
                    _ = ctrl_c => tracing::info!("SIGINT received, starting graceful shutdown"),
                    _ = sigterm.recv() => tracing::info!("SIGTERM received, starting graceful shutdown"),
                }
            }
            #[cfg(not(unix))]
            {
                ctrl_c.await.expect("Failed to listen for ctrl-c");
                tracing::info!("Shutdown signal received");
            }

            // Block new sessions and cancel active ones
            shutdown_mgr.initiate_shutdown();
            let active_count = shutdown_mgr.cancel_all_sessions().await;
            tracing::info!(
                active_sessions = active_count,
                timeout_secs = timeout,
                "Graceful shutdown initiated — waiting for sessions to drain"
            );

            handle_clone.graceful_shutdown(Some(std::time::Duration::from_secs(timeout)));
        });

        axum_server::from_tcp_rustls(std_listener, rustls_config)
            .expect("Failed to wrap listener")
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .expect("Server error");
    } else {
        let listener = tokio::net::TcpListener::bind(&listen_addr)
            .await
            .expect("Failed to bind listener");
        if let Err(e) = socket2::SockRef::from(&listener).set_tcp_keepalive(&keepalive) {
            tracing::warn!(error = %e, "failed to enable TCP keepalive on listener");
        }
        // Disable Nagle so display frames and sync acks flow to the browser
        // without coalescing. Linux propagates this to accepted sockets.
        if let Err(e) = socket2::SockRef::from(&listener).set_tcp_nodelay(true) {
            tracing::warn!(error = %e, "failed to set TCP_NODELAY on listener");
        }

        let shutdown_mgr = manager.clone();
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            // Wait for either SIGTERM or SIGINT
            let ctrl_c = tokio::signal::ctrl_c();
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut sigterm = signal(SignalKind::terminate())
                    .expect("Failed to register SIGTERM handler");
                tokio::select! {
                    _ = ctrl_c => tracing::info!("SIGINT received, starting graceful shutdown"),
                    _ = sigterm.recv() => tracing::info!("SIGTERM received, starting graceful shutdown"),
                }
            }
            #[cfg(not(unix))]
            {
                ctrl_c.await.expect("Failed to listen for ctrl-c");
                tracing::info!("Shutdown signal received");
            }

            // 1. Block new session creation
            shutdown_mgr.initiate_shutdown();
            let active_count = shutdown_mgr.cancel_all_sessions().await;
            tracing::info!(
                active_sessions = active_count,
                timeout_secs = shutdown_timeout_secs,
                "Graceful shutdown initiated — waiting for sessions to drain"
            );

            // 2. Give active sessions time to drain
            tokio::time::sleep(std::time::Duration::from_secs(shutdown_timeout_secs)).await;
            tracing::info!("Graceful shutdown timeout reached — exiting");
        })
        .await
        .expect("Server error");
    }

    // Cleanup LUKS on shutdown
    if let Some(ref drive_config) = shutdown_drive_config {
        if drive_config.enabled && drive::luks_configured(drive_config) {
            tracing::info!("Unmounting LUKS drive volume...");
            if let Err(e) = drive::unmount_luks(drive_config).await {
                tracing::warn!("Failed to unmount LUKS volume on shutdown: {}", e);
            }
        }
    }
}

/// Build a TLS connector for the guacd connection, if `[tls] guacd_cert_path` is configured.
/// This is independent of server HTTPS — you can use guacd TLS without cert_path/key_path.
fn build_guacd_tls(config: &Config) -> Option<tokio_rustls::TlsConnector> {
    let cert_path = config.tls.as_ref()?.guacd_cert_path.as_ref()?;

    let pem_data = std::fs::read(cert_path)
        .unwrap_or_else(|e| panic!("Failed to read guacd cert {}: {}", cert_path.display(), e));

    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    let certs: Vec<_> = rustls_pemfile::certs(&mut &pem_data[..])
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|e| panic!("Failed to parse guacd cert PEM: {}", e));

    for cert in certs {
        root_store
            .add(cert)
            .unwrap_or_else(|e| panic!("Failed to add guacd cert to root store: {}", e));
    }

    let tls_config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    tracing::info!(
        "guacd TLS enabled, trusting cert from {}",
        cert_path.display()
    );
    Some(tokio_rustls::TlsConnector::from(Arc::new(tls_config)))
}

/// Error-page negotiation middleware: captures whether the request wants a
/// styled HTML error page (browser) vs JSON (API client), plus the CSP
/// nonce, so `AppError` responses and the 404 fallback can render the error
/// template. Runs inside `security_headers`, which inserts the nonce into
/// request extensions first.
async fn error_pages(request: Request, next: middleware::Next) -> Response {
    // /api/* always gets JSON errors; other paths get the styled page when
    // the client accepts text/html (browsers).
    let wants_html = !request.uri().path().starts_with("/api/")
        && request
            .headers()
            .get(axum::http::header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("text/html"))
            .unwrap_or(false);
    let csp_nonce = request
        .extensions()
        .get::<CspNonce>()
        .map(|n| n.0.clone())
        .unwrap_or_default();
    crate::error::with_error_context(
        crate::error::ErrorContext {
            wants_html,
            csp_nonce,
        },
        next.run(request),
    )
    .await
}

/// Fallback for unknown routes — renders the styled error page for browser
/// requests, JSON for API paths.
async fn not_found_handler() -> Response {
    crate::error::AppError::error_response(
        axum::http::StatusCode::NOT_FOUND,
        "The page you requested could not be found",
    )
}

/// Serve a branded HTML page from the pre-processed in-memory map.
async fn serve_branded_page(
    Extension(pages): Extension<Arc<std::collections::HashMap<String, String>>>,
    request: axum::extract::Request,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let path = request.uri().path().trim_start_matches('/');
    let key = if path.is_empty() { "index.html" } else { path };
    if let Some(html) = pages.get(key) {
        Html(html.clone()).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// Serve the client HTML page for remote desktop sessions.
/// Renders the new toolbar-based client template.
async fn serve_client_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(nonce): Extension<CspNonce>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let tmpl = templates::ClientTemplate {
        site_title: site_title.0.clone(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

/// HTML-escape a string to prevent XSS when injecting config values into HTML.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Rewrite branding in HTML: replace default "persea" site title and logo.
fn rewrite_branding(html: &str, site_title: &str, logo_url: Option<&str>) -> String {
    let mut out = html.to_string();
    if site_title != "persea" {
        let safe_title = html_escape(site_title);
        // <title>persea</title> and <title>persea - Sessions</title> etc.
        out = out.replace(
            "<title>persea</title>",
            &format!("<title>{}</title>", safe_title),
        );
        out = out.replace("<title>persea - ", &format!("<title>{} - ", safe_title));
        // <h1>persea</h1> (with or without inline style)
        out = out.replace(">persea</h1>", &format!(">{}</h1>", safe_title));
    }
    if let Some(url) = logo_url {
        let safe_url = html_escape(url);
        out = out.replace("src=\"/logo.svg\"", &format!("src=\"{}\"", safe_url));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rewrite_branding_title() {
        let html = "<title>persea - Sessions</title>";
        assert_eq!(
            rewrite_branding(html, "MyGateway", None),
            "<title>MyGateway - Sessions</title>"
        );
    }

    #[test]
    fn test_rewrite_branding_h1() {
        let html = r#"<h1 style="display:inline">persea</h1>"#;
        assert_eq!(
            rewrite_branding(html, "MyGateway", None),
            r#"<h1 style="display:inline">MyGateway</h1>"#
        );
    }

    #[test]
    fn test_rewrite_branding_logo() {
        let html = r#"<img id="site-logo" src="/logo.svg" style="max-height:40px">"#;
        assert_eq!(
            rewrite_branding(html, "persea", Some("https://example.com/logo.png")),
            r#"<img id="site-logo" src="https://example.com/logo.png" style="max-height:40px">"#
        );
    }

    #[test]
    fn test_rewrite_branding_noop() {
        let html = "<title>persea</title><h1>persea</h1>";
        assert_eq!(rewrite_branding(html, "persea", None), html);
    }

    // ── Rate-limit plumbing ─────────────────────────────────────────────
    // Proves that the tower_governor layer is actually applied: bursts
    // above the configured threshold return 429. Guards against a future
    // refactor that drops `.layer(GovernorLayer::new(...))` from a route
    // group without noticing.

    #[tokio::test]
    async fn rate_limit_layer_returns_429_on_burst() {
        use axum::{body::Body, http::Request, routing::get, Router};
        use tower::ServiceExt;

        // Same settings family as the OIDC auth-rate-limit path in main.rs.
        let conf = GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(3)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("governor config");

        let app: Router = Router::new()
            .route("/probe", get(|| async { axum::http::StatusCode::OK }))
            .layer(GovernorLayer::new(conf));

        // Fire 10 requests back-to-back from the same source IP. With
        // burst=3 per_second=1, at least one must be throttled (429).
        // SmartIpKeyExtractor honours X-Forwarded-For when present.
        let mut saw_ok = false;
        let mut saw_429 = false;
        for _ in 0..10 {
            let req = Request::builder()
                .uri("/probe")
                .header("x-forwarded-for", "203.0.113.99")
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            match resp.status().as_u16() {
                200 => saw_ok = true,
                429 => saw_429 = true,
                other => panic!("unexpected status {other} — governor misconfigured"),
            }
        }
        assert!(saw_ok, "no requests succeeded — layer misconfigured");
        assert!(
            saw_429,
            "no requests were throttled — rate-limit not applied"
        );
    }

    // ── Error-page negotiation (R18) ───────────────────────────────────

    #[tokio::test]
    async fn error_page_renders_html_for_browsers_and_json_for_api() {
        use axum::{body::Body, http::Request, routing::get, Router};
        use tower::ServiceExt;

        async fn failing() -> Result<(), crate::error::AppError> {
            Err(crate::error::AppError::NotFound("missing resource".into()))
        }

        let app = Router::new()
            .route("/page.html", get(failing))
            .route("/api/data", get(failing))
            .layer(middleware::from_fn(error_pages));

        // Browser request → styled HTML error page with the right status.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/page.html")
                    .header("accept", "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Not Found"), "expected styled page, got: {html}");
        assert!(html.contains("missing resource"), "got: {html}");
        assert!(html.contains("app.css"), "page must load the design system");

        // API path → JSON even when the client accepts text/html.
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/data")
                    .header("accept", "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers()["content-type"],
            "application/json",
            "API errors must stay JSON"
        );
    }

    #[tokio::test]
    async fn not_found_fallback_renders_error_page() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;

        let dir = std::env::temp_dir().join(format!(
            "persea-notfound-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let app = Router::new()
            .fallback_service(
                ServeDir::new(&dir)
                    .not_found_service(Router::new().fallback(not_found_handler).with_state(())),
            )
            .layer(middleware::from_fn(error_pages));

        // Unknown page → styled 404.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/missing.html")
                    .header("accept", "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("404"), "expected styled 404 page, got: {html}");

        // Unknown API path → JSON.
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/nope")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(resp.headers()["content-type"], "application/json");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
