use axum::extract::Form;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Extension;
use serde::Deserialize;

use crate::api::SiteTitle;
use crate::config::{storage_section_for, toml_escape, Config};
use crate::db_pool::{DbKind, DbPool};
use crate::templates::SetupTemplate;
use crate::CspNonce;

/// Form body of the setup wizard (POST /setup).
#[derive(Debug, Deserialize)]
pub struct SetupForm {
    /// Listen address the server should bind, e.g. "0.0.0.0:8089".
    pub listen_addr: String,
    /// SQLite database file path used when no managed backend URL is given.
    pub db_path: String,
    /// Managed backend URL (Postgres/MySQL); empty keeps the SQLite file.
    #[serde(default)]
    pub db_url: String,
    /// guacd TCP address the server connects to.
    pub guacd_addr: String,
    /// Email of the admin account the wizard creates.
    pub admin_email: String,
    /// Display name of the admin account.
    pub admin_name: String,
    /// Password for the admin account, hashed with Argon2id.
    pub admin_password: String,
    /// Set when the Proxmox VE checkbox is ticked.
    pub feature_proxmox: Option<String>,
    /// Set when the VMware checkbox is ticked; writes a commented
    /// [vsphere] stub into the generated config.
    pub feature_vmware: Option<String>,
    /// Set when the session recording checkbox is ticked.
    pub feature_recordings: Option<String>,
    /// Set when the SSH tunnels checkbox is ticked.
    pub feature_tunnels: Option<String>,
    /// Set when the web browser sessions checkbox is ticked.
    pub feature_browser: Option<String>,
    /// Set when the VDI containers checkbox is ticked.
    pub feature_vdi: Option<String>,
}

/// Detect available IPs on this machine.
fn detect_ips() -> Vec<String> {
    let mut ips = vec!["0.0.0.0:8089".to_string()];
    if let Ok(addrs) = local_ip_address::list_afinet_netifas() {
        for (_name, addr) in addrs {
            if addr.is_ipv4() && !addr.is_loopback() {
                ips.push(format!("{}:8089", addr));
            }
        }
    }
    ips
}

/// Human-readable label for the active backend (setup page indicator).
fn backend_label(kind: DbKind) -> &'static str {
    match kind {
        DbKind::Postgres => "PostgreSQL",
        DbKind::MySQL => "MySQL",
        DbKind::SQLite => "SQLite",
    }
}

/// Which backend is the active store right now (None = legacy SQLite file).
fn current_backend() -> Option<String> {
    crate::db::active_pool()
        .and_then(|p| p.kind())
        .map(|b| backend_label(b).to_string())
}

/// Check if setup is needed (no users in the active store at all).
///
/// Pool-aware: with `db_url` set, this counts rows in the
/// configured backend; without it, in the legacy SQLite file. The wizard is
/// shown whenever the active store has zero users.
pub fn needs_setup(db: &crate::db::Db) -> bool {
    crate::db::count_users(db).unwrap_or(0) == 0
}

/// GET /setup — Show setup wizard.
pub async fn setup_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(config): Extension<Config>,
    Extension(database): Extension<crate::db::Db>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    if !needs_setup(&database) {
        return Redirect::to("/").into_response();
    }

    let detected_ips = detect_ips();
    let listen_addr = detected_ips
        .first()
        .cloned()
        .unwrap_or_else(|| "0.0.0.0:8089".to_string());

    // When the process was started with `db_url`, the pool is already the
    // store: prefill the wizard with the configured URL and show which
    // backend the first admin will land in. Otherwise the user may enter a
    // db_url here (Postgres/MySQL) to be born directly on that backend.
    let backend = current_backend();
    let db_url = if backend.is_some() {
        config.db_url.clone().unwrap_or_default()
    } else {
        String::new()
    };

    let tmpl = SetupTemplate {
        site_title: site_title.0.clone(),
        error: None,
        listen_addr,
        db_path: config.db_path.to_string_lossy().to_string(),
        db_url,
        backend,
        guacd_addr: "127.0.0.1:4822".to_string(),
        admin_email: String::new(),
        admin_name: String::new(),
        password_min_length: config.password_min_length(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

/// Re-render the wizard with an error, keeping the submitted form values.
fn error_response(
    site_title: &str,
    error: String,
    form: &SetupForm,
    min_len: usize,
    nonce: &str,
) -> Response {
    SetupTemplate {
        site_title: site_title.to_string(),
        error: Some(error),
        listen_addr: form.listen_addr.clone(),
        db_path: form.db_path.clone(),
        db_url: form.db_url.clone(),
        backend: current_backend(),
        guacd_addr: form.guacd_addr.clone(),
        admin_email: form.admin_email.clone(),
        admin_name: form.admin_name.clone(),
        password_min_length: min_len,
        csp_nonce: nonce.to_string(),
    }
    .into_response()
}

/// POST /setup — Process setup form.
pub async fn setup_submit(
    Extension(site_title): Extension<SiteTitle>,
    Extension(config): Extension<Config>,
    Extension(database): Extension<crate::db::Db>,
    Extension(nonce): Extension<CspNonce>,
    Form(form): Form<SetupForm>,
) -> Response {
    if !needs_setup(&database) {
        return Redirect::to("/").into_response();
    }

    // Validate against the enforced password policy minimum (the wizard
    // advertises this value on the password field).
    let min_len = config.password_min_length();
    if form.admin_email.is_empty() || form.admin_password.len() < min_len {
        return error_response(
            &site_title.0,
            format!("Email is required and password must be at least {min_len} characters long."),
            &form,
            min_len,
            &nonce.0,
        );
    }

    let db_url = form.db_url.trim().to_string();
    let pool_already_active = crate::db::pool_active();

    if pool_already_active {
        // The pool was installed at startup from the config's `db_url`: the
        // store IS the configured backend. Keep the URL for the config-file
        // write below, but refuse values that would diverge from what this
        // process is actually connected to — otherwise the admin lands in
        // one backend while the written config points at another.
        let configured = config.db_url.as_deref().unwrap_or_default();
        if db_url.is_empty() {
            return error_response(
                &site_title.0,
                "Database URL is required — this server stores its data in the \
                 configured database backend (see the note above the Database \
                 URL field)."
                    .to_string(),
                &form,
                min_len,
                &nonce.0,
            );
        }
        if configured != db_url {
            return error_response(
                &site_title.0,
                format!(
                    "The Database URL does not match the db_url this server was \
                     started with ({}). The server is already connected to its \
                     configured backend; change db_url in the config file and \
                     restart instead.",
                    configured
                ),
                &form,
                min_len,
                &nonce.0,
            );
        }
    } else if !db_url.is_empty() {
        // Fresh process (started without db_url): connect to the chosen
        // backend, run the schema migrations, and install the pool as the
        // active store — so the admin user below lands in the CONFIGURED
        // backend, not in the legacy SQLite file. From that point on every
        // store call in this process is pool-routed.
        let pool = match DbPool::connect(&db_url).await {
            Ok(p) => p,
            Err(e) => {
                return error_response(
                    &site_title.0,
                    format!("Failed to connect to database URL: {}", e),
                    &form,
                    min_len,
                    &nonce.0,
                );
            }
        };
        if let Err(e) = pool.run_migrations().await {
            return error_response(
                &site_title.0,
                format!("Failed to run database migrations: {}", e),
                &form,
                min_len,
                &nonce.0,
            );
        }
        if crate::db::set_active_pool(pool).is_err() {
            return error_response(
                &site_title.0,
                "Failed to activate the database backend (worker thread error).".to_string(),
                &form,
                min_len,
                &nonce.0,
            );
        }
        tracing::info!(
            backend = ?current_backend(),
            "Setup: database backend connected and migrated"
        );
    }

    // Hash password
    let password_hash = match crate::password::hash_password(&form.admin_password) {
        Ok(h) => h,
        Err(e) => {
            return error_response(
                &site_title.0,
                format!("Failed to hash password: {}", e),
                &form,
                min_len,
                &nonce.0,
            );
        }
    };

    // Create admin user in the ACTIVE store: the configured backend when a
    // pool is installed (db_url), otherwise the legacy SQLite file.
    //
    // First-admin claim: the wizard is shown while the store has zero
    // users, and two concurrent submissions can both pass that check. The
    // first to commit wins; a second submission creates a second admin
    // (names are unique, emails are not). Acceptable for a bootstrap
    // wizard — operators should complete setup exactly once.
    if let Err(e) = crate::db::create_user_with_password(
        &database,
        &form.admin_email,
        &form.admin_name,
        &password_hash,
        "admin",
        "database",
    ) {
        return error_response(
            &site_title.0,
            format!("Failed to create admin user: {}", e),
            &form,
            min_len,
            &nonce.0,
        );
    }

    // Write config file
    let guacd_line = format!("guacd_addr = \"{}\"", toml_escape(&form.guacd_addr));

    // Feature stubs — written commented-out so a half-filled config never
    // breaks startup with missing required fields.
    let feature_sections = String::new()
        + if form.feature_vmware.is_some() {
            r#"
# VMware vSphere — uncomment and fill in to enable (password from env var)
# [vsphere]
# vcenter_addr = "https://vcenter.example.com/sdk"
# username = "administrator@vsphere.local"
# password_env = "VSPHERE_PASSWORD"
"#
        } else {
            ""
        };

    // A provided db_url replaces db_path in the generated config: the next
    // start connects the SQLx pool and stores ALL app data in that backend.
    let db_line = if db_url.is_empty() {
        format!("db_path = \"{}\"", toml_escape(&form.db_path))
    } else {
        format!("db_url = \"{}\"", toml_escape(&db_url))
    };

    // Write to config path (same as the --config arg, or default location)
    let config_path =
        std::env::var("RUSTGUAC_CONFIG").unwrap_or_else(|_| "/opt/persea/config.toml".to_string());

    // The storage section holds the credential encryption key: preserve an
    // existing one verbatim and always emit a key (single implementation in
    // crate::config, shared with ensure-storage-key and the startup guard).
    let storage_section = storage_section_for(&config_path);

    let config = format!(
        r#"# persea configuration — generated by setup wizard
listen_addr = "{}"
{}
{}
recording_path = "/opt/persea/recordings"
static_path = "/opt/persea/static"
site_title = "persea"
session_max_duration_secs = 28800
session_cleanup_delay_secs = 300
session_history_retention_days = 90
{}
{}"#,
        toml_escape(&form.listen_addr),
        db_line,
        guacd_line,
        feature_sections,
        storage_section
    );

    if let Err(e) = std::fs::write(&config_path, &config) {
        tracing::warn!("Could not write config to {}: {}", config_path, e);
        // Non-fatal — user can create config manually
    } else {
        // The written config holds the encryption key: not world-readable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600));
        }
        tracing::info!("Config written to {}", config_path);
    }

    tracing::info!(
        email = %form.admin_email,
        listen = %form.listen_addr,
        guacd_addr = %form.guacd_addr,
        db_url_set = !db_url.is_empty(),
        "Setup completed"
    );

    // Redirect to login
    Redirect::to("/?setup=complete").into_response()
}
