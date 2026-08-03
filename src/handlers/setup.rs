use axum::extract::Form;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Extension;
use serde::Deserialize;

use crate::api::SiteTitle;
use crate::templates::SetupTemplate;

#[derive(Debug, Deserialize)]
pub struct SetupForm {
    pub listen_addr: String,
    pub db_path: String,
    pub guacd_mode: String,
    pub guacd_addr: String,
    pub guacd_path: String,
    pub admin_email: String,
    pub admin_name: String,
    pub admin_password: String,
    pub feature_proxmox: Option<String>,
    pub feature_vmware: Option<String>,
    pub feature_recordings: Option<String>,
    pub feature_tunnels: Option<String>,
    pub feature_browser: Option<String>,
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

/// Detect if guacd binary exists.
fn detect_guacd_path() -> String {
    for path in &["/usr/sbin/guacd", "/usr/local/sbin/guacd", "/usr/bin/guacd"] {
        if std::path::Path::new(path).exists() {
            return path.to_string();
        }
    }
    // Check PATH
    if let Ok(output) = std::process::Command::new("which").arg("guacd").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return path;
            }
        }
    }
    "/usr/sbin/guacd".to_string()
}

/// Detect if running in Docker.
fn detect_docker() -> bool {
    std::path::Path::new("/.dockerenv").exists()
        || std::env::var("DOCKER_CONTAINER").is_ok()
}

/// Check if setup is needed (no admin user in DB).
pub fn needs_setup(db: &crate::db::Db) -> bool {
    let conn = db.lock().unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM users WHERE role = 'admin'", [], |row| row.get(0))
        .unwrap_or(0);
    // Also check if there are ANY users at all
    let user_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .unwrap_or(0);
    // Setup needed if no users exist
    user_count == 0
}

/// GET /setup — Show setup wizard.
pub async fn setup_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(database): Extension<crate::db::Db>,
) -> Response {
    if !needs_setup(&database) {
        return Redirect::to("/").into_response();
    }

    let detected_ips = detect_ips();
    let listen_addr = detected_ips.first().cloned().unwrap_or_else(|| "0.0.0.0:8089".to_string());
    let guacd_path = detect_guacd_path();
    let docker = detect_docker();

    let tmpl = SetupTemplate {
        site_title: site_title.0.clone(),
        error: None,
        listen_addr,
        db_path: "/opt/rustguac/data/rustguac.db".to_string(),
        guacd_mode: if docker { "external".to_string() } else { "embedded".to_string() },
        guacd_addr: "127.0.0.1:4822".to_string(),
        guacd_path,
        admin_email: String::new(),
        admin_name: String::new(),
    };
    tmpl.into_response()
}

/// POST /setup — Process setup form.
pub async fn setup_submit(
    Extension(site_title): Extension<SiteTitle>,
    Extension(database): Extension<crate::db::Db>,
    Form(form): Form<SetupForm>,
) -> Response {
    if !needs_setup(&database) {
        return Redirect::to("/").into_response();
    }

    // Validate
    if form.admin_email.is_empty() || form.admin_password.len() < 8 {
        let tmpl = SetupTemplate {
            site_title: site_title.0.clone(),
            error: Some("Email is required and password must be at least 8 characters.".to_string()),
            listen_addr: form.listen_addr,
            db_path: form.db_path,
            guacd_mode: form.guacd_mode,
            guacd_addr: form.guacd_addr,
            guacd_path: form.guacd_path,
            admin_email: form.admin_email,
            admin_name: form.admin_name,
        };
        return tmpl.into_response();
    }

    // Hash password
    let password_hash = match crate::password::hash_password(&form.admin_password) {
        Ok(h) => h,
        Err(e) => {
            let tmpl = SetupTemplate {
                site_title: site_title.0.clone(),
                error: Some(format!("Failed to hash password: {}", e)),
                listen_addr: form.listen_addr,
                db_path: form.db_path,
                guacd_mode: form.guacd_mode,
                guacd_addr: form.guacd_addr,
                guacd_path: form.guacd_path,
                admin_email: form.admin_email,
                admin_name: form.admin_name,
            };
            return tmpl.into_response();
        }
    };

    // Create admin user in DB
    let now = chrono::Utc::now().to_rfc3339();
    {
        let conn = database.lock().unwrap();
        let _ = conn.execute(
            "ALTER TABLE users ADD COLUMN password_hash TEXT",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE users ADD COLUMN auth_source TEXT DEFAULT 'database'",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE users ADD COLUMN oidc_groups TEXT DEFAULT ''",
            [],
        );
        if let Err(e) = conn.execute(
            "INSERT INTO users (email, name, auth_source, password_hash, role, disabled, created_at)
             VALUES (?1, ?2, 'database', ?3, 'admin', 0, ?4)",
            rusqlite::params![form.admin_email, form.admin_name, password_hash, now],
        ) {
            let tmpl = SetupTemplate {
                site_title: site_title.0.clone(),
                error: Some(format!("Failed to create admin user: {}", e)),
                listen_addr: form.listen_addr,
                db_path: form.db_path,
                guacd_mode: form.guacd_mode,
                guacd_addr: form.guacd_addr,
                guacd_path: form.guacd_path,
                admin_email: form.admin_email,
                admin_name: form.admin_name,
            };
            return tmpl.into_response();
        }
    }

    // Write config file
    let guacd_section = if form.guacd_mode == "embedded" {
        format!(
            "guacd_mode = \"embedded\"\nguacd_path = \"{}\"",
            form.guacd_path
        )
    } else {
        format!(
            "guacd_mode = \"external\"\nguacd_addr = \"{}\"",
            form.guacd_addr
        )
    };

    let config = format!(
        r#"# rustguac configuration — generated by setup wizard
listen_addr = "{}"
db_path = "{}"
{}
recording_path = "/opt/rustguac/recordings"
static_path = "/opt/rustguac/static"
site_title = "rustguac"
session_max_duration_secs = 28800
session_cleanup_delay_secs = 300
session_history_retention_days = 90
"#,
        form.listen_addr, form.db_path, guacd_section
    );

    // Write to config path (same as the --config arg, or default location)
    let config_path = std::env::var("RUSTGUAC_CONFIG")
        .unwrap_or_else(|_| "/opt/rustguac/config.toml".to_string());

    if let Err(e) = std::fs::write(&config_path, &config) {
        tracing::warn!("Could not write config to {}: {}", config_path, e);
        // Non-fatal — user can create config manually
    } else {
        tracing::info!("Config written to {}", config_path);
    }

    tracing::info!(
        email = %form.admin_email,
        listen = %form.listen_addr,
        guacd_mode = %form.guacd_mode,
        "Setup completed"
    );

    // Redirect to login
    Redirect::to("/?setup=complete").into_response()
}
