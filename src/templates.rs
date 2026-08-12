use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use minijinja::Environment;
use serde::Serialize;
use std::sync::{Arc, LazyLock};

/// Template environment shared across requests.
static TEMPLATES: LazyLock<Arc<Environment<'static>>> = LazyLock::new(|| {
    let mut env = Environment::new();

    // Register templates
    env.add_template("base.html", include_str!("../templates/base.html"))
        .expect("Failed to register base.html");
    env.add_template(
        "layouts/app.html",
        include_str!("../templates/layouts/app.html"),
    )
    .expect("Failed to register layouts/app.html");
    env.add_template(
        "partials/sidebar.html",
        include_str!("../templates/partials/sidebar.html"),
    )
    .expect("Failed to register partials/sidebar.html");
    env.add_template(
        "partials/header.html",
        include_str!("../templates/partials/header.html"),
    )
    .expect("Failed to register partials/header.html");
    env.add_template(
        "pages/login.html",
        include_str!("../templates/pages/login.html"),
    )
    .expect("Failed to register pages/login.html");
    env.add_template(
        "pages/connections.html",
        include_str!("../templates/pages/connections.html"),
    )
    .expect("Failed to register pages/connections.html");
    env.add_template(
        "pages/sessions.html",
        include_str!("../templates/pages/sessions.html"),
    )
    .expect("Failed to register pages/sessions.html");
    env.add_template(
        "pages/recordings.html",
        include_str!("../templates/pages/recordings.html"),
    )
    .expect("Failed to register pages/recordings.html");
    env.add_template(
        "pages/client.html",
        include_str!("../templates/pages/client.html"),
    )
    .expect("Failed to register pages/client.html");
    env.add_template(
        "pages/setup.html",
        include_str!("../templates/pages/setup.html"),
    )
    .expect("Failed to register pages/setup.html");
    env.add_template(
        "pages/admin/users.html",
        include_str!("../templates/pages/admin/users.html"),
    )
    .expect("Failed to register pages/admin/users.html");
    env.add_template(
        "pages/admin/auth.html",
        include_str!("../templates/pages/admin/auth.html"),
    )
    .expect("Failed to register pages/admin/auth.html");
    env.add_template(
        "pages/admin/groups.html",
        include_str!("../templates/pages/admin/groups.html"),
    )
    .expect("Failed to register pages/admin/groups.html");
    env.add_template(
        "pages/admin/audit.html",
        include_str!("../templates/pages/admin/audit.html"),
    )
    .expect("Failed to register pages/admin/audit.html");
    env.add_template(
        "pages/admin/settings.html",
        include_str!("../templates/pages/admin/settings.html"),
    )
    .expect("Failed to register pages/admin/settings.html");
    env.add_template(
        "pages/admin/reports.html",
        include_str!("../templates/pages/admin/reports.html"),
    )
    .expect("Failed to register pages/admin/reports.html");
    env.add_template(
        "pages/admin/tunnels.html",
        include_str!("../templates/pages/admin/tunnels.html"),
    )
    .expect("Failed to register pages/admin/tunnels.html");
    env.add_template(
        "pages/admin/license.html",
        include_str!("../templates/pages/admin/license.html"),
    )
    .expect("Failed to register pages/admin/license.html");
    env.add_template(
        "pages/admin/branding.html",
        include_str!("../templates/pages/admin/branding.html"),
    )
    .expect("Failed to register pages/admin/branding.html");
    env.add_template(
        "pages/account/profile.html",
        include_str!("../templates/pages/account/profile.html"),
    )
    .expect("Failed to register pages/account/profile.html");
    env.add_template(
        "pages/account/tokens.html",
        include_str!("../templates/pages/account/tokens.html"),
    )
    .expect("Failed to register pages/account/tokens.html");
    env.add_template(
        "pages/account/totp.html",
        include_str!("../templates/pages/account/totp.html"),
    )
    .expect("Failed to register pages/account/totp.html");
    env.add_template(
        "pages/docs.html",
        include_str!("../templates/pages/docs.html"),
    )
    .expect("Failed to register pages/docs.html");
    env.add_template(
        "pages/error.html",
        include_str!("../templates/pages/error.html"),
    )
    .expect("Failed to register pages/error.html");

    Arc::new(env)
});

/// Helper to render a template into an axum response.
///
/// The per-request feature flags (see [`FeatureFlags`]) are merged into
/// every rendered context under the key `features`, so all app pages — and
/// the shared sidebar partial they include — can gate UI on the admin
/// `enable_*` settings without touching individual template structs. The
/// flags are sourced from `load_db_settings` once per request by the
/// `features_context` middleware in main.rs.
fn render_template(template_name: &str, context: &impl Serialize) -> Response {
    let tmpl = match TEMPLATES.get_template(template_name) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Template not found: {}", e),
            )
                .into_response()
        }
    };
    let mut value = match serde_json::to_value(context) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Template context error: {}", e),
            )
                .into_response()
        }
    };
    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "features".to_string(),
            serde_json::to_value(request_features()).unwrap_or_default(),
        );
    }
    match tmpl.render(&value) {
        Ok(html) => Html(html).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Template error: {}", e),
        )
            .into_response(),
    }
}

/// Render a page template wrapped in the app layout.
fn render_app_page(page_template: &str, context: &impl Serialize) -> Response {
    // minijinja renders the page template, which extends layouts/app.html
    render_template(page_template, context)
}

// ── Feature flags ──────────────────────────────────────────────────────────

/// Feature toggle flags for the current request, sourced from the
/// `system_settings` table (`load_db_settings`, once per request by the
/// `features_context` middleware in main.rs) and merged into every rendered
/// template context under the key `features`.
///
/// CONTRACT for template consumers — the rendered context carries a
/// `features` object with EXACTLY these keys (1:1 with the `enable_*`
/// admin settings):
///
/// ```jinja
/// {% if features.rdp %}          ← enable_rdp
/// {% if features.ssh_tunnels %}  ← enable_ssh_tunnels (jump-host UI)
/// {% if features.web_sessions %} ← enable_web_sessions
/// {% if features.vdi %}          ← enable_vdi
/// {% if features.spice %}        ← enable_spice
/// {% if features.proxmox %}      ← enable_proxmox
/// {% if features.vmware %}       ← enable_vmware
/// {% if features.recordings %}   ← enable_recordings
/// {% if features.api_keys %}     ← enable_api_keys
/// ```
///
/// There are NO `enable_ssh` / `enable_vnc` toggles: the ssh and vnc
/// options must always render. The `connections.html` em-type dropdown and
/// the proxmox field block behind it gate on these flags (batch-2 work).
#[derive(Serialize, Clone, Debug)]
pub struct FeatureFlags {
    pub rdp: bool,
    pub ssh_tunnels: bool,
    pub web_sessions: bool,
    pub vdi: bool,
    pub spice: bool,
    pub proxmox: bool,
    pub vmware: bool,
    pub recordings: bool,
    pub api_keys: bool,
}

impl Default for FeatureFlags {
    /// All toggles default ON — a fresh install (or any render outside a
    /// request, e.g. tests) behaves exactly as before the flags existed.
    fn default() -> Self {
        Self {
            rdp: true,
            ssh_tunnels: true,
            web_sessions: true,
            vdi: true,
            spice: true,
            proxmox: true,
            vmware: true,
            recordings: true,
            api_keys: true,
        }
    }
}

impl FeatureFlags {
    /// Build from raw `system_settings` rows; unset/unreadable toggles
    /// default to enabled so existing deployments behave as before.
    pub fn from_settings(settings: &[(String, String)]) -> Self {
        Self {
            rdp: crate::settings_merge::toggle_enabled(settings, "enable_rdp", true),
            ssh_tunnels: crate::settings_merge::toggle_enabled(
                settings,
                "enable_ssh_tunnels",
                true,
            ),
            web_sessions: crate::settings_merge::toggle_enabled(
                settings,
                "enable_web_sessions",
                true,
            ),
            vdi: crate::settings_merge::toggle_enabled(settings, "enable_vdi", true),
            spice: crate::settings_merge::toggle_enabled(settings, "enable_spice", true),
            proxmox: crate::settings_merge::toggle_enabled(settings, "enable_proxmox", true),
            vmware: crate::settings_merge::toggle_enabled(settings, "enable_vmware", true),
            recordings: crate::settings_merge::toggle_enabled(settings, "enable_recordings", true),
            api_keys: crate::settings_merge::toggle_enabled(settings, "enable_api_keys", true),
        }
    }
}

/// Request-scoped feature flags, carried across awaits for the duration of
/// one HTML-page request (mirrors the ERROR_CONTEXT pattern in error.rs).
tokio::task_local! {
    static REQUEST_FEATURES: Arc<FeatureFlags>;
}

/// Run `future` with the given feature flags visible to template rendering.
/// Called by the `features_context` middleware in main.rs.
pub async fn run_with_features<F>(features: Arc<FeatureFlags>, future: F) -> F::Output
where
    F: std::future::Future,
{
    REQUEST_FEATURES.scope(features, future).await
}

/// Feature flags for the current request; all-enabled defaults when no
/// request context exists (login/error/setup pages, unit tests).
fn request_features() -> FeatureFlags {
    REQUEST_FEATURES
        .try_with(|f| f.as_ref().clone())
        .unwrap_or_default()
}

// ── Template contexts ───────────────────────────────────────────────────────

/// Login page template context.
#[derive(Serialize)]
pub struct LoginTemplate {
    pub site_title: String,
    pub logo_url: String,
    pub oidc_enabled: bool,
    pub saml_enabled: bool,
    pub oidc_button_text: String,
    pub saml_button_text: String,
    /// One entry per configured OIDC provider (multi-provider SSO).
    pub oidc_providers: Vec<String>,
    /// Error message from a failed login redirect (`/?error=...`).
    pub error: Option<String>,
    pub csp_nonce: String,
}

impl IntoResponse for LoginTemplate {
    fn into_response(self) -> Response {
        render_template("pages/login.html", &self)
    }
}

/// App layout wrapper — all authenticated pages pass through this.
/// The inner page template is specified at render time (via `extends`).
#[derive(Serialize)]
pub struct AppLayoutTemplate {
    pub site_title: String,
    pub logo_url: String,
    pub is_admin: bool,
    pub active_page: String,
    pub csp_nonce: String,
}

impl AppLayoutTemplate {
    /// Render a specific page within the app layout.
    pub fn render_page(&self, page_template: &str) -> Response {
        render_app_page(page_template, self)
    }
}

/// Connections page template context.
#[derive(Serialize)]
pub struct ConnectionsPageTemplate {
    pub site_title: String,
    pub logo_url: String,
    pub is_admin: bool,
    pub active_page: String,
    pub csp_nonce: String,
}

impl IntoResponse for ConnectionsPageTemplate {
    fn into_response(self) -> Response {
        render_template("pages/connections.html", &self)
    }
}

/// Sessions page template context.
#[derive(Serialize)]
pub struct SessionsPageTemplate {
    pub site_title: String,
    pub logo_url: String,
    pub is_admin: bool,
    pub active_page: String,
    pub csp_nonce: String,
}

impl IntoResponse for SessionsPageTemplate {
    fn into_response(self) -> Response {
        render_template("pages/sessions.html", &self)
    }
}

// ── Admin page templates ──

/// Admin users page template context.
#[derive(Serialize)]
pub struct AdminUsersTemplate {
    pub site_title: String,
    pub logo_url: String,
    pub is_admin: bool,
    pub active_page: String,
    pub csp_nonce: String,
}

impl IntoResponse for AdminUsersTemplate {
    fn into_response(self) -> Response {
        render_template("pages/admin/users.html", &self)
    }
}

/// Admin auth providers page template context.
#[derive(Serialize)]
pub struct AdminAuthTemplate {
    pub site_title: String,
    pub logo_url: String,
    pub is_admin: bool,
    pub active_page: String,
    pub csp_nonce: String,
}

impl IntoResponse for AdminAuthTemplate {
    fn into_response(self) -> Response {
        render_template("pages/admin/auth.html", &self)
    }
}

/// Admin groups page template context.
#[derive(Serialize)]
pub struct AdminGroupsTemplate {
    pub site_title: String,
    pub logo_url: String,
    pub is_admin: bool,
    pub active_page: String,
    pub csp_nonce: String,
}

impl IntoResponse for AdminGroupsTemplate {
    fn into_response(self) -> Response {
        render_template("pages/admin/groups.html", &self)
    }
}

/// Admin audit log page template context.
#[derive(Serialize)]
pub struct AdminAuditTemplate {
    pub site_title: String,
    pub logo_url: String,
    pub is_admin: bool,
    pub active_page: String,
    pub csp_nonce: String,
}

impl IntoResponse for AdminAuditTemplate {
    fn into_response(self) -> Response {
        render_template("pages/admin/audit.html", &self)
    }
}

/// Admin settings page template context.
#[derive(Serialize)]
pub struct AdminSettingsTemplate {
    pub site_title: String,
    pub logo_url: String,
    pub is_admin: bool,
    pub active_page: String,
    pub csp_nonce: String,
}

impl IntoResponse for AdminSettingsTemplate {
    fn into_response(self) -> Response {
        render_template("pages/admin/settings.html", &self)
    }
}

/// Admin reports page template context.
#[derive(Serialize)]
pub struct AdminReportsTemplate {
    pub site_title: String,
    pub logo_url: String,
    pub is_admin: bool,
    pub active_page: String,
    pub csp_nonce: String,
}

impl IntoResponse for AdminReportsTemplate {
    fn into_response(self) -> Response {
        render_template("pages/admin/reports.html", &self)
    }
}

/// Admin tunnels page template context.
#[derive(Serialize)]
pub struct AdminTunnelsTemplate {
    pub site_title: String,
    pub logo_url: String,
    pub is_admin: bool,
    pub active_page: String,
    pub csp_nonce: String,
}

impl IntoResponse for AdminTunnelsTemplate {
    fn into_response(self) -> Response {
        render_template("pages/admin/tunnels.html", &self)
    }
}

/// Admin branding page template context.
#[derive(Serialize)]
pub struct AdminBrandingTemplate {
    pub site_title: String,
    pub logo_url: String,
    pub is_admin: bool,
    pub active_page: String,
    pub csp_nonce: String,
}

impl IntoResponse for AdminBrandingTemplate {
    fn into_response(self) -> Response {
        render_template("pages/admin/branding.html", &self)
    }
}

/// Admin license page template context.
#[derive(Serialize)]
pub struct AdminLicenseTemplate {
    pub site_title: String,
    pub logo_url: String,
    pub is_admin: bool,
    pub active_page: String,
    pub csp_nonce: String,
}

impl IntoResponse for AdminLicenseTemplate {
    fn into_response(self) -> Response {
        render_template("pages/admin/license.html", &self)
    }
}

/// Client (remote desktop) page template context.
#[derive(Serialize)]
pub struct ClientTemplate {
    pub site_title: String,
    pub csp_nonce: String,
}

impl IntoResponse for ClientTemplate {
    fn into_response(self) -> Response {
        render_template("pages/client.html", &self)
    }
}

/// Recordings page template context.
#[derive(Serialize)]
pub struct RecordingsPageTemplate {
    pub site_title: String,
    pub logo_url: String,
    pub is_admin: bool,
    pub active_page: String,
    pub csp_nonce: String,
}

impl IntoResponse for RecordingsPageTemplate {
    fn into_response(self) -> Response {
        render_template("pages/recordings.html", &self)
    }
}

/// Profile page template context.
#[derive(Serialize)]
pub struct ProfileTemplate {
    pub site_title: String,
    pub logo_url: String,
    pub is_admin: bool,
    pub active_page: String,
    pub csp_nonce: String,
}

impl IntoResponse for ProfileTemplate {
    fn into_response(self) -> Response {
        render_template("pages/account/profile.html", &self)
    }
}

/// Account tokens page template context.
#[derive(Serialize)]
pub struct AccountTokensTemplate {
    pub site_title: String,
    pub logo_url: String,
    pub is_admin: bool,
    pub active_page: String,
    pub csp_nonce: String,
}

impl IntoResponse for AccountTokensTemplate {
    fn into_response(self) -> Response {
        render_template("pages/account/tokens.html", &self)
    }
}

/// Account TOTP page template context.
#[derive(Serialize)]
pub struct AccountTotpTemplate {
    pub site_title: String,
    pub logo_url: String,
    pub is_admin: bool,
    pub active_page: String,
    pub csp_nonce: String,
}

impl IntoResponse for AccountTotpTemplate {
    fn into_response(self) -> Response {
        render_template("pages/account/totp.html", &self)
    }
}

/// Docs page template context.
#[derive(Serialize)]
pub struct DocsTemplate {
    pub site_title: String,
    pub logo_url: String,
    pub is_admin: bool,
    pub active_page: String,
    pub csp_nonce: String,
}

impl IntoResponse for DocsTemplate {
    fn into_response(self) -> Response {
        render_template("pages/docs.html", &self)
    }
}

/// Styled error page template context.
#[derive(Serialize)]
pub struct ErrorPageTemplate {
    pub status_code: u16,
    pub title: String,
    pub message: String,
    pub csp_nonce: String,
}

impl IntoResponse for ErrorPageTemplate {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = render_template("pages/error.html", &self);
        *response.status_mut() = status;
        response
    }
}

/// Render the styled error page for `status` with the given message.
/// The page carries the HTTP status so it works as a fallback service too.
pub fn render_error_page(status: StatusCode, message: &str, csp_nonce: &str) -> Response {
    ErrorPageTemplate {
        status_code: status.as_u16(),
        title: status.canonical_reason().unwrap_or("Error").to_string(),
        message: message.to_string(),
        csp_nonce: csp_nonce.to_string(),
    }
    .into_response()
}

// Re-export old name for backward compatibility
pub type LoginPageTemplate = LoginTemplate;

#[derive(serde::Serialize)]
pub struct SetupTemplate {
    pub site_title: String,
    pub error: Option<String>,
    pub listen_addr: String,
    pub db_path: String,
    /// Optional managed-backend URL (Postgres/MySQL/...) entered in the
    /// wizard; empty means the legacy SQLite file at `db_path`.
    pub db_url: String,
    /// Label of the active store backend ("PostgreSQL", "MySQL", "SQLite")
    /// when a SQLx pool is installed (db_url configured); None = legacy
    /// SQLite file mode.
    pub backend: Option<String>,
    pub guacd_mode: String,
    pub guacd_addr: String,
    pub guacd_path: String,
    pub admin_email: String,
    pub admin_name: String,
    pub csp_nonce: String,
}

impl IntoResponse for SetupTemplate {
    fn into_response(self) -> Response {
        render_template("pages/setup.html", &self)
    }
}
