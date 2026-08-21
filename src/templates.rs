use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use minijinja::{AutoEscape, Environment};
use serde::Serialize;
use std::sync::{Arc, LazyLock};

/// CSP nonce carried as a request extension by the security headers
/// middleware so page handlers can stamp inline scripts with `nonce=`.
#[derive(Clone)]
pub struct CspNonce(pub String);

/// Template environment shared across requests.
static TEMPLATES: LazyLock<Arc<Environment<'static>>> = LazyLock::new(|| {
    let mut env = Environment::new();

    // Autoescape all HTML templates: every `{{ }}` is HTML-escaped at render
    // time unless the value is explicitly marked safe (`| safe`). Reflected
    // values (site_title, logo_url, setup form fields, error messages) are
    // escaped by default instead of on a per-interpolation basis.
    env.set_auto_escape_callback(|name| {
        if name.ends_with(".html") {
            AutoEscape::Html
        } else {
            AutoEscape::None
        }
    });

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
        "pages/admin/roles.html",
        include_str!("../templates/pages/admin/roles.html"),
    )
    .expect("Failed to register pages/admin/roles.html");
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
        obj.insert(
            "version".to_string(),
            serde_json::to_value(env!("CARGO_PKG_VERSION")).unwrap_or_default(),
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
/// admin settings, plus one config-sourced flag):
///
/// ```jinja
/// {% if features.rdp %}          ← enable_rdp
/// {% if features.ssh_tunnels %}  ← enable_ssh_tunnels (jump-host UI)
/// {% if features.web_sessions %} ← enable_web_sessions
/// {% if features.vdi %}          ← enable_vdi
/// {% if features.powershell_ssh %} ← enable_powershell_ssh
/// {% if features.spice %}        ← enable_spice
/// {% if features.proxmox %}      ← enable_proxmox
/// {% if features.vmware %}       ← enable_vmware
/// {% if features.recordings %}   ← enable_recordings
/// {% if features.api_keys %}     ← enable_api_keys
/// {% if features.desktop_bridge %} ← NOT an enable_* setting: mirrors the
///                                     [desktop] allow_bridge config flag
///                                     (src/config.rs, `init_allow_bridge`)
/// ```
///
/// There are NO `enable_ssh` / `enable_vnc` toggles: the ssh and vnc
/// options must always render. The `connections.html` em-type dropdown and
/// the proxmox field block behind it gate on these flags (batch-2 work).
#[derive(Serialize, Clone, Debug)]
pub struct FeatureFlags {
    /// RDP connection type available in the UI (`enable_rdp`).
    pub rdp: bool,
    /// Jump-host and SSH tunnel management UI (`enable_ssh_tunnels`).
    pub ssh_tunnels: bool,
    /// Browser-based web sessions (`enable_web_sessions`).
    pub web_sessions: bool,
    /// VDI desktop container sessions (`enable_vdi`).
    pub vdi: bool,
    /// PowerShell remoting over SSH connection type (`enable_powershell_ssh`).
    pub powershell_ssh: bool,
    /// SPICE connection type available in the UI (`enable_spice`).
    pub spice: bool,
    /// Proxmox VE connection type (`enable_proxmox`).
    pub proxmox: bool,
    /// VMware connection type (`enable_vmware`).
    pub vmware: bool,
    /// Recordings page and playback (`enable_recordings`).
    pub recordings: bool,
    /// API key creation from the account page (`enable_api_keys`).
    pub api_keys: bool,
    /// Desktop shell bridge (`[desktop] allow_bridge` config flag, NOT an
    /// `enable_*` setting). Gates the base.html desktop bridge partial; the
    /// CSP `connect-src` addition is gated on the same flag.
    pub desktop_bridge: bool,
}

impl Default for FeatureFlags {
    /// All toggles default ON — a fresh install (or any render outside a
    /// request, e.g. tests) behaves exactly as before the flags existed.
    /// `desktop_bridge` mirrors the config flag instead, which defaults to
    /// false (no bridge = exactly as before).
    fn default() -> Self {
        Self {
            rdp: true,
            ssh_tunnels: true,
            web_sessions: true,
            vdi: true,
            powershell_ssh: true,
            spice: true,
            proxmox: true,
            vmware: true,
            recordings: true,
            api_keys: true,
            desktop_bridge: crate::config::allow_bridge_enabled(),
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
            powershell_ssh: crate::settings_merge::toggle_enabled(
                settings,
                "enable_powershell_ssh",
                true,
            ),
            spice: crate::settings_merge::toggle_enabled(settings, "enable_spice", true),
            proxmox: crate::settings_merge::toggle_enabled(settings, "enable_proxmox", true),
            vmware: crate::settings_merge::toggle_enabled(settings, "enable_vmware", true),
            recordings: crate::settings_merge::toggle_enabled(settings, "enable_recordings", true),
            api_keys: crate::settings_merge::toggle_enabled(settings, "enable_api_keys", true),
            desktop_bridge: crate::config::allow_bridge_enabled(),
        }
    }
}

// Request-scoped feature flags, carried across awaits for the duration of
// one HTML-page request (mirrors the ERROR_CONTEXT pattern in error.rs).
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
    /// Site title shown on the login card and in the browser tab.
    pub site_title: String,
    /// Branding logo URL; empty renders the default placeholder.
    pub logo_url: String,
    /// Whether an OIDC provider is configured, which shows the SSO button.
    pub oidc_enabled: bool,
    /// Whether SAML is configured, which shows the SAML SSO button.
    pub saml_enabled: bool,
    /// Label on the OIDC SSO button.
    pub oidc_button_text: String,
    /// Label on the SAML SSO button.
    pub saml_button_text: String,
    /// One entry per configured OIDC provider (multi-provider SSO).
    pub oidc_providers: Vec<String>,
    /// Error message from a failed login redirect (`/?error=...`).
    pub error: Option<String>,
    /// CSP nonce for the inline scripts on the login page.
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
    /// Site title shown in the page header and browser tab.
    pub site_title: String,
    /// Branding logo URL resolved from config and DB settings; empty
    /// renders the default placeholder.
    pub logo_url: String,
    /// Whether the signed-in user holds the admin role; drives the admin
    /// entries in the sidebar.
    pub is_admin: bool,
    /// Sidebar highlight key naming the current page, e.g. "connections".
    pub active_page: String,
    /// CSP nonce that inline scripts in the rendered page must carry.
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
    /// Site title shown in the page header and browser tab.
    pub site_title: String,
    /// Branding logo URL resolved from config and DB settings; empty
    /// renders the default placeholder.
    pub logo_url: String,
    /// Whether the signed-in user holds the admin role; drives the admin
    /// entries in the sidebar.
    pub is_admin: bool,
    /// Sidebar highlight key naming the current page, e.g. "connections".
    pub active_page: String,
    /// CSP nonce that inline scripts in the rendered page must carry.
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
    /// Site title shown in the page header and browser tab.
    pub site_title: String,
    /// Branding logo URL resolved from config and DB settings; empty
    /// renders the default placeholder.
    pub logo_url: String,
    /// Whether the signed-in user holds the admin role; drives the admin
    /// entries in the sidebar.
    pub is_admin: bool,
    /// Sidebar highlight key naming the current page, e.g. "connections".
    pub active_page: String,
    /// CSP nonce that inline scripts in the rendered page must carry.
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
    /// Site title shown in the page header and browser tab.
    pub site_title: String,
    /// Branding logo URL resolved from config and DB settings; empty
    /// renders the default placeholder.
    pub logo_url: String,
    /// Whether the signed-in user holds the admin role; drives the admin
    /// entries in the sidebar.
    pub is_admin: bool,
    /// Sidebar highlight key naming the current page, e.g. "connections".
    pub active_page: String,
    /// CSP nonce that inline scripts in the rendered page must carry.
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
    /// Site title shown in the page header and browser tab.
    pub site_title: String,
    /// Branding logo URL resolved from config and DB settings; empty
    /// renders the default placeholder.
    pub logo_url: String,
    /// Whether the signed-in user holds the admin role; drives the admin
    /// entries in the sidebar.
    pub is_admin: bool,
    /// Sidebar highlight key naming the current page, e.g. "connections".
    pub active_page: String,
    /// CSP nonce that inline scripts in the rendered page must carry.
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
    /// Site title shown in the page header and browser tab.
    pub site_title: String,
    /// Branding logo URL resolved from config and DB settings; empty
    /// renders the default placeholder.
    pub logo_url: String,
    /// Whether the signed-in user holds the admin role; drives the admin
    /// entries in the sidebar.
    pub is_admin: bool,
    /// Sidebar highlight key naming the current page, e.g. "connections".
    pub active_page: String,
    /// CSP nonce that inline scripts in the rendered page must carry.
    pub csp_nonce: String,
}

impl IntoResponse for AdminGroupsTemplate {
    fn into_response(self) -> Response {
        render_template("pages/admin/groups.html", &self)
    }
}

/// Admin custom roles page template context (T05/T06).
#[derive(Serialize)]
pub struct AdminRolesTemplate {
    /// Site title shown in the page header and browser tab.
    pub site_title: String,
    /// Branding logo URL resolved from config and DB settings; empty
    /// renders the default placeholder.
    pub logo_url: String,
    /// Whether the signed-in user holds the admin role; drives the admin
    /// entries in the sidebar.
    pub is_admin: bool,
    /// Sidebar highlight key naming the current page, e.g. "connections".
    pub active_page: String,
    /// CSP nonce that inline scripts in the rendered page must carry.
    pub csp_nonce: String,
}

impl IntoResponse for AdminRolesTemplate {
    fn into_response(self) -> Response {
        render_template("pages/admin/roles.html", &self)
    }
}

/// Admin audit log page template context.
#[derive(Serialize)]
pub struct AdminAuditTemplate {
    /// Site title shown in the page header and browser tab.
    pub site_title: String,
    /// Branding logo URL resolved from config and DB settings; empty
    /// renders the default placeholder.
    pub logo_url: String,
    /// Whether the signed-in user holds the admin role; drives the admin
    /// entries in the sidebar.
    pub is_admin: bool,
    /// Sidebar highlight key naming the current page, e.g. "connections".
    pub active_page: String,
    /// CSP nonce that inline scripts in the rendered page must carry.
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
    /// Site title shown in the page header and browser tab.
    pub site_title: String,
    /// Branding logo URL resolved from config and DB settings; empty
    /// renders the default placeholder.
    pub logo_url: String,
    /// Whether the signed-in user holds the admin role; drives the admin
    /// entries in the sidebar.
    pub is_admin: bool,
    /// Sidebar highlight key naming the current page, e.g. "connections".
    pub active_page: String,
    /// CSP nonce that inline scripts in the rendered page must carry.
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
    /// Site title shown in the page header and browser tab.
    pub site_title: String,
    /// Branding logo URL resolved from config and DB settings; empty
    /// renders the default placeholder.
    pub logo_url: String,
    /// Whether the signed-in user holds the admin role; drives the admin
    /// entries in the sidebar.
    pub is_admin: bool,
    /// Sidebar highlight key naming the current page, e.g. "connections".
    pub active_page: String,
    /// CSP nonce that inline scripts in the rendered page must carry.
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
    /// Site title shown in the page header and browser tab.
    pub site_title: String,
    /// Branding logo URL resolved from config and DB settings; empty
    /// renders the default placeholder.
    pub logo_url: String,
    /// Whether the signed-in user holds the admin role; drives the admin
    /// entries in the sidebar.
    pub is_admin: bool,
    /// Sidebar highlight key naming the current page, e.g. "connections".
    pub active_page: String,
    /// CSP nonce that inline scripts in the rendered page must carry.
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
    /// Site title shown in the page header and browser tab.
    pub site_title: String,
    /// Branding logo URL resolved from config and DB settings; empty
    /// renders the default placeholder.
    pub logo_url: String,
    /// Whether the signed-in user holds the admin role; drives the admin
    /// entries in the sidebar.
    pub is_admin: bool,
    /// Sidebar highlight key naming the current page, e.g. "connections".
    pub active_page: String,
    /// CSP nonce that inline scripts in the rendered page must carry.
    pub csp_nonce: String,
}

impl IntoResponse for AdminBrandingTemplate {
    fn into_response(self) -> Response {
        render_template("pages/admin/branding.html", &self)
    }
}

/// Client (remote desktop) page template context.
#[derive(Serialize)]
pub struct ClientTemplate {
    /// Site title shown in the client page header.
    pub site_title: String,
    /// CSP nonce for the Guacamole client's inline scripts.
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
    /// Site title shown in the page header and browser tab.
    pub site_title: String,
    /// Branding logo URL resolved from config and DB settings; empty
    /// renders the default placeholder.
    pub logo_url: String,
    /// Whether the signed-in user holds the admin role; drives the admin
    /// entries in the sidebar.
    pub is_admin: bool,
    /// Sidebar highlight key naming the current page, e.g. "connections".
    pub active_page: String,
    /// CSP nonce that inline scripts in the rendered page must carry.
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
    /// Site title shown in the page header and browser tab.
    pub site_title: String,
    /// Branding logo URL resolved from config and DB settings; empty
    /// renders the default placeholder.
    pub logo_url: String,
    /// Whether the signed-in user holds the admin role; drives the admin
    /// entries in the sidebar.
    pub is_admin: bool,
    /// Sidebar highlight key naming the current page, e.g. "connections".
    pub active_page: String,
    /// CSP nonce that inline scripts in the rendered page must carry.
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
    /// Site title shown in the page header and browser tab.
    pub site_title: String,
    /// Branding logo URL resolved from config and DB settings; empty
    /// renders the default placeholder.
    pub logo_url: String,
    /// Whether the signed-in user holds the admin role; drives the admin
    /// entries in the sidebar.
    pub is_admin: bool,
    /// Sidebar highlight key naming the current page, e.g. "connections".
    pub active_page: String,
    /// CSP nonce that inline scripts in the rendered page must carry.
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
    /// Site title shown in the page header and browser tab.
    pub site_title: String,
    /// Branding logo URL resolved from config and DB settings; empty
    /// renders the default placeholder.
    pub logo_url: String,
    /// Whether the signed-in user holds the admin role; drives the admin
    /// entries in the sidebar.
    pub is_admin: bool,
    /// Sidebar highlight key naming the current page, e.g. "connections".
    pub active_page: String,
    /// CSP nonce that inline scripts in the rendered page must carry.
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
    /// Site title shown in the page header and browser tab.
    pub site_title: String,
    /// Branding logo URL resolved from config and DB settings; empty
    /// renders the default placeholder.
    pub logo_url: String,
    /// Whether the signed-in user holds the admin role; drives the admin
    /// entries in the sidebar.
    pub is_admin: bool,
    /// Sidebar highlight key naming the current page, e.g. "connections".
    pub active_page: String,
    /// CSP nonce that inline scripts in the rendered page must carry.
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
    /// HTTP status the response carries, also surfaced on the page.
    pub status_code: u16,
    /// Short page heading, usually the status canonical reason.
    pub title: String,
    /// Explanation shown under the heading.
    pub message: String,
    /// CSP nonce for inline scripts on the error page.
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

/// Backward-compatible alias for [`LoginTemplate`] under its old name.
pub type LoginPageTemplate = LoginTemplate;

/// First-run setup wizard template context.
///
/// Rendered by `setup_page` with a clean form, and re-rendered with
/// `error` set when the submitted form fails validation so the entered
/// values stay visible.
#[derive(serde::Serialize)]
pub struct SetupTemplate {
    /// Site title shown on the wizard.
    pub site_title: String,
    /// Validation or backend error to display; None renders a clean form.
    pub error: Option<String>,
    /// Listen address prefilled from detected machine IPs.
    pub listen_addr: String,
    /// SQLite database path used when no managed backend URL is entered.
    pub db_path: String,
    /// Optional managed-backend URL (Postgres/MySQL/...) entered in the
    /// wizard; empty means the legacy SQLite file at `db_path`.
    pub db_url: String,
    /// Label of the active store backend ("PostgreSQL", "MySQL", "SQLite")
    /// when a SQLx pool is installed (db_url configured); None = legacy
    /// SQLite file mode.
    pub backend: Option<String>,
    /// guacd TCP address the server connects to, e.g. "127.0.0.1:4822".
    pub guacd_addr: String,
    /// Email address of the admin account the wizard creates.
    pub admin_email: String,
    /// Display name of the admin account.
    pub admin_name: String,
    /// Minimum password length enforced by the `[password]` policy; the
    /// wizard renders it into the password field hint and `minlength`.
    pub password_min_length: usize,
    /// CSP nonce for inline scripts on the setup page.
    pub csp_nonce: String,
}

impl IntoResponse for SetupTemplate {
    fn into_response(self) -> Response {
        render_template("pages/setup.html", &self)
    }
}
