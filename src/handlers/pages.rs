use axum::response::{IntoResponse, Response};
use axum::Extension;

use crate::api::{SiteTitle, ThemeData};
use crate::auth::AuthIdentity;
use crate::db::Db;
use crate::templates::{
    AdminAuditTemplate, AdminAuthTemplate, AdminBrandingTemplate, AdminGroupsTemplate,
    AdminLicenseTemplate, AdminReportsTemplate, AdminSettingsTemplate, AdminTunnelsTemplate,
    AdminUsersTemplate, ConnectionsPageTemplate, RecordingsPageTemplate, SessionsPageTemplate,
};
use crate::CspNonce;

/// Determine if the current user has admin role.
fn is_admin(identity: &Option<Extension<AuthIdentity>>) -> bool {
    identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
}

/// Branding logo URL resolved from the startup ThemeData (config + DB
/// settings overlay); empty string renders the sidebar/login placeholder.
fn logo_url(theme: &ThemeData) -> String {
    theme.logo_url.clone().unwrap_or_default()
}

/// GET /connections.html — connections page.
///
/// Template contract (see `FeatureFlags` in templates.rs): the rendered
/// context carries a `features` object with exactly these keys —
/// rdp, ssh_tunnels, web_sessions, vdi, spice, proxmox, vmware, recordings,
/// api_keys — so connections.html can gate its `em-type` dropdown and the
/// proxmox field block, e.g. `{% if features.proxmox %}`. ssh/vnc have no
/// toggles and must always render. Flags are sourced from `load_db_settings`
/// once per request (features_context middleware).
pub async fn connections_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let tmpl = ConnectionsPageTemplate {
        site_title: site_title.0.clone(),
        logo_url: logo_url(&theme),
        is_admin: is_admin(&identity),
        active_page: "connections".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

/// GET /sessions.html — sessions page.
pub async fn sessions_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let tmpl = SessionsPageTemplate {
        site_title: site_title.0.clone(),
        logo_url: logo_url(&theme),
        is_admin: is_admin(&identity),
        active_page: "sessions".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

/// GET /recordings.html — recordings page.
/// Returns 404 (request-time) when the `enable_recordings` admin toggle is
/// off, so a disabled feature is indistinguishable from a missing page.
pub async fn recordings_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
    Extension(db): Extension<Db>,
) -> Response {
    if !crate::settings_merge::read_toggle(&db, "enable_recordings", true) {
        return crate::templates::render_error_page(
            axum::http::StatusCode::NOT_FOUND,
            "The page you requested could not be found",
            &nonce.0,
        );
    }
    let tmpl = RecordingsPageTemplate {
        site_title: site_title.0.clone(),
        logo_url: logo_url(&theme),
        is_admin: is_admin(&identity),
        active_page: "recordings".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

// ── Admin pages ──

/// GET /admin/users.html — admin user management page.
pub async fn admin_users_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let tmpl = AdminUsersTemplate {
        site_title: site_title.0.clone(),
        logo_url: logo_url(&theme),
        is_admin: is_admin(&identity),
        active_page: "users".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

/// GET /admin/auth.html — admin auth providers page.
pub async fn admin_auth_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let tmpl = AdminAuthTemplate {
        site_title: site_title.0.clone(),
        logo_url: logo_url(&theme),
        is_admin: is_admin(&identity),
        active_page: "auth".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

/// GET /admin/groups.html — admin groups page.
pub async fn admin_groups_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let tmpl = AdminGroupsTemplate {
        site_title: site_title.0.clone(),
        logo_url: logo_url(&theme),
        is_admin: is_admin(&identity),
        active_page: "groups".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

/// GET /admin/audit.html — admin audit log page.
pub async fn admin_audit_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let tmpl = AdminAuditTemplate {
        site_title: site_title.0.clone(),
        logo_url: logo_url(&theme),
        is_admin: is_admin(&identity),
        active_page: "audit".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

/// GET /admin/settings.html — admin settings page.
pub async fn admin_settings_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let tmpl = AdminSettingsTemplate {
        site_title: site_title.0.clone(),
        logo_url: logo_url(&theme),
        is_admin: is_admin(&identity),
        active_page: "settings".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

/// GET /admin/reports.html — admin reports page.
pub async fn admin_reports_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let tmpl = AdminReportsTemplate {
        site_title: site_title.0.clone(),
        logo_url: logo_url(&theme),
        is_admin: is_admin(&identity),
        active_page: "reports".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

/// GET /admin/tunnels.html — admin SSH tunnels management page.
/// Returns 404 (request-time) when the `enable_ssh_tunnels` admin toggle is
/// off, so a disabled feature is indistinguishable from a missing page.
pub async fn admin_tunnels_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
    Extension(db): Extension<Db>,
) -> Response {
    if !crate::settings_merge::read_toggle(&db, "enable_ssh_tunnels", true) {
        return crate::templates::render_error_page(
            axum::http::StatusCode::NOT_FOUND,
            "The page you requested could not be found",
            &nonce.0,
        );
    }
    let tmpl = AdminTunnelsTemplate {
        site_title: site_title.0.clone(),
        logo_url: logo_url(&theme),
        is_admin: is_admin(&identity),
        active_page: "tunnels".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

/// GET /admin/license.html — admin license management page.
pub async fn admin_license_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let tmpl = AdminLicenseTemplate {
        site_title: site_title.0.clone(),
        logo_url: logo_url(&theme),
        is_admin: is_admin(&identity),
        active_page: "license".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

/// GET /admin/branding.html — admin branding page.
pub async fn admin_branding_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let tmpl = AdminBrandingTemplate {
        site_title: site_title.0.clone(),
        logo_url: logo_url(&theme),
        is_admin: is_admin(&identity),
        active_page: "branding".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}
