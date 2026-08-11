use axum::response::{IntoResponse, Response};
use axum::Extension;

use crate::api::SiteTitle;
use crate::auth::AuthIdentity;
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

/// GET /connections.html — connections page.
pub async fn connections_page(
    Extension(site_title): Extension<SiteTitle>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let tmpl = ConnectionsPageTemplate {
        site_title: site_title.0.clone(),
        logo_url: String::new(),
        is_admin: is_admin(&identity),
        active_page: "connections".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

/// GET /sessions.html — sessions page.
pub async fn sessions_page(
    Extension(site_title): Extension<SiteTitle>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let tmpl = SessionsPageTemplate {
        site_title: site_title.0.clone(),
        logo_url: String::new(),
        is_admin: is_admin(&identity),
        active_page: "sessions".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

/// GET /recordings.html — recordings page.
pub async fn recordings_page(
    Extension(site_title): Extension<SiteTitle>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let tmpl = RecordingsPageTemplate {
        site_title: site_title.0.clone(),
        logo_url: String::new(),
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
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let tmpl = AdminUsersTemplate {
        site_title: site_title.0.clone(),
        logo_url: String::new(),
        is_admin: is_admin(&identity),
        active_page: "users".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

/// GET /admin/auth.html — admin auth providers page.
pub async fn admin_auth_page(
    Extension(site_title): Extension<SiteTitle>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let tmpl = AdminAuthTemplate {
        site_title: site_title.0.clone(),
        logo_url: String::new(),
        is_admin: is_admin(&identity),
        active_page: "auth".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

/// GET /admin/groups.html — admin groups page.
pub async fn admin_groups_page(
    Extension(site_title): Extension<SiteTitle>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let tmpl = AdminGroupsTemplate {
        site_title: site_title.0.clone(),
        logo_url: String::new(),
        is_admin: is_admin(&identity),
        active_page: "groups".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

/// GET /admin/audit.html — admin audit log page.
pub async fn admin_audit_page(
    Extension(site_title): Extension<SiteTitle>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let tmpl = AdminAuditTemplate {
        site_title: site_title.0.clone(),
        logo_url: String::new(),
        is_admin: is_admin(&identity),
        active_page: "audit".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

/// GET /admin/settings.html — admin settings page.
pub async fn admin_settings_page(
    Extension(site_title): Extension<SiteTitle>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let tmpl = AdminSettingsTemplate {
        site_title: site_title.0.clone(),
        logo_url: String::new(),
        is_admin: is_admin(&identity),
        active_page: "settings".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

/// GET /admin/reports.html — admin reports page.
pub async fn admin_reports_page(
    Extension(site_title): Extension<SiteTitle>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let tmpl = AdminReportsTemplate {
        site_title: site_title.0.clone(),
        logo_url: String::new(),
        is_admin: is_admin(&identity),
        active_page: "reports".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

/// GET /admin/tunnels.html — admin SSH tunnels management page.
pub async fn admin_tunnels_page(
    Extension(site_title): Extension<SiteTitle>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let tmpl = AdminTunnelsTemplate {
        site_title: site_title.0.clone(),
        logo_url: String::new(),
        is_admin: is_admin(&identity),
        active_page: "tunnels".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

/// GET /admin/license.html — admin license management page.
pub async fn admin_license_page(
    Extension(site_title): Extension<SiteTitle>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let tmpl = AdminLicenseTemplate {
        site_title: site_title.0.clone(),
        logo_url: String::new(),
        is_admin: is_admin(&identity),
        active_page: "license".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}

/// GET /admin/branding.html — admin branding page.
pub async fn admin_branding_page(
    Extension(site_title): Extension<SiteTitle>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let tmpl = AdminBrandingTemplate {
        site_title: site_title.0.clone(),
        logo_url: String::new(),
        is_admin: is_admin(&identity),
        active_page: "branding".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    tmpl.into_response()
}
