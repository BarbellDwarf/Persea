use axum::response::{IntoResponse, Response};
use axum::Extension;

use crate::api::{SiteTitle, ThemeData};
use crate::auth::AuthIdentity;
use crate::templates;
use crate::CspNonce;

/// Determine if the current user has admin role.
fn is_admin(identity: &Option<Extension<AuthIdentity>>) -> bool {
    identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
}

/// Branding logo URL resolved from the startup ThemeData (config + DB
/// settings overlay); empty string renders the sidebar placeholder.
fn logo_url(theme: &ThemeData) -> String {
    theme.logo_url.clone().unwrap_or_default()
}

/// GET /account/profile.html
pub async fn profile_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    templates::ProfileTemplate {
        site_title: site_title.0.clone(),
        logo_url: logo_url(&theme),
        is_admin: is_admin(&identity),
        active_page: "profile".to_string(),
        csp_nonce: nonce.0,
    }
    .into_response()
}

/// GET /account/tokens.html
pub async fn tokens_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    templates::AccountTokensTemplate {
        site_title: site_title.0.clone(),
        logo_url: logo_url(&theme),
        is_admin: is_admin(&identity),
        active_page: "tokens".to_string(),
        csp_nonce: nonce.0,
    }
    .into_response()
}

/// GET /account/totp.html
pub async fn totp_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    templates::AccountTotpTemplate {
        site_title: site_title.0.clone(),
        logo_url: logo_url(&theme),
        is_admin: is_admin(&identity),
        active_page: "totp".to_string(),
        csp_nonce: nonce.0,
    }
    .into_response()
}

/// GET /docs
pub async fn docs_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    templates::DocsTemplate {
        site_title: site_title.0.clone(),
        logo_url: logo_url(&theme),
        is_admin: is_admin(&identity),
        active_page: "docs".to_string(),
        csp_nonce: nonce.0,
    }
    .into_response()
}
