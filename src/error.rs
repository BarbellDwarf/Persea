use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
#[must_use]
pub enum AppError {
    #[error("session error: {0}")]
    Session(String),

    #[error("guacd error: {0}")]
    Guacd(String),

    #[error("vault error: {0}")]
    Vault(String),

    #[error("auth error: {0}")]
    Auth(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("browser error: {0}")]
    Browser(String),

    #[error("vdi error: {0}")]
    Vdi(String),

    #[error("tunnel error: {0}")]
    Tunnel(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("drive error: {0}")]
    Drive(String),

    #[error("pve error: {0}")]
    Pve(String),

    #[error("vsphere error: {0}")]
    Vsphere(String),

    #[error("{0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Session(msg) if msg.contains("not found") => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::Session(msg) if msg.contains("validation") => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::Session(msg) if msg.contains("not active") => (StatusCode::CONFLICT, self.to_string()),
            AppError::Session(_) => (StatusCode::BAD_GATEWAY, self.to_string()),

            AppError::Guacd(_) => (StatusCode::BAD_GATEWAY, self.to_string()),

            AppError::Vault(msg) if msg.contains("not found") => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::Vault(msg) if msg.contains("forbidden") || msg.contains("access denied") => (StatusCode::FORBIDDEN, self.to_string()),
            AppError::Vault(msg) if msg.contains("unavailable") => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            AppError::Vault(msg) if msg.contains("invalid name") => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::Vault(_) => (StatusCode::BAD_GATEWAY, self.to_string()),

            AppError::Auth(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::Forbidden(_) => (StatusCode::FORBIDDEN, self.to_string()),
            AppError::Conflict(_) => (StatusCode::CONFLICT, self.to_string()),
            AppError::Browser(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            AppError::Vdi(msg) if msg.contains("not enabled") => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            AppError::Vdi(msg) if msg.contains("timeout") => (StatusCode::GATEWAY_TIMEOUT, self.to_string()),
            AppError::Vdi(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            AppError::Tunnel(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            AppError::Protocol(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            AppError::Drive(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::Pve(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            AppError::Vsphere(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        let body = json!({ "error": message });
        (status, axum::Json(body)).into_response()
    }
}

// ── From impls for module error types ──

impl From<crate::session::SessionError> for AppError {
    fn from(e: crate::session::SessionError) -> Self {
        AppError::Session(e.to_string())
    }
}

impl From<crate::guacd::GuacdError> for AppError {
    fn from(e: crate::guacd::GuacdError) -> Self {
        AppError::Guacd(e.to_string())
    }
}

impl From<crate::vault::VaultError> for AppError {
    fn from(e: crate::vault::VaultError) -> Self {
        AppError::Vault(e.to_string())
    }
}

impl From<crate::db::AuthError> for AppError {
    fn from(e: crate::db::AuthError) -> Self {
        AppError::Auth(e.to_string())
    }
}

impl From<crate::browser::BrowserError> for AppError {
    fn from(e: crate::browser::BrowserError) -> Self {
        AppError::Browser(e.to_string())
    }
}

impl From<crate::vdi::VdiError> for AppError {
    fn from(e: crate::vdi::VdiError) -> Self {
        AppError::Vdi(e.to_string())
    }
}

impl From<crate::tunnel::TunnelError> for AppError {
    fn from(e: crate::tunnel::TunnelError) -> Self {
        AppError::Tunnel(e.to_string())
    }
}

impl From<crate::protocol::ParseError> for AppError {
    fn from(e: crate::protocol::ParseError) -> Self {
        AppError::Protocol(e.to_string())
    }
}

impl From<crate::drive::DriveError> for AppError {
    fn from(e: crate::drive::DriveError) -> Self {
        AppError::Drive(e.to_string())
    }
}

impl From<crate::pve::PveError> for AppError {
    fn from(e: crate::pve::PveError) -> Self {
        AppError::Pve(e.to_string())
    }
}

impl From<crate::vsphere::VsphereError> for AppError {
    fn from(e: crate::vsphere::VsphereError) -> Self {
        AppError::Vsphere(e.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::Internal(format!("JSON error: {e}"))
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        AppError::Internal(format!("database error: {e}"))
    }
}
