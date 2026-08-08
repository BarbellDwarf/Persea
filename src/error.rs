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

    #[error("validation error: {0}")]
    Validation(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("{0}")]
    Internal(String),
}

impl AppError {
    fn status_for_response(status: StatusCode, message: &str) -> Response {
        let error_code = match status {
            StatusCode::NOT_FOUND => "NOT_FOUND",
            StatusCode::BAD_REQUEST => "VALIDATION_ERROR",
            StatusCode::CONFLICT => "CONFLICT",
            StatusCode::BAD_GATEWAY => "BAD_GATEWAY",
            StatusCode::UNAUTHORIZED => "UNAUTHORIZED",
            StatusCode::FORBIDDEN => "FORBIDDEN",
            StatusCode::SERVICE_UNAVAILABLE => "SERVICE_UNAVAILABLE",
            StatusCode::GATEWAY_TIMEOUT => "GATEWAY_TIMEOUT",
            StatusCode::PAYLOAD_TOO_LARGE => "PAYLOAD_TOO_LARGE",
            StatusCode::INTERNAL_SERVER_ERROR => "INTERNAL_ERROR",
            _ => "INTERNAL_ERROR",
        };
        let body = json!({
            "error": message,
            "code": status.as_u16(),
            "error_code": error_code,
        });
        (status, axum::Json(body)).into_response()
    }

    pub fn internal_response(message: impl Into<String>) -> Response {
        let msg = message.into();
        tracing::error!(error = %msg, "internal error");
        Self::status_for_response(StatusCode::INTERNAL_SERVER_ERROR, &msg)
    }

    pub fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
        let msg = message.into();
        Self::status_for_response(status, &msg)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            // ── User-facing errors: safe to include specific messages ──
            AppError::Session(msg) if msg.contains("not found") => {
                (StatusCode::NOT_FOUND, self.to_string())
            }
            AppError::Session(msg) if msg.contains("validation") => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            AppError::Session(msg) if msg.contains("not active") => {
                (StatusCode::CONFLICT, self.to_string())
            }

            AppError::Vault(msg) if msg.contains("not found") => {
                (StatusCode::NOT_FOUND, self.to_string())
            }
            AppError::Vault(msg) if msg.contains("forbidden") || msg.contains("access denied") => {
                (StatusCode::FORBIDDEN, self.to_string())
            }
            AppError::Vault(msg) if msg.contains("unavailable") => {
                (StatusCode::SERVICE_UNAVAILABLE, self.to_string())
            }
            AppError::Vault(msg) if msg.contains("invalid name") => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }

            AppError::Auth(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::Forbidden(_) => (StatusCode::FORBIDDEN, self.to_string()),
            AppError::Conflict(_) => (StatusCode::CONFLICT, self.to_string()),
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::Validation(_) => (StatusCode::BAD_REQUEST, self.to_string()),

            AppError::Vdi(msg) if msg.contains("not enabled") => {
                (StatusCode::SERVICE_UNAVAILABLE, self.to_string())
            }
            AppError::Vdi(msg) if msg.contains("timeout") => {
                (StatusCode::GATEWAY_TIMEOUT, self.to_string())
            }

            // ── Infrastructure errors: sanitize to avoid leaking paths / hostnames ──
            AppError::Session(_) => {
                tracing::error!(error = %self, "session error (sanitized in response)");
                (StatusCode::BAD_GATEWAY, "session error".to_string())
            }
            AppError::Guacd(_) => {
                tracing::error!(error = %self, "guacd error (sanitized in response)");
                (StatusCode::BAD_GATEWAY, "guacd error".to_string())
            }
            AppError::Vault(_) => {
                tracing::error!(error = %self, "vault error (sanitized in response)");
                (StatusCode::BAD_GATEWAY, "vault error".to_string())
            }
            AppError::Browser(_) => {
                tracing::error!(error = %self, "browser error (sanitized in response)");
                (StatusCode::BAD_GATEWAY, "browser error".to_string())
            }
            AppError::Vdi(_) => {
                tracing::error!(error = %self, "vdi error (sanitized in response)");
                (StatusCode::BAD_GATEWAY, "vdi error".to_string())
            }
            AppError::Tunnel(_) => {
                tracing::error!(error = %self, "tunnel error (sanitized in response)");
                (StatusCode::BAD_GATEWAY, "tunnel error".to_string())
            }
            AppError::Protocol(_) => {
                tracing::error!(error = %self, "protocol error (sanitized in response)");
                (StatusCode::BAD_GATEWAY, "protocol error".to_string())
            }
            AppError::Drive(_) => {
                tracing::error!(error = %self, "drive error (sanitized in response)");
                (StatusCode::INTERNAL_SERVER_ERROR, "drive error".to_string())
            }
            AppError::Pve(_) => {
                tracing::error!(error = %self, "pve error (sanitized in response)");
                (StatusCode::BAD_GATEWAY, "pve error".to_string())
            }
            AppError::Vsphere(_) => {
                tracing::error!(error = %self, "vsphere error (sanitized in response)");
                (StatusCode::BAD_GATEWAY, "vsphere error".to_string())
            }
            AppError::Internal(msg) => {
                tracing::error!(internal_error = %msg, "internal error (sanitized in response)");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal error occurred".to_string(),
                )
            }
        };

        tracing::error!(status = %status, error = %message, "request error");
        Self::status_for_response(status, &message)
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

impl From<tokio::task::JoinError> for AppError {
    fn from(e: tokio::task::JoinError) -> Self {
        tracing::error!(error = %e, "spawn_blocking task panicked or was cancelled");
        AppError::Internal(format!("internal task error: {e}"))
    }
}

impl From<String> for AppError {
    fn from(s: String) -> Self {
        AppError::Internal(s)
    }
}
