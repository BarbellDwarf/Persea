use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Per-request context for error rendering, captured by the error middleware
/// (see `error_pages` in main.rs) so `AppError::into_response` can pick
/// between the styled HTML error page and JSON without request access.
#[derive(Clone, Debug)]
pub struct ErrorContext {
    /// Whether the client wants an HTML error page (browser) vs JSON (API).
    pub wants_html: bool,
    /// CSP nonce for the rendered page (empty when unavailable).
    pub csp_nonce: String,
}

tokio::task_local! {
    static ERROR_CONTEXT: ErrorContext;
}

/// Run `future` inside the given error context. Called by the error
/// middleware; the context stays visible to every `IntoResponse` that runs
/// inside the request, even across awaits.
pub async fn with_error_context(
    ctx: ErrorContext,
    future: impl std::future::Future<Output = Response>,
) -> Response {
    ERROR_CONTEXT.scope(ctx, future).await
}

/// The error context for the current request, when the error middleware ran.
fn current_error_context() -> Option<ErrorContext> {
    ERROR_CONTEXT.try_with(|c| c.clone()).ok()
}

/// Unified application error type used across handlers and API code.
///
/// Module errors (session, guacd, vault, auth, browser, vdi, tunnel,
/// protocol, drive, pve, vsphere) convert into this type via `From`
/// impls, and `IntoResponse` maps each variant to an HTTP status.
/// Variants whose messages are safe to expose keep their detail;
/// infrastructure variants are logged in full and sanitized in the
/// response body.
#[derive(Debug, thiserror::Error)]
#[must_use]
pub enum AppError {
    /// Session lookup, creation, or lifecycle failure. Messages containing
    /// "not found", "validation", or "not active" map to 404, 400, or 409;
    /// the rest are sanitized to a 502 response.
    #[error("session error: {0}")]
    Session(String),

    /// guacd connection or handshake failure. The message stays
    /// server-side; clients get a generic 502.
    #[error("guacd error: {0}")]
    Guacd(String),

    /// Vault/OpenBao operation failure. "not found", "forbidden",
    /// "unavailable", and "invalid name" messages map to 404, 403, 503,
    /// or 400; the rest are sanitized to 502.
    #[error("vault error: {0}")]
    Vault(String),

    /// Authentication failure; always a 401 with the message shown.
    #[error("auth error: {0}")]
    Auth(String),

    /// Authorization failure; always a 403 with the message shown.
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// State conflict, e.g. creating something that already exists;
    /// always a 409 with the message shown.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Xvnc/Chromium browser-session failure; sanitized to 502.
    #[error("browser error: {0}")]
    Browser(String),

    /// VDI container failure. "not enabled" and "timeout" messages map to
    /// 503 and 504; the rest are sanitized to 502.
    #[error("vdi error: {0}")]
    Vdi(String),

    /// SSH tunnel (jump host) failure; sanitized to 502.
    #[error("tunnel error: {0}")]
    Tunnel(String),

    /// Guacamole wire protocol parse or encode failure; sanitized to 502.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// LUKS drive or file-transfer failure; sanitized to 500.
    #[error("drive error: {0}")]
    Drive(String),

    /// Proxmox VE API failure; sanitized to 502 so tickets never reach
    /// the client.
    #[error("pve error: {0}")]
    Pve(String),

    /// VMware vSphere API failure; sanitized to 502.
    #[error("vsphere error: {0}")]
    Vsphere(String),

    /// Client input failed validation; always a 400 with the message shown.
    #[error("validation error: {0}")]
    Validation(String),

    /// The requested resource does not exist; always a 404 with the
    /// message shown.
    #[error("not found: {0}")]
    NotFound(String),

    /// Unexpected internal failure; always a 500 with a generic message.
    #[error("{0}")]
    Internal(String),
}

impl AppError {
    fn status_for_response(status: StatusCode, message: &str) -> Response {
        // Browser requests (Accept: text/html) get the styled error page;
        // API and unknown clients keep the JSON error body.
        if let Some(ctx) = current_error_context() {
            if ctx.wants_html {
                return crate::templates::render_error_page(status, message, &ctx.csp_nonce);
            }
        }
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

    /// Render a 500 response for an unexpected internal error, logging
    /// the full message server-side. Use this when a handler must respond
    /// inline; otherwise return a typed `Err` and let `?` convert it.
    pub fn internal_response(message: impl Into<String>) -> Response {
        let msg = message.into();
        tracing::error!(error = %msg, "internal error");
        Self::status_for_response(StatusCode::INTERNAL_SERVER_ERROR, &msg)
    }

    /// Render an error response with an explicit status and message.
    ///
    /// The message goes into the response body verbatim, so only pass
    /// content that is safe to expose to the client.
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
            AppError::Session(_)
            | AppError::Guacd(_)
            | AppError::Vault(_)
            | AppError::Browser(_)
            | AppError::Vdi(_)
            | AppError::Tunnel(_)
            | AppError::Protocol(_)
            | AppError::Pve(_)
            | AppError::Vsphere(_) => {
                tracing::error!(error = %self, "infrastructure error (sanitized in response)");
                (StatusCode::BAD_GATEWAY, "infrastructure error".to_string())
            }
            AppError::Drive(_) => {
                tracing::error!(error = %self, "drive error (sanitized in response)");
                (StatusCode::INTERNAL_SERVER_ERROR, "drive error".to_string())
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
