//! persea: a lightweight Rust replacement for the Apache Guacamole Java
//! webapp.
//!
//! The server proxies the Guacamole protocol over WebSockets between a
//! browser and guacd, and brokers sessions for SSH, RDP, VNC, SPICE,
//! Proxmox VE, VMware vSphere, web browser sessions (headless Chromium on
//! Xvnc), and VDI desktop containers (Docker).

#![warn(missing_docs)]
#![warn(clippy::manual_assert)]
#![warn(clippy::needless_pass_by_value)]
// Deliberate style: unwraps and expects in this codebase are used for
// config parsing, tokio join handles, and other fail-fast sites where
// recovering is not meaningful. Kept visible in review, not fail-on.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// The lints above are deliberate developer visibility aids: they surface
// undocumented public API and unwrap sites during `cargo check`/`cargo test`.
// Release builds (Docker image, `cargo build --release`) do not need ~800
// warnings re-printed on every build, so they are silenced there.
#![cfg_attr(
    not(debug_assertions),
    allow(
        missing_docs,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::manual_assert,
        clippy::needless_pass_by_value
    )
)]

pub mod api;
pub mod audit;
pub mod auth;
pub mod auth_chain;
pub mod auth_provider;
pub mod auth_providers;
pub mod browser;
pub mod config;
/// AES-256-GCM encryption for credentials and secrets at rest.
pub mod crypto;
/// Double-submit cookie CSRF protection middleware and cookie helpers.
pub mod csrf;
pub mod csv_import;
pub mod db;
pub mod db_migrate;
pub mod db_pool;
pub mod drive;
/// Unified application error type with HTTP status mapping and
/// HTML/JSON rendering.
pub mod error;
pub mod guacd;
/// HTTP handlers for pages, the setup wizard, and management APIs. Also
/// compiled into the binary crate via `mod handlers` in main.rs; the lib
/// copy exists so integration tests can exercise the real handlers.
pub mod handlers;
pub mod import;
pub mod metrics;
pub mod migrate;
/// Small host/port string helpers shared by the tunnel, session, config,
/// and CSV-import surfaces.
pub mod net_util;
pub mod oidc;
pub mod password;
pub mod protocol;
pub mod providers_db;
pub mod pve;
pub mod rbac;
pub mod recording;
pub mod role;
/// Session state machine: types, manager, creation, and the guacd
/// handshake.
pub mod session;
pub mod settings_merge;
pub mod slugify;
/// minijinja template rendering and error page helpers.
pub mod templates;
/// CSP nonce carried as a request extension by the security headers
/// middleware; re-exported at the crate root so the lib copy of the
/// handlers (which use `crate::CspNonce`) resolves it.
pub use templates::CspNonce;
#[cfg(test)]
pub mod testing;
pub mod thumbnails;
pub mod totp;
pub mod tunnel;
pub mod updates;
pub mod validation;
pub mod vault;
pub mod vdi;
pub mod vsphere;
