#![warn(missing_docs)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]
#![warn(clippy::manual_assert)]
#![warn(clippy::needless_pass_by_value)]

pub mod api;
pub mod audit;
pub mod auth;
pub mod auth_chain;
pub mod auth_provider;
pub mod auth_providers;
pub mod browser;
pub mod config;
pub mod crypto;
pub mod db;
pub mod db_migrate;
pub mod db_pool;
pub mod drive;
pub mod error;
pub mod guacd;
pub mod import;
pub mod metrics;
pub mod migrate;
pub mod oidc;
pub mod password;
pub mod protocol;
pub mod pve;
pub mod rbac;
pub mod recording;
pub mod role;
pub mod session;
pub mod templates;
#[cfg(test)]
pub mod testing;
pub mod totp;
pub mod tunnel;
pub mod vault;
pub mod vdi;
pub mod vsphere;
