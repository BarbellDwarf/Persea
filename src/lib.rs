#![warn(clippy::pedantic)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]
#![allow(missing_docs)]

/// Re-export modules for fuzz targets and testing.
pub mod protocol;
pub mod password;
pub mod crypto;
pub mod audit;
pub mod rbac;
pub mod auth_provider;
pub mod auth_providers;
pub mod auth_chain;
pub mod totp;
pub mod db;
