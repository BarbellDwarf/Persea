//! Auth provider implementations.
//!
//! Each sub-module implements [`AuthProvider`](crate::auth_provider::AuthProvider)
//! for a specific backend.

pub mod database;
pub mod ldap;
pub mod radius;
pub mod saml;
pub mod totp;
