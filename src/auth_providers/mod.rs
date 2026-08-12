//! Auth provider implementations.
//!
//! Each sub-module implements [`AuthProvider`](crate::auth_provider::AuthProvider)
//! for a specific backend.

pub mod database;
/// LDAP/AD bind + search auth provider.
pub mod ldap;
pub mod radius;
pub mod saml;
pub mod totp;
