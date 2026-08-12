/// Account pages and the password change endpoint.
pub mod account;
/// Login, MFA verification, and SAML endpoint handlers.
pub mod auth;
/// Authenticated page handlers: connections, sessions, recordings, and
/// the admin pages.
pub mod pages;
/// RBAC management API: groups, connection permissions, custom roles.
pub mod rbac;
/// First-run setup wizard handlers.
pub mod setup;
/// Jump-host and tunnel management API.
pub mod tunnels;
