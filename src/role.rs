//! System role definitions and role-level comparison.

use std::str::FromStr;

/// All valid role names.
pub const VALID_ROLES: &[&str] = &["admin", "poweruser", "operator", "viewer"];

/// Map role names to numeric levels for comparison.
pub fn role_level(role: &str) -> u8 {
    Role::from_str(role).map_or(0, |r| r.level())
}

/// Check if a role string is a valid role name.
pub fn is_valid_role(role: &str) -> bool {
    VALID_ROLES.contains(&role)
}

/// A system role with a fixed hierarchy: admin > poweruser > operator > viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Admin,
    PowerUser,
    Operator,
    Viewer,
}

impl Role {
    /// Numeric level for comparison (higher = more privilege).
    pub fn level(&self) -> u8 {
        match self {
            Role::Admin => 4,
            Role::PowerUser => 3,
            Role::Operator => 2,
            Role::Viewer => 1,
        }
    }

    /// Check if a string is a valid role name.
    pub fn is_valid(s: &str) -> bool {
        Self::from_str(s).is_ok()
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Admin => write!(f, "admin"),
            Role::PowerUser => write!(f, "poweruser"),
            Role::Operator => write!(f, "operator"),
            Role::Viewer => write!(f, "viewer"),
        }
    }
}

impl std::str::FromStr for Role {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "admin" => Ok(Role::Admin),
            "poweruser" => Ok(Role::PowerUser),
            "operator" => Ok(Role::Operator),
            "viewer" => Ok(Role::Viewer),
            _ => Err(format!("unknown role: {s}")),
        }
    }
}
