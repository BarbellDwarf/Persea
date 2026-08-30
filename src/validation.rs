//! Small field validators shared across API handlers.

use crate::error::AppError;

/// Validate an optional user-supplied email address.
///
/// Accepts `None` for "no email given". A provided value must be
/// non-empty after trimming, contain an `@`, and carry no whitespace;
/// anything else is an [`AppError::Validation`] (an empty trimmed value
/// is rejected, matching the original inline validators). The check
/// mirrors the inline validators this replaces in the user create/update
/// and profile handlers: shape checks only, no deliverability promise.
pub fn validate_email(email: Option<&str>) -> Result<Option<String>, AppError> {
    let Some(value) = email else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() || !trimmed.contains('@') || trimmed.chars().any(char::is_whitespace) {
        return Err(AppError::Validation("invalid email address".into()));
    }
    Ok(Some(trimmed.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_addresses() {
        assert_eq!(
            validate_email(Some("user@example.com")).unwrap().as_deref(),
            Some("user@example.com")
        );
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(
            validate_email(Some("  user@example.com ")).unwrap(),
            Some("user@example.com".to_string())
        );
    }

    #[test]
    fn empty_string_rejected() {
        // An explicitly empty email is a validation error, exactly as the
        // original inline validators treated it; only `None` clears.
        assert!(validate_email(Some("   ")).is_err());
        assert_eq!(validate_email(None).unwrap(), None);
    }

    #[test]
    fn requires_an_at_sign() {
        assert!(validate_email(Some("no-at-sign")).is_err());
    }

    #[test]
    fn rejects_inner_whitespace() {
        assert!(validate_email(Some("user name@example.com")).is_err());
        assert!(validate_email(Some("user@example .com")).is_err());
    }
}
