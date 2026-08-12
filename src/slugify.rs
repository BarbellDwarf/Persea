//! Friendly-name → stable identifier conversion for address book entries.
//!
//! The connection form asks for ONE friendly name ("Web Server 01"). The
//! stored identifier is the slugified form (`web-server-01`), which is the
//! identity everywhere it matters: URL path segments, Vault keys, RBAC
//! connection ids (`scope/folder/name`), the `UNIQUE(folder_id, name)`
//! constraint, and audit subjects. The friendly text is kept separately as
//! the entry's `display_name`.

/// Derive a stable, path-safe identifier from a friendly name.
///
/// Rules: trim surrounding whitespace; lowercase; spaces → `-`; keep only
/// `[a-z0-9._-]` (everything else is dropped); collapse runs of duplicate
/// separators (`-`, `.`, `_`, spaces) into one; strip leading/trailing
/// separators.
///
/// Examples: `"Web Server 01"` → `"web-server-01"`,
/// `"My  Server!!"` → `"my-server"`, `"ssh_prod-1"` → `"ssh_prod-1"`.
pub fn slugify(name: &str) -> String {
    let mut slug = String::with_capacity(name.len());
    let mut prev_sep = false;
    for c in name.trim().chars() {
        let lower = c.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() {
            slug.push(lower);
            prev_sep = false;
        } else if c.is_whitespace() {
            // Spaces become dashes; duplicate runs collapse into one.
            if !prev_sep && !slug.is_empty() {
                slug.push('-');
            }
            prev_sep = true;
        } else if matches!(lower, '.' | '_' | '-') {
            // Allowed separators pass through, but a run of duplicates
            // collapses to the first one.
            if !prev_sep && !slug.is_empty() {
                slug.push(lower);
            }
            prev_sep = true;
        }
        // Anything else is dropped entirely (no separator is emitted).
    }
    while slug.ends_with(['-', '.', '_']) {
        slug.pop();
    }
    slug
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn friendly_names_become_slugs() {
        assert_eq!(slugify("Web Server 01"), "web-server-01");
        assert_eq!(slugify("My  Server!!"), "my-server");
        assert_eq!(slugify("ssh_prod-1"), "ssh_prod-1");
    }

    #[test]
    fn collapses_duplicate_separator_runs() {
        assert_eq!(slugify("a--b"), "a-b");
        assert_eq!(slugify("a__b"), "a_b");
        assert_eq!(slugify("a  b"), "a-b");
        assert_eq!(slugify("a.-b"), "a.b");
        assert_eq!(slugify("web . server"), "web-server");
    }

    #[test]
    fn strips_leading_and_trailing_separators() {
        assert_eq!(slugify("-web-server-"), "web-server");
        assert_eq!(slugify("  My Server  "), "my-server");
        assert_eq!(slugify("_prod."), "prod");
    }

    #[test]
    fn drops_disallowed_characters() {
        assert_eq!(slugify("Web!!!Server"), "webserver");
        assert_eq!(slugify("Café & Bistro"), "caf-bistro");
        assert_eq!(slugify("Über-01"), "ber-01");
        assert_eq!(slugify("!!!"), "");
        assert_eq!(slugify(""), "");
        assert_eq!(slugify("   "), "");
    }
}
