//! Small host/port string helpers shared by the tunnel, session, config,
//! and CSV-import surfaces.
//!
//! These split/parse snippets were pasted independently in tunnel.rs,
//! session/manager.rs, session/create.rs, main.rs, config.rs, and
//! api/settings.rs before landing here.

/// Split a `host:port` string into its host part and trailing port text.
///
/// The cut lands on the LAST colon, so a bare IPv6 host without a port
/// (`"::1"`) loses its tail to the port slot, matching the historical
/// `rfind(':')` semantics in force at every adoption site. A bracketed
/// IPv6 endpoint keeps its shape (`"[::1]:22"` → host `"[::1]"`); callers
/// that show the host to users or feed it to TLS strip the brackets
/// separately. Input without a colon is all host, empty port.
pub fn split_host_port(addr: &str) -> (&str, &str) {
    match addr.rfind(':') {
        Some(pos) => (&addr[..pos], &addr[pos + 1..]),
        None => (addr, ""),
    }
}

/// Parse a port string into a `u16`; anything unparsable or out of range
/// yields `None`.
pub fn parse_port(s: &str) -> Option<u16> {
    s.parse::<u16>().ok()
}

/// Does the address end in a numeric port? Accepts `IP:port` and
/// `hostname:port`; the check only reads the text after the last colon.
/// Bracketed IPv6 addresses (`"[::1]:4822"`) parse correctly because the
/// last colon still lands inside the port slot.
pub fn has_valid_trailing_port(addr: &str) -> bool {
    addr.rsplit(':')
        .next()
        .is_some_and(|p| parse_port(p).is_some())
}

/// Parse a host and port from a full URL ("https://host:8006") or a bare
/// authority ("host:3128" / "host"), falling back to `default_port` when the
/// input carries no explicit port. Used to tunnel Proxmox's PVE API and SPICE
/// proxy endpoints through a jump-host chain.
///
/// Errors carry the same wording the session-creation path used when this
/// lived in `session/create.rs`.
pub fn parse_host_port(input: &str, default_port: u16) -> Result<(String, u16), String> {
    let parsed = if input.contains("://") {
        url::Url::parse(input)
    } else {
        url::Url::parse(&format!("tcp://{input}"))
    }
    .map_err(|e| format!("invalid host/URL '{input}': {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("no host in '{input}'"))?
        .to_string();
    let port = parsed.port().unwrap_or(default_port);
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_host_and_port() {
        assert_eq!(split_host_port("example.com:22"), ("example.com", "22"));
        assert_eq!(split_host_port("127.0.0.1:4822"), ("127.0.0.1", "4822"));
    }

    #[test]
    fn split_without_port_is_all_host() {
        assert_eq!(split_host_port("example.com"), ("example.com", ""));
    }

    #[test]
    fn bracketed_ipv6_keeps_host_intact() {
        // The bracketed form is the one IPv6 shape the last-colon cut
        // handles: the port comes after the closing bracket.
        assert_eq!(split_host_port("[::1]:22"), ("[::1]", "22"));
        assert_eq!(
            split_host_port("[2001:db8::1]:4822"),
            ("[2001:db8::1]", "4822")
        );
    }

    #[test]
    fn bare_ipv6_follows_last_colon_semantics() {
        // Bare IPv6 without brackets predates this helper at every
        // adoption site: the cut is the LAST colon, so "::1" is host "::"
        // with port "1". Documented here so nobody mistakes it for a
        // regression; unbracketed IPv6 with an explicit port is ambiguous
        // by construction and every caller already required brackets.
        assert_eq!(split_host_port("::1"), (":", "1"));
    }

    #[test]
    fn parse_port_variants() {
        assert_eq!(parse_port("4822"), Some(4822));
        assert_eq!(parse_port("0"), Some(0));
        assert_eq!(parse_port("65535"), Some(65535));
        assert_eq!(parse_port("65536"), None);
        assert_eq!(parse_port("-1"), None);
        assert_eq!(parse_port("abc"), None);
        assert_eq!(parse_port(""), None);
    }

    #[test]
    fn trailing_port_check() {
        assert!(has_valid_trailing_port("127.0.0.1:4822"));
        assert!(has_valid_trailing_port("[::1]:4822"));
        assert!(!has_valid_trailing_port("host:99999"));
        assert!(!has_valid_trailing_port("host:nonsense"));
    }

    #[test]
    fn parse_host_port_urls_and_authorities() {
        assert_eq!(
            parse_host_port("https://pve.example.com:8006", 443).unwrap(),
            ("pve.example.com".to_string(), 8006)
        );
        assert_eq!(
            parse_host_port("proxy.example.com:3128", 3128).unwrap(),
            ("proxy.example.com".to_string(), 3128)
        );
        assert_eq!(
            parse_host_port("bare-host", 3128).unwrap(),
            ("bare-host".to_string(), 3128)
        );
        assert!(parse_host_port("://bad", 1).is_err());
    }
}
