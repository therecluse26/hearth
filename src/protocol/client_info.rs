//! Client information extraction from HTTP requests.
//!
//! Extracts the client IP address (with trusted proxy support) and parses
//! the `User-Agent` header into a human-readable device label for session
//! metadata display.

use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;

use crate::identity::SessionContext;

/// Extracts the client's IP address from the request.
///
/// If `trusted_proxies` is empty, returns the peer (socket) IP directly —
/// this is the safe default that avoids trusting forged `X-Forwarded-For`
/// headers.
///
/// If `trusted_proxies` is configured, walks the `X-Forwarded-For` header
/// right-to-left and returns the first IP that is NOT in the trusted set.
/// This follows the "rightmost non-trusted" algorithm recommended by OWASP.
pub fn extract_client_ip(
    headers: &HeaderMap,
    peer: SocketAddr,
    trusted_proxies: &[IpAddr],
) -> String {
    if trusted_proxies.is_empty() {
        return peer.ip().to_string();
    }

    // Parse X-Forwarded-For (comma-separated, rightmost = closest proxy)
    let xff = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let ips: Vec<&str> = xff
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    // Walk right-to-left, find first non-trusted IP
    for ip_str in ips.iter().rev() {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            if !trusted_proxies.contains(&ip) {
                return ip.to_string();
            }
        }
    }

    // All IPs in XFF are trusted (or XFF is empty/unparseable) — fall back to peer
    peer.ip().to_string()
}

/// Parses a `User-Agent` string into a human-readable device label.
///
/// Returns `Some("Browser, OS")` on success, or `None` for empty/unrecognizable UAs.
pub fn parse_device_label(ua: Option<&str>) -> Option<String> {
    let ua_str = ua?;
    if ua_str.is_empty() {
        return None;
    }

    let parser = woothee::parser::Parser::new();
    let result = parser.parse(ua_str)?;

    // woothee returns "UNKNOWN" for unrecognized fields
    let browser = if result.name == "UNKNOWN" {
        return None;
    } else {
        result.name
    };

    let os = if result.os == "UNKNOWN" {
        "Unknown OS"
    } else {
        result.os
    };

    Some(format!("{browser}, {os}"))
}

/// Builds a complete [`SessionContext`] from HTTP request metadata.
///
/// Combines IP extraction and UA parsing into a single struct ready for
/// passing to `create_session()`.
pub fn build_session_context(
    headers: &HeaderMap,
    peer: SocketAddr,
    trusted_proxies: &[IpAddr],
) -> SessionContext {
    let ip_address = Some(extract_client_ip(headers, peer, trusted_proxies));

    let ua_raw = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let device_label = parse_device_label(ua_raw.as_deref());

    SessionContext {
        ip_address,
        user_agent_raw: ua_raw,
        device_label,
        satisfies_mfa_via_passkey: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn peer_addr() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 12345))
    }

    // ===== IP extraction tests =====

    #[test]
    fn no_trusted_proxies_returns_peer_ip() {
        let headers = HeaderMap::new();
        let result = extract_client_ip(&headers, peer_addr(), &[]);
        assert_eq!(result, "192.168.1.100");
    }

    #[test]
    fn xff_ignored_when_no_trusted_proxies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("10.0.0.1, 172.16.0.1"),
        );
        let result = extract_client_ip(&headers, peer_addr(), &[]);
        assert_eq!(result, "192.168.1.100");
    }

    #[test]
    fn xff_right_to_left_with_trusted_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.50, 10.0.0.1"),
        );
        let trusted: Vec<IpAddr> = vec!["10.0.0.1".parse().expect("valid IP")];
        let result = extract_client_ip(&headers, peer_addr(), &trusted);
        assert_eq!(result, "203.0.113.50");
    }

    #[test]
    fn all_trusted_fallback_to_peer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("10.0.0.1, 10.0.0.2"),
        );
        let trusted: Vec<IpAddr> = vec![
            "10.0.0.1".parse().expect("valid"),
            "10.0.0.2".parse().expect("valid"),
        ];
        let result = extract_client_ip(&headers, peer_addr(), &trusted);
        assert_eq!(result, "192.168.1.100");
    }

    // ===== UA parsing tests =====

    #[test]
    fn chrome_macos_ua() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        let label = parse_device_label(Some(ua));
        assert!(label.is_some());
        let label = label.expect("should parse");
        assert!(label.contains("Chrome"), "expected Chrome in '{label}'");
        assert!(
            label.contains("Mac") || label.contains("OS X"),
            "expected Mac in '{label}'"
        );
    }

    #[test]
    fn firefox_windows_ua() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0";
        let label = parse_device_label(Some(ua));
        assert!(label.is_some());
        let label = label.expect("should parse");
        assert!(label.contains("Firefox"), "expected Firefox in '{label}'");
        assert!(label.contains("Windows"), "expected Windows in '{label}'");
    }

    #[test]
    fn empty_ua_returns_none() {
        assert_eq!(parse_device_label(Some("")), None);
    }

    #[test]
    fn none_ua_returns_none() {
        assert_eq!(parse_device_label(None), None);
    }

    #[test]
    fn garbage_ua_returns_none() {
        assert_eq!(parse_device_label(Some("not-a-real-user-agent")), None);
    }
}
