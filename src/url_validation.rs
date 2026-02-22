// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Federation URL Validation (Tracker #133)
//!
//! Validates peer relay URLs to prevent SSRF attacks via gossip-injected
//! URLs. Rejects URLs that point to private IP ranges, loopback, link-local,
//! multicast, and unspecified addresses.
//!
//! ## Limitations
//!
//! Hostname-based URLs are only validated for scheme correctness at
//! registration time. DNS rebinding attacks (where a public hostname
//! resolves to a private IP) require connection-time validation after
//! DNS resolution — use [`validate_resolved_ip`] in the connection path.

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};

/// Errors from federation URL validation.
#[derive(Debug, PartialEq)]
pub enum SsrfError {
    InvalidUrl(String),
    InvalidScheme(String),
    PrivateIp(IpAddr),
    LoopbackIp(IpAddr),
    LinkLocalIp(IpAddr),
    MulticastIp(IpAddr),
    UnspecifiedIp(IpAddr),
}

impl fmt::Display for SsrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SsrfError::InvalidUrl(msg) => write!(f, "invalid federation URL: {}", msg),
            SsrfError::InvalidScheme(s) => {
                write!(f, "invalid scheme: {} (expected ws:// or wss://)", s)
            }
            SsrfError::PrivateIp(ip) => write!(f, "blocked private IP: {}", ip),
            SsrfError::LoopbackIp(ip) => write!(f, "blocked loopback IP: {}", ip),
            SsrfError::LinkLocalIp(ip) => write!(f, "blocked link-local IP: {}", ip),
            SsrfError::MulticastIp(ip) => write!(f, "blocked multicast IP: {}", ip),
            SsrfError::UnspecifiedIp(ip) => write!(f, "blocked unspecified IP: {}", ip),
        }
    }
}

/// Extracts the host (without port) from a WebSocket URL.
fn extract_host(url: &str) -> Result<&str, SsrfError> {
    let stripped = url
        .strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))
        .ok_or_else(|| {
            let scheme = url.split("://").next().unwrap_or("(none)");
            SsrfError::InvalidScheme(scheme.to_string())
        })?;

    if stripped.is_empty() {
        return Err(SsrfError::InvalidUrl("empty host".to_string()));
    }

    let authority = stripped.split('/').next().unwrap_or(stripped);

    // Handle IPv6 bracket notation: [::1]:8080
    if authority.starts_with('[') {
        let end = authority
            .find(']')
            .ok_or_else(|| SsrfError::InvalidUrl("unclosed IPv6 bracket".to_string()))?;
        return Ok(&authority[1..end]);
    }

    // host:port or just host
    if let Some((h, _)) = authority.rsplit_once(':') {
        Ok(h)
    } else {
        Ok(authority)
    }
}

/// Returns true if an IPv6 address is link-local (fe80::/10).
fn is_ipv6_link_local(v6: &Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}

/// Checks if an IP address is in a blocked range for federation connections.
fn check_blocked_ip(ip: IpAddr) -> Result<(), SsrfError> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                Err(SsrfError::LoopbackIp(ip))
            } else if v4.is_private() {
                Err(SsrfError::PrivateIp(ip))
            } else if v4.is_link_local() {
                Err(SsrfError::LinkLocalIp(ip))
            } else if v4.is_multicast() {
                Err(SsrfError::MulticastIp(ip))
            } else if v4.is_unspecified() {
                Err(SsrfError::UnspecifiedIp(ip))
            } else {
                Ok(())
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                Err(SsrfError::LoopbackIp(ip))
            } else if is_ipv6_link_local(&v6) {
                Err(SsrfError::LinkLocalIp(ip))
            } else if v6.is_multicast() {
                Err(SsrfError::MulticastIp(ip))
            } else if v6.is_unspecified() {
                Err(SsrfError::UnspecifiedIp(ip))
            } else if let Some(v4) = v6.to_ipv4_mapped() {
                // Check IPv4-mapped IPv6 addresses (::ffff:a.b.c.d)
                check_blocked_ip(IpAddr::V4(v4))
            } else {
                Ok(())
            }
        }
    }
}

/// Validates a federation peer URL against SSRF blocklists.
///
/// Checks:
/// 1. URL scheme is `ws://` or `wss://`
/// 2. Host is not empty
/// 3. If host is an IP literal, it is not in a blocked range
///
/// Hostnames pass this check — use [`validate_resolved_ip`] after
/// DNS resolution to catch DNS rebinding.
pub fn validate_federation_url(url: &str) -> Result<(), SsrfError> {
    let host = extract_host(url)?;

    if let Ok(ip) = host.parse::<IpAddr>() {
        check_blocked_ip(ip)?;
    }
    // Hostnames pass — validated at connection time after resolution.

    Ok(())
}

/// Validates a resolved IP address before establishing a connection.
///
/// Call this after DNS resolution and before TCP connect to prevent
/// DNS rebinding attacks where a hostname resolves to a private IP.
pub fn validate_resolved_ip(ip: IpAddr) -> Result<(), SsrfError> {
    check_blocked_ip(ip)
}

/// Resolves a host:port pair and validates all resolved IPs against the SSRF blocklist.
///
/// Returns the first valid `SocketAddr` or an error if:
/// - DNS resolution fails
/// - All resolved addresses are in blocked ranges
///
/// This prevents DNS rebinding attacks where a hostname initially resolves
/// to a public IP (passing URL validation) but later resolves to a private IP.
pub async fn resolve_and_validate(
    host: &str,
    port: u16,
) -> Result<std::net::SocketAddr, SsrfError> {
    let addr_str = format!("{}:{}", host, port);
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(&addr_str)
        .await
        .map_err(|e| SsrfError::InvalidUrl(format!("DNS resolution failed for {}: {}", host, e)))?
        .collect();

    if addrs.is_empty() {
        return Err(SsrfError::InvalidUrl(format!(
            "DNS resolution returned no addresses for {}",
            host
        )));
    }

    // Validate ALL resolved addresses — reject if any resolve to blocked ranges
    for addr in &addrs {
        check_blocked_ip(addr.ip())?;
    }

    // Return first address (all are validated)
    Ok(addrs[0])
}

// INLINE_TEST_REQUIRED: SSRF validation tests must access private functions (check_blocked_ip, extract_host)
#[cfg(test)]
mod tests {
    use super::*;

    // === Scheme validation ===

    #[test]
    fn test_rejects_http_scheme() {
        let result = validate_federation_url("http://example.com");
        assert!(matches!(result, Err(SsrfError::InvalidScheme(_))));
    }

    #[test]
    fn test_rejects_https_scheme() {
        let result = validate_federation_url("https://example.com");
        assert!(matches!(result, Err(SsrfError::InvalidScheme(_))));
    }

    #[test]
    fn test_rejects_ftp_scheme() {
        let result = validate_federation_url("ftp://example.com");
        assert!(matches!(result, Err(SsrfError::InvalidScheme(_))));
    }

    #[test]
    fn test_rejects_no_scheme() {
        let result = validate_federation_url("example.com:8080");
        assert!(matches!(result, Err(SsrfError::InvalidScheme(_))));
    }

    #[test]
    fn test_accepts_ws_scheme() {
        assert!(validate_federation_url("ws://example.com:8080").is_ok());
    }

    #[test]
    fn test_accepts_wss_scheme() {
        assert!(validate_federation_url("wss://example.com").is_ok());
    }

    // === Public IPs (should pass) ===

    #[test]
    fn test_accepts_public_ipv4() {
        assert!(validate_federation_url("wss://8.8.8.8:443").is_ok());
    }

    #[test]
    fn test_accepts_public_ipv4_no_port() {
        assert!(validate_federation_url("wss://203.0.113.1").is_ok());
    }

    #[test]
    fn test_accepts_hostname() {
        assert!(validate_federation_url("wss://relay.example.com:443").is_ok());
    }

    #[test]
    fn test_accepts_hostname_with_path() {
        assert!(validate_federation_url("wss://relay.example.com/federation").is_ok());
    }

    // === Loopback (blocked) ===

    #[test]
    fn test_blocks_loopback_127_0_0_1() {
        let result = validate_federation_url("ws://127.0.0.1:8080");
        assert!(matches!(result, Err(SsrfError::LoopbackIp(_))));
    }

    #[test]
    fn test_blocks_loopback_127_x() {
        let result = validate_federation_url("ws://127.255.0.1:8080");
        assert!(matches!(result, Err(SsrfError::LoopbackIp(_))));
    }

    #[test]
    fn test_blocks_ipv6_loopback() {
        let result = validate_federation_url("ws://[::1]:8080");
        assert!(matches!(result, Err(SsrfError::LoopbackIp(_))));
    }

    // === Private ranges (blocked) ===

    #[test]
    fn test_blocks_10_network() {
        let result = validate_federation_url("ws://10.0.0.1:8080");
        assert!(matches!(result, Err(SsrfError::PrivateIp(_))));
    }

    #[test]
    fn test_blocks_172_16_network() {
        let result = validate_federation_url("ws://172.16.0.1:8080");
        assert!(matches!(result, Err(SsrfError::PrivateIp(_))));
    }

    #[test]
    fn test_blocks_172_31_network() {
        let result = validate_federation_url("ws://172.31.255.255:8080");
        assert!(matches!(result, Err(SsrfError::PrivateIp(_))));
    }

    #[test]
    fn test_allows_172_32_network() {
        // 172.32.0.0 is NOT in the 172.16.0.0/12 private range
        assert!(validate_federation_url("ws://172.32.0.1:8080").is_ok());
    }

    #[test]
    fn test_blocks_192_168_network() {
        let result = validate_federation_url("ws://192.168.1.1:8080");
        assert!(matches!(result, Err(SsrfError::PrivateIp(_))));
    }

    // === Link-local (blocked) ===

    #[test]
    fn test_blocks_ipv4_link_local() {
        let result = validate_federation_url("ws://169.254.1.1:8080");
        assert!(matches!(result, Err(SsrfError::LinkLocalIp(_))));
    }

    #[test]
    fn test_blocks_ipv6_link_local() {
        let result = validate_federation_url("ws://[fe80::1]:8080");
        assert!(matches!(result, Err(SsrfError::LinkLocalIp(_))));
    }

    // === Multicast (blocked) ===

    #[test]
    fn test_blocks_multicast() {
        let result = validate_federation_url("ws://224.0.0.1:8080");
        assert!(matches!(result, Err(SsrfError::MulticastIp(_))));
    }

    #[test]
    fn test_blocks_ipv6_multicast() {
        let result = validate_federation_url("ws://[ff02::1]:8080");
        assert!(matches!(result, Err(SsrfError::MulticastIp(_))));
    }

    // === Unspecified (blocked) ===

    #[test]
    fn test_blocks_unspecified_ipv4() {
        let result = validate_federation_url("ws://0.0.0.0:8080");
        assert!(matches!(result, Err(SsrfError::UnspecifiedIp(_))));
    }

    #[test]
    fn test_blocks_unspecified_ipv6() {
        let result = validate_federation_url("ws://[::]:8080");
        assert!(matches!(result, Err(SsrfError::UnspecifiedIp(_))));
    }

    // === IPv4-mapped IPv6 (blocked if inner IP is blocked) ===

    #[test]
    fn test_blocks_ipv4_mapped_loopback() {
        let result = validate_federation_url("ws://[::ffff:127.0.0.1]:8080");
        assert!(matches!(result, Err(SsrfError::LoopbackIp(_))));
    }

    #[test]
    fn test_blocks_ipv4_mapped_private() {
        let result = validate_federation_url("ws://[::ffff:10.0.0.1]:8080");
        assert!(matches!(result, Err(SsrfError::PrivateIp(_))));
    }

    #[test]
    fn test_accepts_ipv4_mapped_public() {
        assert!(validate_federation_url("ws://[::ffff:8.8.8.8]:8080").is_ok());
    }

    // === validate_resolved_ip ===

    #[test]
    fn test_validate_resolved_ip_public() {
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        assert!(validate_resolved_ip(ip).is_ok());
    }

    #[test]
    fn test_validate_resolved_ip_private() {
        let ip: IpAddr = "192.168.0.1".parse().unwrap();
        assert!(matches!(
            validate_resolved_ip(ip),
            Err(SsrfError::PrivateIp(_))
        ));
    }

    #[test]
    fn test_validate_resolved_ip_loopback() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(matches!(
            validate_resolved_ip(ip),
            Err(SsrfError::LoopbackIp(_))
        ));
    }

    // === Edge cases ===

    #[test]
    fn test_empty_host_rejected() {
        let result = validate_federation_url("ws://");
        assert!(matches!(result, Err(SsrfError::InvalidUrl(_))));
    }

    #[test]
    fn test_display_impl() {
        let err = SsrfError::LoopbackIp("127.0.0.1".parse().unwrap());
        assert!(err.to_string().contains("loopback"));
        assert!(err.to_string().contains("127.0.0.1"));
    }

    // === resolve_and_validate ===

    #[tokio::test]
    async fn test_resolve_and_validate_blocks_loopback_ip_literal() {
        let result = resolve_and_validate("127.0.0.1", 8080).await;
        assert!(
            matches!(result, Err(SsrfError::LoopbackIp(_))),
            "Expected loopback block, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_resolve_and_validate_blocks_private_ip_literal() {
        let result = resolve_and_validate("10.0.0.1", 8080).await;
        assert!(
            matches!(result, Err(SsrfError::PrivateIp(_))),
            "Expected private block, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_resolve_and_validate_blocks_192_168_ip_literal() {
        let result = resolve_and_validate("192.168.1.1", 8080).await;
        assert!(
            matches!(result, Err(SsrfError::PrivateIp(_))),
            "Expected private block, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_resolve_and_validate_blocks_link_local() {
        let result = resolve_and_validate("169.254.1.1", 8080).await;
        assert!(
            matches!(result, Err(SsrfError::LinkLocalIp(_))),
            "Expected link-local block, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_resolve_and_validate_invalid_host() {
        let result = resolve_and_validate("", 8080).await;
        assert!(
            matches!(result, Err(SsrfError::InvalidUrl(_))),
            "Expected DNS error, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_resolve_and_validate_localhost_hostname() {
        // "localhost" resolves to 127.0.0.1 — should be blocked
        let result = resolve_and_validate("localhost", 8080).await;
        assert!(
            matches!(result, Err(SsrfError::LoopbackIp(_))),
            "Expected loopback block for localhost, got: {:?}",
            result
        );
    }
}
