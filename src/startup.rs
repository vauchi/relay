// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Decisions the relay makes while starting, as functions of their inputs.
//!
//! `main` reads the environment and acts on the answers; nothing here
//! touches the environment, the clock or the network
//! (relay-pfc-violations R1).

use std::net::SocketAddr;

/// Whether an environment flag is switched on: exactly `"true"` or `"1"`.
pub fn env_flag_is_on(value: Option<&str>) -> bool {
    matches!(value, Some("true" | "1"))
}

/// Whether `RELAY_LOG_FORMAT` asks for JSON log lines.
pub fn wants_json_logs(log_format: &str) -> bool {
    log_format == "json"
}

/// Whether the relay may listen on `listen_addr`: on loopback always, on
/// any other address only once the operator has confirmed that TLS is
/// terminated in front of it.
pub fn tls_requirement_met(listen_addr: SocketAddr, tls_verified: bool) -> bool {
    listen_addr.ip().is_loopback() || tls_verified
}

/// The federation mTLS listener address used when none is configured: the
/// main listener's address on the next port.
pub fn default_mtls_addr(listen_addr: SocketAddr) -> SocketAddr {
    let mut addr = listen_addr;
    addr.set_port(addr.port() + 1);
    addr
}

/// The `min_version_changed_at` timestamp to persist, if any.
///
/// `current` is what the version policy holds after start-up and `loaded`
/// what it was started from. A test override is authoritative and never
/// persisted, so an override run cannot pollute the storage a later run
/// without it reads.
pub fn min_version_change_to_persist(
    env_override: Option<u64>,
    loaded: Option<u64>,
    current: Option<u64>,
) -> Option<u64> {
    if env_override.is_some() {
        return None;
    }
    current.filter(|changed_at| Some(*changed_at) != loaded)
}

/// The OHTTP key rotation interval in seconds: the seconds override when
/// set, otherwise the configured hours.
pub fn ohttp_rotation_secs(secs_override: Option<u64>, rotation_hours: u64) -> u64 {
    secs_override.unwrap_or(rotation_hours * 3600)
}

/// Whether the metrics address is reachable from beyond this host.
pub fn binds_beyond_localhost(http_addr: &str) -> bool {
    !http_addr.starts_with("127.0.0.1") && !http_addr.starts_with("localhost")
}

/// DEV/TEST-only: whether federation offload may target loopback/private
/// peers, bypassing the SSRF IP blocklist. Honoured only in debug builds;
/// a release build answers `false` whatever
/// `RELAY_FEDERATION_DANGEROUSLY_ALLOW_LOOPBACK` says, so the SSRF guard
/// always applies in production. Exists solely to make local two-relay
/// federation testable (ADR-052).
pub fn federation_allow_loopback_peers(env_var_is_set: bool) -> bool {
    cfg!(debug_assertions) && env_var_is_set
}
