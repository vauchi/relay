// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! External config tests — moved from inline `mod tests` in config.rs.
//! Also covers `from_env_with_warnings()` parse-warning behaviour.
//!
//! Many tests manipulate env vars; they MUST run with `--test-threads=1`
//! (configured in `.cargo/config.toml` or via `just test relay`).

use std::path::PathBuf;
use std::time::Duration;

use rstest::rstest;
use vauchi_relay::config::{
    ConfigWarningLevel, FederationConfig, NetworkConfig, RelayConfig, SecurityConfig,
    StorageConfig, load_relay_id,
};
use vauchi_relay::storage::StorageBackend;

// ── Default / struct layout ─────────────────────────────────────────────────

// @internal
#[test]
fn test_default_config() {
    let config = RelayConfig::default();

    assert_eq!(config.network.listen_addr.port(), 8080);
    assert_eq!(config.network.max_connections, 1000);
    assert_eq!(config.network.max_message_size, 1_048_576);
    assert_eq!(config.storage.blob_ttl_secs, 120 * 24 * 60 * 60); // 30 days
    assert_eq!(config.security.rate_limit_per_min, 60);
    assert_eq!(config.storage.cleanup_interval_secs, 3600);
    assert_eq!(config.storage.backend, StorageBackend::Sqlite);
    assert_eq!(config.storage.data_dir, PathBuf::from("./data"));
    assert_eq!(config.storage.max_blobs_per_user, 1000);
    assert_eq!(config.storage.max_storage_per_user, 50_000_000);
    assert_eq!(config.security.recovery_rate_limit_per_min, 10);
}

// @internal
#[test]
fn test_blob_ttl_duration() {
    let config = RelayConfig::default();
    assert_eq!(config.blob_ttl(), Duration::from_secs(120 * 24 * 60 * 60));
}

// @internal
#[test]
fn test_cleanup_interval_duration() {
    let config = RelayConfig::default();
    assert_eq!(config.cleanup_interval(), Duration::from_secs(3600));
}

// @internal
#[test]
fn test_federation_defaults() {
    let config = RelayConfig::default();
    assert!(!config.federation.enabled);
    assert!(config.federation.peers.is_empty());
    assert!((config.federation.offload_threshold - 0.80).abs() < f64::EPSILON);
    assert!((config.federation.offload_refuse - 0.95).abs() < f64::EPSILON);
    assert_eq!(config.federation.drain_timeout_secs, 300);
    assert_eq!(config.federation.peer_timeout_secs, 30);
    assert_eq!(config.federation.capacity_interval_secs, 60);
    assert_eq!(config.storage.max_storage_bytes, 1_073_741_824);
}

// @internal
#[test]
fn test_gossip_defaults() {
    let config = RelayConfig::default();
    assert!(!config.federation.gossip_enabled);
    assert_eq!(config.federation.gossip_interval_secs, 120);
    assert_eq!(config.federation.peer_ttl_secs, 3600);
}

// @internal
#[test]
fn test_mtls_defaults() {
    let config = RelayConfig::default();
    assert!(config.federation.tls_cert_path.is_none());
    assert!(config.federation.tls_key_path.is_none());
    assert!(config.federation.tls_ca_path.is_none());
}

// @internal
#[test]
fn test_nested_network_config_defaults() {
    let config = RelayConfig::default();
    assert_eq!(config.network.listen_addr.port(), 8080);
    assert_eq!(config.network.max_connections, 1000);
    assert_eq!(config.network.max_message_size, 1_048_576);
    assert_eq!(config.network.idle_timeout_secs, 300);
}

// @internal
#[test]
fn test_nested_storage_config_defaults() {
    let config = RelayConfig::default();
    assert_eq!(config.storage.backend, StorageBackend::Sqlite);
    assert_eq!(config.storage.data_dir, PathBuf::from("./data"));
    assert_eq!(config.storage.blob_ttl_secs, 120 * 24 * 60 * 60);
    assert_eq!(config.storage.cleanup_interval_secs, 3600);
    assert_eq!(config.storage.max_blobs_per_user, 1000);
    assert_eq!(config.storage.max_storage_per_user, 50_000_000);
    assert_eq!(config.storage.max_storage_bytes, 1_073_741_824);
}

// @internal
#[test]
fn test_nested_federation_config_defaults() {
    let config = RelayConfig::default();
    assert!(!config.federation.enabled);
    assert!(config.federation.peers.is_empty());
    assert!((config.federation.offload_threshold - 0.80).abs() < f64::EPSILON);
    assert!((config.federation.offload_refuse - 0.95).abs() < f64::EPSILON);
    assert_eq!(config.federation.drain_timeout_secs, 300);
    assert_eq!(config.federation.peer_timeout_secs, 30);
    assert_eq!(config.federation.capacity_interval_secs, 60);
    assert!(!config.federation.gossip_enabled);
    assert_eq!(config.federation.gossip_interval_secs, 120);
    assert_eq!(config.federation.peer_ttl_secs, 3600);
    assert_eq!(config.federation.federation_rate_limit_per_min, 300);
    assert!(config.federation.tls_cert_path.is_none());
    assert!(config.federation.tls_key_path.is_none());
    assert!(config.federation.tls_ca_path.is_none());
    assert!(config.federation.mtls_addr.is_none());
    assert!(config.federation.relay_id.is_empty());
}

// @internal
#[test]
fn test_nested_security_config_defaults() {
    let config = RelayConfig::default();
    assert_eq!(config.security.rate_limit_per_min, 60);
    assert_eq!(config.security.recovery_rate_limit_per_min, 10);
    assert_eq!(config.security.delivery_jitter_min_ms, 50);
    assert_eq!(config.security.delivery_jitter_max_ms, 500);
}

// @internal
#[test]
fn test_nested_config_network_has_idle_timeout_method() {
    let config = RelayConfig::default();
    assert_eq!(config.network.idle_timeout(), Duration::from_secs(300));
}

// @internal
#[test]
fn test_nested_config_storage_has_blob_ttl_method() {
    let config = RelayConfig::default();
    assert_eq!(
        config.storage.blob_ttl(),
        Duration::from_secs(120 * 24 * 60 * 60)
    );
}

// @internal
#[test]
fn test_nested_config_storage_has_cleanup_interval_method() {
    let config = RelayConfig::default();
    assert_eq!(config.storage.cleanup_interval(), Duration::from_secs(3600));
}

// @internal
#[test]
fn test_nested_config_construction_with_overrides() {
    let config = RelayConfig {
        network: NetworkConfig {
            listen_addr: "127.0.0.1:9090".parse().unwrap(),
            max_connections: 500,
            ..Default::default()
        },
        storage: StorageConfig {
            backend: StorageBackend::Memory,
            max_storage_bytes: 512_000,
            ..Default::default()
        },
        federation: FederationConfig {
            enabled: true,
            peers: vec!["ws://peer-1:8080".to_string()],
            offload_threshold: 0.70,
            ..Default::default()
        },
        security: SecurityConfig {
            rate_limit_per_min: 120,
            ..Default::default()
        },
        ..Default::default()
    };
    assert_eq!(config.network.listen_addr.port(), 9090);
    assert_eq!(config.network.max_connections, 500);
    assert_eq!(config.storage.backend, StorageBackend::Memory);
    assert_eq!(config.storage.max_storage_bytes, 512_000);
    assert!(config.federation.enabled);
    assert_eq!(config.federation.peers.len(), 1);
    assert!((config.federation.offload_threshold - 0.70).abs() < f64::EPSILON);
    assert_eq!(config.security.rate_limit_per_min, 120);
}

/// RelayConfig delegate: idle_timeout()
// @internal
#[test]
fn test_relay_config_idle_timeout_delegate() {
    let config = RelayConfig::default();
    assert_eq!(config.idle_timeout(), Duration::from_secs(300));
}

// ── validate() ───────────────────────────────────────────────────────────────

/// validate() returns no warnings for a valid default config.
// @internal
#[test]
fn test_validate_default_config_clean() {
    let config = RelayConfig::default();
    let warnings = config.validate();
    assert!(
        warnings.is_empty(),
        "Default config should produce no warnings, got: {:?}",
        warnings.iter().map(|w| &w.message).collect::<Vec<_>>()
    );
}

// Trace: codebase-review-tracker item #44
// @internal
#[test]
fn test_validate_gossip_requires_mtls() {
    let config = RelayConfig {
        federation: FederationConfig {
            gossip_enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let warnings = config.validate();
    assert!(
        warnings
            .iter()
            .any(|w| w.level == ConfigWarningLevel::Error && w.message.contains("mTLS")),
        "Gossip without mTLS should produce an error"
    );
}

// Trace: codebase-review-tracker item #44
// @internal
#[test]
fn test_validate_gossip_with_mtls_ok() {
    let config = RelayConfig {
        federation: FederationConfig {
            gossip_enabled: true,
            tls_cert_path: Some("/path/to/cert.pem".to_string()),
            tls_key_path: Some("/path/to/key.pem".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    let warnings = config.validate();
    assert!(
        !warnings.iter().any(|w| w.message.contains("mTLS")),
        "Gossip with mTLS configured should not warn about mTLS"
    );
}

// @internal
#[test]
fn test_validate_offload_threshold_sanity() {
    let config = RelayConfig {
        federation: FederationConfig {
            offload_threshold: 0.99,
            offload_refuse: 0.95,
            ..Default::default()
        },
        ..Default::default()
    };
    let warnings = config.validate();
    assert!(
        warnings
            .iter()
            .any(|w| w.level == ConfigWarningLevel::Warning && w.message.contains("threshold")),
        "Inverted threshold should warn"
    );
}

/// validate() catches equal thresholds (boundary of >= check).
// @internal
#[test]
fn test_validate_offload_threshold_equal() {
    let config = RelayConfig {
        federation: FederationConfig {
            offload_threshold: 0.95,
            offload_refuse: 0.95,
            ..Default::default()
        },
        ..Default::default()
    };
    let warnings = config.validate();
    assert!(
        warnings
            .iter()
            .any(|w| w.level == ConfigWarningLevel::Warning),
        "Equal threshold/refuse should produce a warning"
    );
}

/// R-M3: Partial mTLS config (cert xor key) must produce error; complete config must not.
#[rstest]
#[case::cert_without_key(
    Some("/path/to/cert.pem".to_string()),
    None,
    true,
    "R-M3: Cert without key should produce an error about partial mTLS config"
)]
#[case::key_without_cert(
    None,
    Some("/path/to/key.pem".to_string()),
    true,
    "R-M3: Key without cert should produce an error about partial mTLS config"
)]
#[case::complete_mtls_no_error(
    Some("/path/to/cert.pem".to_string()),
    Some("/path/to/key.pem".to_string()),
    false,
    "Complete mTLS config should not produce partial mTLS error"
)]
fn test_validate_partial_mtls(
    #[case] cert_path: Option<String>,
    #[case] key_path: Option<String>,
    #[case] expect_error: bool,
    #[case] msg: &str,
) {
    let config = RelayConfig {
        federation: FederationConfig {
            tls_cert_path: cert_path,
            tls_key_path: key_path,
            ..Default::default()
        },
        ..Default::default()
    };
    let warnings = config.validate();
    let has_partial_mtls = warnings
        .iter()
        .any(|w| w.level == ConfigWarningLevel::Error && w.message.contains("Partial mTLS"));
    assert_eq!(has_partial_mtls, expect_error, "{msg}");
}

// ── Peer list parsing (pure logic, no env) ───────────────────────────────────

// @internal
#[test]
fn test_federation_peer_list_parsing() {
    let peer_str = "ws://relay-a:8080, ws://relay-b:8080 , ws://relay-c:8080";
    let peers: Vec<String> = peer_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(peers.len(), 3);
    assert_eq!(peers[0], "ws://relay-a:8080");
    assert_eq!(peers[1], "ws://relay-b:8080");
    assert_eq!(peers[2], "ws://relay-c:8080");
}

// @internal
#[test]
fn test_federation_peer_list_empty() {
    let peer_str = "";
    let peers: Vec<String> = peer_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    assert!(peers.is_empty());
}

// @internal
#[test]
fn test_federation_peer_whitespace_trimming() {
    let peer_str = "  ws://relay-a:8080  ,  ws://relay-b:8080  ";
    let peers: Vec<String> = peer_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(peers[0], "ws://relay-a:8080");
    assert_eq!(peers[1], "ws://relay-b:8080");
}

// ── load_relay_id ────────────────────────────────────────────────────────────

// @internal
#[test]
fn test_relay_id_file_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path();

    let id1 = load_relay_id(data_dir);
    assert!(!id1.is_empty());

    let id2 = load_relay_id(data_dir);
    assert_eq!(id1, id2, "relay_id should be stable across calls");

    let file_content = std::fs::read_to_string(data_dir.join("relay_id")).unwrap();
    assert_eq!(file_content.trim(), id1);
}

// @internal
#[test]
fn test_relay_id_env_var_overrides_file() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path();

    std::fs::write(data_dir.join("relay_id"), "file-relay-id").unwrap();

    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("RELAY_FEDERATION_RELAY_ID", "env-relay-id") };
    let id = load_relay_id(data_dir);
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::remove_var("RELAY_FEDERATION_RELAY_ID") };

    assert_eq!(id, "env-relay-id");
}

/// load_relay_id: empty env var falls through to file/generate.
// @internal
#[test]
fn test_relay_id_empty_env_var_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path();

    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("RELAY_FEDERATION_RELAY_ID", "") };
    let id = load_relay_id(data_dir);
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::remove_var("RELAY_FEDERATION_RELAY_ID") };

    assert!(!id.is_empty(), "Empty env var should be ignored");
    assert!(id.len() >= 32, "Should be a UUID: {}", id);
}

/// load_relay_id: empty file falls through to generate.
// @internal
#[test]
fn test_relay_id_empty_file_regenerates() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path();

    std::fs::write(data_dir.join("relay_id"), "").unwrap();

    let id = load_relay_id(data_dir);
    assert!(!id.is_empty(), "Empty file should trigger regeneration");
}

// ── from_env_with_warnings — parse warning tests ────────────────────────────
//
// These tests exercise the NEW behaviour: invalid numeric/address env vars
// produce a warning string and fall back to the default, rather than being
// silently ignored.
//
// NOTE: env-var tests modify the process environment and MUST run serially.
// Configure `just test relay` or set RUST_TEST_THREADS=1 when running the
// config_tests binary directly.

/// Invalid env var produces a warning and keeps the default.
#[rstest]
#[case::max_connections("RELAY_MAX_CONNECTIONS", "not_a_number")]
#[case::listen_addr("RELAY_LISTEN_ADDR", "not-an-address")]
#[case::idle_timeout("RELAY_IDLE_TIMEOUT", "five_minutes")]
#[case::max_message_size("RELAY_MAX_MESSAGE_SIZE", "1mb")]
#[case::blob_ttl_secs("RELAY_BLOB_TTL_SECS", "thirty-days")]
#[case::rate_limit("RELAY_RATE_LIMIT", "unlimited")]
#[case::offload_threshold("RELAY_FEDERATION_OFFLOAD_THRESHOLD", "eighty-percent")]
#[case::mtls_addr("RELAY_FEDERATION_MTLS_ADDR", "bad-addr:xyz")]
fn test_parse_warning_invalid_env_var(#[case] env_var: &str, #[case] bad_value: &str) {
    // SAFETY: env-var tests run with --test-threads=1 (configured in .cargo/config.toml)
    unsafe { std::env::set_var(env_var, bad_value) };
    let (_config, warnings) = RelayConfig::from_env_with_warnings();
    unsafe { std::env::remove_var(env_var) };

    assert!(
        warnings.iter().any(|w| w.contains(env_var)),
        "Expected warning mentioning {env_var}, got: {warnings:?}",
    );
}

/// Valid RELAY_MAX_CONNECTIONS produces no warning and updates the field.
// @internal
#[test]
fn test_no_warning_max_connections_valid() {
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("RELAY_MAX_CONNECTIONS", "500") };
    let (config, warnings) = RelayConfig::from_env_with_warnings();
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::remove_var("RELAY_MAX_CONNECTIONS") };

    assert_eq!(config.network.max_connections, 500);
    assert!(
        !warnings.iter().any(|w| w.contains("RELAY_MAX_CONNECTIONS")),
        "No warning expected for valid value"
    );
}

/// Multiple invalid env vars produce one warning each.
// @internal
#[test]
fn test_parse_warnings_multiple_invalid_vars() {
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("RELAY_MAX_CONNECTIONS", "abc") };
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("RELAY_RATE_LIMIT", "xyz") };
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("RELAY_BLOB_TTL_SECS", "forever") };
    let (_config, warnings) = RelayConfig::from_env_with_warnings();
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::remove_var("RELAY_MAX_CONNECTIONS") };
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::remove_var("RELAY_RATE_LIMIT") };
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::remove_var("RELAY_BLOB_TTL_SECS") };

    assert!(
        warnings.iter().any(|w| w.contains("RELAY_MAX_CONNECTIONS")),
        "Expected RELAY_MAX_CONNECTIONS warning"
    );
    assert!(
        warnings.iter().any(|w| w.contains("RELAY_RATE_LIMIT")),
        "Expected RELAY_RATE_LIMIT warning"
    );
    assert!(
        warnings.iter().any(|w| w.contains("RELAY_BLOB_TTL_SECS")),
        "Expected RELAY_BLOB_TTL_SECS warning"
    );
    assert!(
        warnings.len() >= 3,
        "Expected at least 3 warnings, got {}",
        warnings.len()
    );
}

/// from_env() (thin wrapper) still works and returns config without panicking.
// @internal
#[test]
fn test_from_env_wrapper_still_works() {
    // Even with a bad env var, from_env() must not panic — it discards warnings silently.
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("RELAY_MAX_CONNECTIONS", "not_a_number") };
    let config = RelayConfig::from_env();
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::remove_var("RELAY_MAX_CONNECTIONS") };

    assert_eq!(
        config.network.max_connections,
        RelayConfig::default().network.max_connections,
        "from_env() wrapper must fall back to default on parse failure"
    );
}

/// Warning message format: must include env var name, bad value, and default.
// @internal
#[test]
fn test_warning_message_format() {
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("RELAY_MAX_CONNECTIONS", "bad_val") };
    let (_config, warnings) = RelayConfig::from_env_with_warnings();
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::remove_var("RELAY_MAX_CONNECTIONS") };

    let warning = warnings
        .iter()
        .find(|w| w.contains("RELAY_MAX_CONNECTIONS"))
        .expect("Warning for RELAY_MAX_CONNECTIONS must be present");

    assert!(
        warning.contains("bad_val"),
        "Warning must include the bad value, got: {}",
        warning
    );
    assert!(
        warning.contains("using default"),
        "Warning must mention 'using default', got: {}",
        warning
    );
    // Default is 1000
    assert!(
        warning.contains("1000"),
        "Warning must include the default value (1000), got: {}",
        warning
    );
}

/// from_env_with_warnings() returns a structurally valid config (non-zero defaults).
///
/// This verifies the call completes and the resulting config has sensible
/// defaults regardless of what env vars happen to be set in the environment.
// @internal
#[test]
fn test_from_env_with_warnings_returns_valid_config() {
    let (config, _warnings) = RelayConfig::from_env_with_warnings();

    // The config must always be structurally sound: non-zero limits, valid address.
    assert!(
        config.network.max_connections > 0,
        "max_connections must be non-zero"
    );
    assert!(
        config.network.max_message_size > 0,
        "max_message_size must be non-zero"
    );
    assert!(
        config.storage.blob_ttl_secs > 0,
        "blob_ttl_secs must be non-zero"
    );
    assert!(
        config.security.rate_limit_per_min > 0,
        "rate_limit_per_min must be non-zero"
    );
}
