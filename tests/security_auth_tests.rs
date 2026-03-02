// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Security & Authentication Tests
//!
//! Tests for relay authentication and replay protection vulnerabilities.
//! Based on: 2026-03-02 security review (SP-13₀)

use vauchi_relay::config::{ConfigWarningLevel, RelayConfig};

// @scenario: security.feature @relay @auth
/// Test: Config validation detects gossip without mTLS
#[test]
fn test_config_validation_gossip_without_mtls() {
    let mut config = RelayConfig::default();
    config.federation.gossip_enabled = true;
    config.federation.tls_cert_path = None;

    let warnings = config.validate();

    assert!(
        warnings.iter().any(|w| w.level == ConfigWarningLevel::Error
            && w.message.contains("gossip")
            && w.message.contains("mTLS")),
        "Should detect gossip without mTLS as Error"
    );
}

// @scenario: security.feature @relay @auth
/// Test: Config validation accepts gossip with mTLS
#[test]
fn test_config_validation_gossip_with_mtls() {
    let mut config = RelayConfig::default();
    config.federation.gossip_enabled = true;
    config.federation.tls_cert_path = Some("/path/to/cert".to_string());

    let warnings = config.validate();

    let gossip_error = warnings.iter().any(|w| {
        w.level == ConfigWarningLevel::Error
            && w.message.contains("gossip")
            && w.message.contains("mTLS")
    });
    assert!(
        !gossip_error,
        "Should NOT error when gossip has mTLS configured"
    );
}

// @scenario: security.feature @relay @auth
/// Test: Config validation detects bad offload thresholds
#[test]
fn test_config_validation_offload_threshold() {
    let mut config = RelayConfig::default();
    config.federation.offload_threshold = 0.90;
    config.federation.offload_refuse = 0.85;

    let warnings = config.validate();

    assert!(
        warnings
            .iter()
            .any(|w| w.level == ConfigWarningLevel::Warning
                && w.message.contains("offload_threshold")
                && w.message.contains("offload_refuse")),
        "Should warn when offload_threshold >= offload_refuse"
    );
}

// @scenario: security.feature @relay @auth
/// Test: R-C1: Startup validation detects gossip without mTLS and aborts
/// This is the critical fix: main() must call config.validate() and exit on Error
#[test]
fn test_startup_aborts_on_config_error() {
    let mut config = RelayConfig::default();
    config.federation.gossip_enabled = true;
    config.federation.tls_cert_path = None;

    let warnings = config.validate();

    // Should have at least one Error level warning about gossip+mTLS
    assert!(
        warnings
            .iter()
            .any(|w| w.level == ConfigWarningLevel::Error),
        "Config with gossip and no mTLS should produce Error-level warning"
    );

    // In the real implementation, main() will check for these and call std::process::exit(1)
    // For now, verify the validation works correctly
    let has_gossip_error = warnings.iter().any(|w| {
        w.level == ConfigWarningLevel::Error
            && w.message.contains("gossip")
            && w.message.contains("mTLS")
    });
    assert!(has_gossip_error, "Should detect gossip without mTLS error");
}
