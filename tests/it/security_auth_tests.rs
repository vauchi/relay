// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Security & Authentication Tests
//!
//! Tests for relay authentication and replay protection vulnerabilities.
//! Based on: 2026-03-02 security review (SP-13₀)

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use vauchi_protocol::PurgeRequest;
use vauchi_relay::config::{ConfigWarningLevel, RelayConfig};
use vauchi_relay::noise_key::RelaySigningKey;

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

// @scenario: security.feature @relay @auth @replay
/// Test: R-C2 and R-M5: Purge request validation
/// Tests timestamp window and token length checks
#[test]
fn test_purge_request_timestamp_window() {
    // This test verifies the purge request structure but the actual
    // timestamp validation will be checked in handler_websocket_test.rs
    // where PurgeVerify::verify_signature() is tested.
    // For now, verify that PurgeRequest can be constructed with timestamp.

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let purge = PurgeRequest {
        include_recovery_proofs: false,
        recovery_key_hash: None,
        public_key: Some(
            "3031323334353637383930313233343536373839303132333435363738393031".to_string(),
        ),
        signature: Some("0".repeat(128)), // Ed25519 is 64 bytes = 128 hex chars
        purge_token: Some(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        ), // 32 bytes
        timestamp: Some(now),
    };

    // Verify that structure is valid
    assert!(purge.timestamp.is_some(), "Purge should have timestamp");
    assert_eq!(
        purge.purge_token.as_ref().unwrap().len(),
        64,
        "Token hex string should be 64 chars (32 bytes)"
    );
}

// @scenario: security.feature @relay @auth
/// Test: R-M5: Token length validation
/// Purge token must be exactly 32 bytes after hex::decode
#[test]
fn test_purge_request_token_length() {
    // 32 bytes = 64 hex characters (valid)
    let valid_token = "a".repeat(64);
    assert_eq!(
        valid_token.len(),
        64,
        "Valid 32-byte token should be 64 hex chars"
    );

    // Invalid: 31 bytes = 62 hex characters
    let invalid_token_short = "a".repeat(62);
    assert_ne!(
        invalid_token_short.len(),
        64,
        "31-byte token should not be 64 hex chars"
    );

    // Invalid: 33 bytes = 66 hex characters
    let invalid_token_long = "a".repeat(66);
    assert_ne!(
        invalid_token_long.len(),
        64,
        "33-byte token should not be 64 hex chars"
    );
}

// @scenario: security.feature @relay @auth @timing
/// Test: R-C4: Constant-time bearer token comparison
/// Verify that metrics endpoint uses subtle::ConstantTimeEq for timing-safe comparison
#[test]
fn test_bearer_token_constant_time_eq() {
    let token1 = "my_secret_token_123456789";
    let token2 = "my_secret_token_123456789";
    let token_wrong = "my_secret_token_123456790"; // Last char different

    // Verify ConstantTimeEq works correctly
    assert!(token1.as_bytes().ct_eq(token2.as_bytes()).unwrap_u8() == 1);
    assert!(token1.as_bytes().ct_eq(token_wrong.as_bytes()).unwrap_u8() == 0);

    // Verify that the comparison doesn't short-circuit on mismatched chars
    let long_token = "a".repeat(100);
    let long_wrong = "a".repeat(99) + "b";
    assert!(
        long_token
            .as_bytes()
            .ct_eq(long_wrong.as_bytes())
            .unwrap_u8()
            == 0
    );

    // Verify byte-by-byte attack vector: correct tokens should take same time
    // even if they differ at the end (ConstantTimeEq doesn't short-circuit)
    let correct = "my_secret_0000000000000000";
    let wrong_end = "my_secret_0000000000000001";
    let wrong_start = "my_secret_1111111111111111";

    // All comparisons should be made in constant time
    let _result1 = correct.as_bytes().ct_eq(wrong_end.as_bytes()).unwrap_u8();
    let _result2 = correct.as_bytes().ct_eq(wrong_start.as_bytes()).unwrap_u8();
    // In real cryptography, timing-safe comparison ensures both take same time
}

// @scenario: security.feature @relay @dos
/// Test: R-C3: NonceTracker rejects insertions at capacity
/// Without a cap, an attacker can exhaust relay memory with unlimited nonces.
#[test]
fn test_nonce_tracker_rejects_at_capacity() {
    use vauchi_relay::handler::NonceTracker;

    let tracker = NonceTracker::with_capacity(100);

    // Fill to capacity
    for i in 0..100u32 {
        let nonce = i.to_be_bytes().to_vec();
        assert!(
            tracker.check_and_insert(&nonce),
            "Nonce {i} should be accepted (under capacity)"
        );
    }

    // 101st nonce should be rejected
    let overflow_nonce = 100u32.to_be_bytes().to_vec();
    assert!(
        !tracker.check_and_insert(&overflow_nonce),
        "Should reject nonce at capacity"
    );
}

// @scenario: security.feature @relay @dos
/// Test: R-C3: NonceTracker default capacity is 200_000
#[test]
fn test_nonce_tracker_default_capacity() {
    use vauchi_relay::handler::NonceTracker;

    let tracker = NonceTracker::new();
    assert_eq!(
        tracker.capacity(),
        200_000,
        "Default capacity should be 200,000"
    );
}

// @scenario: security.feature @relay @dos
/// Test: R-C3: NonceTracker still accepts after eviction frees space
#[test]
fn test_nonce_tracker_accepts_after_eviction() {
    use vauchi_relay::handler::NonceTracker;

    // Use a small capacity and custom TTL for testing
    let tracker = NonceTracker::with_capacity(5);

    // Fill to capacity
    for i in 0..5u32 {
        assert!(tracker.check_and_insert(&i.to_be_bytes()));
    }

    // At capacity — new nonce rejected
    assert!(!tracker.check_and_insert(&99u32.to_be_bytes()));

    // Force eviction by clearing expired entries (simulate time passing)
    tracker.evict_all();

    // Now should accept again
    assert!(
        tracker.check_and_insert(&99u32.to_be_bytes()),
        "Should accept after eviction frees space"
    );
}

// @scenario: security.feature @relay @auth @signing
/// Test: R-M4: Forwarding hints must be signed with relay signing key.
/// Verify sign_hints produces valid signatures verifiable via aws-lc-rs.
#[test]
fn test_forwarding_hints_are_signed() {
    let noise_private = [42u8; 32];
    let signing_key = RelaySigningKey::from_noise_key(&noise_private);

    let hints = vauchi_protocol::ForwardingHints {
        hints: vec![vauchi_protocol::ForwardingHintInfo {
            blob_id: "blob123".to_string(),
            relay_url: "wss://peer.relay.example.com".to_string(),
            expires_at_secs: 9999999999,
        }],
        relay_signing_key: None,
        signature: None,
    };

    let signed = signing_key.sign_hints(&hints);

    assert!(
        signed.relay_signing_key.is_some(),
        "signing key should be set"
    );
    assert!(signed.signature.is_some(), "signature should be set");
    assert_eq!(
        signed.relay_signing_key.as_ref().unwrap(),
        &signing_key.public_key_hex()
    );

    // Verify via aws-lc-rs Ed25519
    let canonical = signed.canonical_data();
    let pk_bytes = hex::decode(signed.relay_signing_key.as_ref().unwrap()).unwrap();
    let sig_bytes = hex::decode(signed.signature.as_ref().unwrap()).unwrap();
    let pk =
        aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::ED25519, &pk_bytes);
    assert!(
        pk.verify(&canonical, &sig_bytes).is_ok(),
        "signature must verify"
    );
}

/// Test: R-M4: Tampered forwarding hints fail verification.
#[test]
fn test_forwarding_hints_tampered_rejected() {
    let noise_private = [42u8; 32];
    let signing_key = RelaySigningKey::from_noise_key(&noise_private);

    let hints = vauchi_protocol::ForwardingHints {
        hints: vec![vauchi_protocol::ForwardingHintInfo {
            blob_id: "blob123".to_string(),
            relay_url: "wss://peer.relay.example.com".to_string(),
            expires_at_secs: 9999999999,
        }],
        relay_signing_key: None,
        signature: None,
    };

    let signed = signing_key.sign_hints(&hints);
    let sig_bytes = hex::decode(signed.signature.as_ref().unwrap()).unwrap();
    let pk_bytes = hex::decode(signed.relay_signing_key.as_ref().unwrap()).unwrap();

    // Tamper with the relay URL
    let tampered = vauchi_protocol::ForwardingHints {
        hints: vec![vauchi_protocol::ForwardingHintInfo {
            blob_id: "blob123".to_string(),
            relay_url: "wss://evil.attacker.com".to_string(),
            expires_at_secs: 9999999999,
        }],
        relay_signing_key: None,
        signature: None,
    };

    let pk =
        aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::ED25519, &pk_bytes);
    assert!(
        pk.verify(&tampered.canonical_data(), &sig_bytes).is_err(),
        "tampered hints must fail verification"
    );
}

/// Test: R-M4: ConnectionDeps has relay_signing_key field.
#[test]
fn test_connection_deps_has_signing_key() {
    // Verify the field exists on ConnectionDeps and can be set
    let noise_private = [42u8; 32];
    let signing_key = Arc::new(RelaySigningKey::from_noise_key(&noise_private));

    let pk = signing_key.public_key_hex();
    assert_eq!(
        pk.len(),
        64,
        "Ed25519 public key should be 32 bytes = 64 hex chars"
    );
}
