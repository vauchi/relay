// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for nonce tracking, hex decoding, signed handshake verification,
//! and purge signature verification (SP-2).

use super::*;

use nonce::decode_hex;
use verify::{PurgeVerify, protocol, verify_signed_handshake};

use aws_lc_rs::signature::KeyPair;

// ================================================================
// NonceTracker tests
// ================================================================

#[test]
fn test_nonce_tracker_accepts_fresh_nonce() {
    let tracker = NonceTracker::new();
    assert!(tracker.check_and_insert(b"nonce1"));
}

#[test]
fn test_nonce_tracker_rejects_replay() {
    let tracker = NonceTracker::new();
    assert!(tracker.check_and_insert(b"nonce1"));
    assert!(!tracker.check_and_insert(b"nonce1"));
}

#[test]
fn test_nonce_tracker_accepts_different_nonces() {
    let tracker = NonceTracker::new();
    assert!(tracker.check_and_insert(b"nonce1"));
    assert!(tracker.check_and_insert(b"nonce2"));
}

// ================================================================
// decode_hex tests
// ================================================================

#[test]
fn test_decode_hex_valid() {
    let result = decode_hex("0102ff").unwrap();
    assert_eq!(result, vec![0x01, 0x02, 0xff]);
}

#[test]
fn test_decode_hex_odd_length() {
    assert!(decode_hex("abc").is_err());
}

#[test]
fn test_decode_hex_invalid_char() {
    assert!(decode_hex("zz").is_err());
}

// ================================================================
// verify_signed_handshake tests
// ================================================================

/// Helper: generate an Ed25519 keypair, sign (nonce || timestamp), and return
/// (public_key_hex, nonce_hex, signature_hex, timestamp, derived_client_id).
fn make_test_signed_handshake() -> (String, String, String, u64, String) {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = aws_lc_rs::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

    let public_key = key_pair.public_key().as_ref();
    let public_key_hex: String = public_key.iter().map(|b| format!("{:02x}", b)).collect();

    let nonce = [42u8; 32];
    let nonce_hex: String = nonce.iter().map(|b| format!("{:02x}", b)).collect();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut sign_data = Vec::with_capacity(40);
    sign_data.extend_from_slice(&nonce);
    sign_data.extend_from_slice(&timestamp.to_be_bytes());

    let signature = key_pair.sign(&sign_data);
    let sig_hex: String = signature
        .as_ref()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    (
        public_key_hex.clone(),
        nonce_hex,
        sig_hex,
        timestamp,
        public_key_hex,
    )
}

#[test]
fn test_verify_signed_handshake_valid() {
    let (pk, nonce, sig, ts, expected_id) = make_test_signed_handshake();
    let tracker = NonceTracker::new();
    let result = verify_signed_handshake(&pk, &nonce, &sig, ts, &tracker);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), expected_id);
}

#[test]
fn test_verify_signed_handshake_bad_signature() {
    let (pk, nonce, mut sig, ts, _) = make_test_signed_handshake();
    // Corrupt the signature
    sig.replace_range(0..2, "ff");
    let tracker = NonceTracker::new();
    let result = verify_signed_handshake(&pk, &nonce, &sig, ts, &tracker);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "signature verification failed");
}

#[test]
fn test_verify_signed_handshake_expired_timestamp() {
    let (_pk, nonce, _, _, _) = make_test_signed_handshake();

    // Re-sign with old timestamp
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = aws_lc_rs::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let pub_hex: String = key_pair
        .public_key()
        .as_ref()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    let old_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 120; // 2 minutes ago

    let nonce_bytes = decode_hex(&nonce).unwrap();
    let mut sign_data = Vec::with_capacity(40);
    sign_data.extend_from_slice(&nonce_bytes);
    sign_data.extend_from_slice(&old_ts.to_be_bytes());
    let sig = key_pair.sign(&sign_data);
    let sig_hex: String = sig.as_ref().iter().map(|b| format!("{:02x}", b)).collect();

    let tracker = NonceTracker::new();
    let result = verify_signed_handshake(&pub_hex, &nonce, &sig_hex, old_ts, &tracker);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "timestamp outside allowed window");
}

#[test]
fn test_verify_signed_handshake_nonce_replay() {
    let (pk, nonce, sig, ts, _) = make_test_signed_handshake();
    let tracker = NonceTracker::new();

    // First call succeeds
    let result1 = verify_signed_handshake(&pk, &nonce, &sig, ts, &tracker);
    assert!(result1.is_ok());

    // Second call with same nonce fails
    let result2 = verify_signed_handshake(&pk, &nonce, &sig, ts, &tracker);
    assert!(result2.is_err());
    assert_eq!(result2.unwrap_err(), "nonce replay detected");
}

// ================================================================
// Purge signature verification tests (SP-2)
// ================================================================

#[test]
fn test_purge_request_rejects_missing_signature() {
    let purge = protocol::PurgeRequest {
        include_device_sync: true,
        include_recovery_proofs: false,
        recovery_key_hash: None,
        public_key: None,
        signature: None,
        purge_token: None,
        timestamp: None,
    };
    assert!(!purge.is_authenticated());
}

#[test]
fn test_purge_request_accepts_valid_signature() {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = aws_lc_rs::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

    let public_key = key_pair.public_key().as_ref();
    let pk_hex: String = public_key.iter().map(|b| format!("{:02x}", b)).collect();

    let purge_token = [0xABu8; 32];
    let token_hex: String = purge_token.iter().map(|b| format!("{:02x}", b)).collect();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Sign: public_key || purge_token || timestamp_be_bytes
    let mut message = Vec::with_capacity(32 + 32 + 8);
    message.extend_from_slice(public_key);
    message.extend_from_slice(&purge_token);
    message.extend_from_slice(&timestamp.to_be_bytes());

    let signature = key_pair.sign(&message);
    let sig_hex: String = signature
        .as_ref()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    let purge = protocol::PurgeRequest {
        include_device_sync: true,
        include_recovery_proofs: false,
        recovery_key_hash: None,
        public_key: Some(pk_hex),
        signature: Some(sig_hex),
        purge_token: Some(token_hex),
        timestamp: Some(timestamp),
    };

    assert!(purge.is_authenticated());
    assert!(purge.verify_signature().is_ok());
}

#[test]
fn test_purge_request_rejects_bad_signature() {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = aws_lc_rs::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

    let public_key = key_pair.public_key().as_ref();
    let pk_hex: String = public_key.iter().map(|b| format!("{:02x}", b)).collect();

    let purge_token = [0xABu8; 32];
    let token_hex: String = purge_token.iter().map(|b| format!("{:02x}", b)).collect();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Create a bad signature (just random bytes)
    let bad_sig: String = [0xFFu8; 64].iter().map(|b| format!("{:02x}", b)).collect();

    let purge = protocol::PurgeRequest {
        include_device_sync: true,
        include_recovery_proofs: false,
        recovery_key_hash: None,
        public_key: Some(pk_hex),
        signature: Some(bad_sig),
        purge_token: Some(token_hex),
        timestamp: Some(timestamp),
    };

    assert!(purge.is_authenticated());
    assert!(purge.verify_signature().is_err());
}

#[test]
fn test_verify_signed_handshake_wrong_key_length() {
    let tracker = NonceTracker::new();
    let result = verify_signed_handshake(
        "aabb",
        "cc".repeat(32).as_str(),
        "dd".repeat(64).as_str(),
        0,
        &tracker,
    );
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "public key must be 32 bytes");
}
