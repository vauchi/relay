// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for nonce tracking and purge signature verification (SP-2).

use super::*;

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
// Purge signature verification tests (SP-2)
// ================================================================

#[test]
fn test_verify_purge_ed25519_valid() {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = aws_lc_rs::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

    let public_key = key_pair.public_key().as_ref();
    let purge_token = [0xABu8; 32];
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut message = Vec::with_capacity(72);
    message.extend_from_slice(public_key);
    message.extend_from_slice(&purge_token);
    message.extend_from_slice(&timestamp.to_be_bytes());

    let signature = key_pair.sign(&message);

    let result =
        verify::verify_purge_ed25519(public_key, &purge_token, signature.as_ref(), timestamp);
    assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
}

#[test]
fn test_verify_purge_ed25519_bad_signature() {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = aws_lc_rs::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

    let public_key = key_pair.public_key().as_ref();
    let purge_token = [0xABu8; 32];
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let bad_sig = [0xFFu8; 64];

    let result = verify::verify_purge_ed25519(public_key, &purge_token, &bad_sig, timestamp);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "invalid purge signature");
}

#[test]
fn test_verify_purge_ed25519_expired_timestamp() {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = aws_lc_rs::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

    let public_key = key_pair.public_key().as_ref();
    let purge_token = [0xABu8; 32];
    let old_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 120;

    let mut message = Vec::with_capacity(72);
    message.extend_from_slice(public_key);
    message.extend_from_slice(&purge_token);
    message.extend_from_slice(&old_ts.to_be_bytes());
    let signature = key_pair.sign(&message);

    let result = verify::verify_purge_ed25519(public_key, &purge_token, signature.as_ref(), old_ts);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        "purge timestamp outside acceptable window"
    );
}

#[test]
fn test_verify_purge_ed25519_wrong_key_length() {
    let result = verify::verify_purge_ed25519(&[0u8; 16], &[0u8; 32], &[0u8; 64], 0);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("public_key must be 32 bytes"));
}
