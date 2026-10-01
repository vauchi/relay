// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for nonce tracking and purge signature verification (SP-2).

use super::*;

use aws_lc_rs::signature::KeyPair;

// ================================================================
// NonceTracker tests
// ================================================================

// @internal
#[test]
fn test_nonce_tracker_accepts_fresh_nonce() {
    let tracker = NonceTracker::new();
    assert!(tracker.check_and_insert(b"nonce1"));
}

// @internal
#[test]
fn test_nonce_tracker_rejects_replay() {
    let tracker = NonceTracker::new();
    assert!(tracker.check_and_insert(b"nonce1"));
    assert!(!tracker.check_and_insert(b"nonce1"));
}

// @internal
#[test]
fn test_nonce_tracker_accepts_different_nonces() {
    let tracker = NonceTracker::new();
    assert!(tracker.check_and_insert(b"nonce1"));
    assert!(tracker.check_and_insert(b"nonce2"));
}

// ================================================================
// Purge signature verification tests (SP-2)
// ================================================================

// @internal
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

// @internal
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
    assert_eq!(result.unwrap_err(), "invalid purge signature");
}

// @internal
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
    assert_eq!(
        result.unwrap_err(),
        "purge timestamp outside acceptable window"
    );
}

// @internal
#[test]
fn test_verify_purge_ed25519_wrong_key_length() {
    let result = verify::verify_purge_ed25519(&[0u8; 16], &[0u8; 32], &[0u8; 64], 0);
    assert!(result.unwrap_err().contains("public_key must be 32 bytes"));
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn generated_key_pair() -> aws_lc_rs::signature::Ed25519KeyPair {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = aws_lc_rs::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

// The edge is probed from the future side on purpose: if the clock ticks
// between here and the check, the skew shrinks to 59s and still passes,
// so the test cannot fail on timing.
// @internal
#[test]
fn test_verify_purge_ed25519_accepts_timestamp_at_window_edge() {
    let key_pair = generated_key_pair();
    let public_key = key_pair.public_key().as_ref();
    let purge_token = [0xABu8; 32];
    let timestamp = unix_now() + verify::TIMESTAMP_WINDOW;

    let mut message = Vec::with_capacity(72);
    message.extend_from_slice(public_key);
    message.extend_from_slice(&purge_token);
    message.extend_from_slice(&timestamp.to_be_bytes());
    let signature = key_pair.sign(&message);

    let result =
        verify::verify_purge_ed25519(public_key, &purge_token, signature.as_ref(), timestamp);

    assert_eq!(result, Ok(()));
}

// @internal
#[test]
fn test_verify_guardian_ed25519_accepts_timestamp_at_window_edge() {
    let key_pair = generated_key_pair();
    let public_key = key_pair.public_key().as_ref();
    let domain = b"guardian-store";
    let timestamp = unix_now() + verify::TIMESTAMP_WINDOW;

    let mut to_hash = public_key.to_vec();
    to_hash.extend_from_slice(b"guardians");
    let guardian_hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &to_hash);

    let mut message = domain.to_vec();
    message.extend_from_slice(public_key);
    message.extend_from_slice(guardian_hash.as_ref());
    message.extend_from_slice(&timestamp.to_be_bytes());
    let signature = key_pair.sign(&message);

    let result = verify::verify_guardian_ed25519(
        domain,
        &hex::encode(public_key),
        &hex::encode(guardian_hash.as_ref()),
        timestamp,
        &hex::encode(signature.as_ref()),
    );

    let mut expected_hash = [0u8; 32];
    expected_hash.copy_from_slice(guardian_hash.as_ref());
    assert_eq!(result, Ok(expected_hash));
}
