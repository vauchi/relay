// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! WebSocket authenticated handshake tests: signature validation, nonce replay,
//! timestamp expiry, and legacy unauthenticated fallback.

mod common;

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use vauchi_relay::connection_registry::ConnectionRegistry;
use vauchi_relay::handler::{self, ConnectionDeps, QuotaLimits};
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::noise_key::generate_relay_keypair;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::recovery_storage::SqliteRecoveryProofStore;
use vauchi_relay::storage::{BlobStore, SqliteBlobStore};

use common::ws_helpers::*;

// ============================================================================
// Auth helpers
// ============================================================================

/// Generates an Ed25519 keypair and builds a signed handshake JSON envelope.
/// Returns (handshake_value, client_id_hex).
fn make_signed_handshake_envelope() -> (serde_json::Value, String) {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

    let public_key = key_pair.public_key().as_ref();
    let client_id: String = public_key.iter().map(|b| format!("{:02x}", b)).collect();
    let pk_hex = client_id.clone();

    let nonce = [0x42u8; 32];
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

    let envelope = json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "Handshake",
            "client_id": client_id,
            "identity_public_key": pk_hex,
            "nonce": nonce_hex,
            "signature": sig_hex,
            "timestamp": timestamp,
        }
    });

    (envelope, client_id)
}

/// Helper: generate a signed handshake with a specific nonce (for replay testing).
fn make_signed_handshake_with_nonce(nonce_bytes: &[u8; 32]) -> (serde_json::Value, String) {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

    let public_key = key_pair.public_key().as_ref();
    let client_id: String = public_key.iter().map(|b| format!("{:02x}", b)).collect();
    let pk_hex = client_id.clone();

    let nonce_hex: String = nonce_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut sign_data = Vec::with_capacity(40);
    sign_data.extend_from_slice(nonce_bytes);
    sign_data.extend_from_slice(&timestamp.to_be_bytes());

    let signature = key_pair.sign(&sign_data);
    let sig_hex: String = signature
        .as_ref()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    let envelope = json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "Handshake",
            "client_id": client_id,
            "identity_public_key": pk_hex,
            "nonce": nonce_hex,
            "signature": sig_hex,
            "timestamp": timestamp,
        }
    });

    (envelope, client_id)
}

// ============================================================================
// Tests: Authenticated handshake
// ============================================================================

// @scenario: security:Authenticated handshake with valid signature accepted
#[tokio::test]
async fn test_authenticated_handshake_accepted() {
    let (deps, relay_pub, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    let (hs, _client_id) = make_signed_handshake_envelope();
    let ack = client.send_recv(&hs).await;

    assert_eq!(ack["payload"]["type"], "HandshakeAck");
    assert_eq!(ack["payload"]["protocol_version"], 1);
    let features = ack["payload"]["features"].as_array().unwrap();
    assert!(features.iter().any(|f| f == "authenticated_handshake"));

    client.close().await;
}

// @scenario: security:Invalid signature rejected at handshake
#[tokio::test]
async fn test_invalid_signature_rejected() {
    let (deps, relay_pub, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    let (mut hs, _) = make_signed_handshake_envelope();
    // Corrupt the signature by changing its first two hex chars
    let bad_sig = format!("ff{}", &hs["payload"]["signature"].as_str().unwrap()[2..]);
    hs["payload"]["signature"] = json!(bad_sig);

    client.send_envelope(&hs).await;

    // Server should close the connection (auth failed)
    let msg = timeout(Duration::from_secs(2), client.next_raw_ws()).await;
    match msg {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {
            // Expected: disconnected
        }
        other => panic!("Expected close/disconnect, got {:?}", other),
    }
}

// @scenario: security:Client ID mismatch rejected at handshake
#[tokio::test]
async fn test_client_id_mismatch_rejected() {
    let (deps, relay_pub, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    let (mut hs, _) = make_signed_handshake_envelope();
    // Change client_id to a different valid hex string (not matching the public key)
    hs["payload"]["client_id"] = json!("a".repeat(64));

    client.send_envelope(&hs).await;

    // Server should close the connection (client_id mismatch)
    let msg = timeout(Duration::from_secs(2), client.next_raw_ws()).await;
    match msg {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {
            // Expected: disconnected
        }
        other => panic!("Expected close/disconnect, got {:?}", other),
    }
}

// @scenario: security:Nonce replay rejected at handshake
#[tokio::test]
async fn test_nonce_replay_rejected() {
    // Two connections share the same nonce_tracker via shared deps
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let nonce_tracker = Arc::new(handler::NonceTracker::new());
    let kp = generate_relay_keypair();

    // First connection with a signed handshake
    let nonce_bytes = [0xABu8; 32];
    let (hs1, _client_id1) = make_signed_handshake_with_nonce(&nonce_bytes);

    let deps1 = ConnectionDeps {
        storage: storage.clone() as Arc<dyn BlobStore>,
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(60)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(10)),
        registry: registry.clone(),
        blob_sender_map: handler::new_blob_sender_map(),
        max_message_size: 1_048_576,
        idle_timeout: Duration::from_secs(5),
        quota: QuotaLimits {
            max_blobs: 100,
            max_bytes: 10_000_000,
        },
        hint_store: None,
        noise_static_key: Some(kp.private),
        nonce_tracker: nonce_tracker.clone(),
        delivery_jitter_min_ms: 0,
        delivery_jitter_max_ms: 0,
        relay_signing_key: None,
        metrics: RelayMetrics::new(),
    };

    let url1 = start_test_server(deps1).await;
    let mut client1 = connect_noise(&url1, &kp.public).await;

    // First connection succeeds
    let ack1 = client1.send_recv(&hs1).await;
    assert_eq!(ack1["payload"]["type"], "HandshakeAck");
    client1.close().await;

    // Second connection with same nonce (different keypair but same nonce bytes)
    // The nonce_tracker is shared, so this should be rejected
    let (hs2, _) = make_signed_handshake_with_nonce(&nonce_bytes);

    let kp2 = generate_relay_keypair();
    let deps2 = ConnectionDeps {
        storage: storage.clone() as Arc<dyn BlobStore>,
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(60)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(10)),
        registry: registry.clone(),
        blob_sender_map: handler::new_blob_sender_map(),
        max_message_size: 1_048_576,
        idle_timeout: Duration::from_secs(5),
        quota: QuotaLimits {
            max_blobs: 100,
            max_bytes: 10_000_000,
        },
        hint_store: None,
        noise_static_key: Some(kp2.private),
        nonce_tracker: nonce_tracker.clone(),
        delivery_jitter_min_ms: 0,
        delivery_jitter_max_ms: 0,
        relay_signing_key: None,
        metrics: RelayMetrics::new(),
    };

    let url2 = start_test_server(deps2).await;
    let mut client2 = connect_noise(&url2, &kp2.public).await;

    client2.send_envelope(&hs2).await;

    // Should be rejected (nonce replay)
    let msg = timeout(Duration::from_secs(2), client2.next_raw_ws()).await;
    match msg {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {
            // Expected: disconnected
        }
        other => panic!("Expected close/disconnect, got {:?}", other),
    }
}

// @scenario: security:Expired timestamp rejected at handshake
#[tokio::test]
async fn test_expired_timestamp_rejected() {
    let (deps, relay_pub, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    // Generate keypair and sign with a timestamp that's 120s old
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

    let public_key = key_pair.public_key().as_ref();
    let client_id: String = public_key.iter().map(|b| format!("{:02x}", b)).collect();
    let pk_hex = client_id.clone();

    let nonce = [0x99u8; 32];
    let nonce_hex: String = nonce.iter().map(|b| format!("{:02x}", b)).collect();

    let old_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 120; // 2 minutes ago, outside ±60s window

    let mut sign_data = Vec::with_capacity(40);
    sign_data.extend_from_slice(&nonce);
    sign_data.extend_from_slice(&old_timestamp.to_be_bytes());

    let signature = key_pair.sign(&sign_data);
    let sig_hex: String = signature
        .as_ref()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    let hs = json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "Handshake",
            "client_id": client_id,
            "identity_public_key": pk_hex,
            "nonce": nonce_hex,
            "signature": sig_hex,
            "timestamp": old_timestamp,
        }
    });

    client.send_envelope(&hs).await;

    // Should be rejected (expired timestamp)
    let msg = timeout(Duration::from_secs(2), client.next_raw_ws()).await;
    match msg {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {
            // Expected: disconnected
        }
        other => panic!("Expected close/disconnect, got {:?}", other),
    }
}

// ============================================================================
// Tests: Legacy unauthenticated handshake
// ============================================================================

// @scenario: relay_network:Legacy unauthenticated handshake still accepted
#[tokio::test]
async fn test_unauthenticated_handshake_still_accepted() {
    // Legacy clients without auth fields should still work (over Noise NK)
    let (deps, relay_pub, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    let client_id = common::generate_test_client_id(1);
    let ack = client.do_handshake(&client_id).await;

    assert_eq!(ack["payload"]["type"], "HandshakeAck");
    assert_eq!(ack["payload"]["protocol_version"], 1);

    // Can still store blobs
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[10, 20]);
    let response = client.send_recv(&update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    client.close().await;
}

// ============================================================================
// Tests: Auth hash rate limiting (SP-33)
// ============================================================================

/// Builds a signed handshake for a given keypair, using a specific routing_token.
/// Returns the handshake envelope.
fn make_signed_handshake_with_routing_token(
    key_pair: &aws_lc_rs::signature::Ed25519KeyPair,
    routing_token: &str,
) -> serde_json::Value {
    use aws_lc_rs::signature::KeyPair;

    let public_key = key_pair.public_key().as_ref();
    let client_id: String = public_key.iter().map(|b| format!("{:02x}", b)).collect();
    let pk_hex = client_id.clone();

    // Use a unique nonce per call (include routing_token bytes to ensure uniqueness)
    let mut nonce = [0u8; 32];
    let rt_bytes = routing_token.as_bytes();
    let copy_len = rt_bytes.len().min(32);
    nonce[..copy_len].copy_from_slice(&rt_bytes[..copy_len]);
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

    serde_json::json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "Handshake",
            "client_id": client_id,
            "identity_public_key": pk_hex,
            "nonce": nonce_hex,
            "signature": sig_hex,
            "timestamp": timestamp,
            "routing_token": routing_token,
        }
    })
}

// @scenario: security:Rate limiting uses stable auth hash, not rotating token
// Two connections using the SAME signing key but DIFFERENT routing tokens share
// the same rate-limit bucket (keyed on SHA-256(signing_key)).
#[tokio::test]
async fn test_rate_limit_keys_on_auth_hash_not_routing_id() {
    use std::sync::Arc;

    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};

    use vauchi_relay::connection_registry::ConnectionRegistry;
    use vauchi_relay::handler::{self, ConnectionDeps, NonceTracker, QuotaLimits};
    use vauchi_relay::metrics::RelayMetrics;
    use vauchi_relay::noise_key::generate_relay_keypair;
    use vauchi_relay::rate_limit::RateLimiter;
    use vauchi_relay::recovery_storage::SqliteRecoveryProofStore;
    use vauchi_relay::storage::{BlobStore, SqliteBlobStore};

    // Rate limit of 1 message per minute: first message passes, second is rejected.
    let rate_limit = 1u32;

    let kp = generate_relay_keypair();
    let relay_pub = kp.public;
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let shared_rate_limiter = Arc::new(RateLimiter::new(rate_limit));
    let nonce_tracker = Arc::new(NonceTracker::new());

    // Generate ONE signing keypair (same auth identity)
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let client_id: String = key_pair
        .public_key()
        .as_ref()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    // Two different routing tokens for the same identity
    let routing_token_1 = common::generate_test_client_id(10);
    let routing_token_2 = common::generate_test_client_id(20);

    let make_deps = |nonce_tracker: Arc<NonceTracker>| ConnectionDeps {
        storage: storage.clone() as Arc<dyn BlobStore>,
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        rate_limiter: shared_rate_limiter.clone(),
        recovery_rate_limiter: Arc::new(vauchi_relay::rate_limit::RateLimiter::new(10)),
        registry: registry.clone(),
        blob_sender_map: handler::new_blob_sender_map(),
        max_message_size: 1_048_576,
        idle_timeout: std::time::Duration::from_secs(5),
        quota: QuotaLimits {
            max_blobs: 100,
            max_bytes: 0,
        },
        hint_store: None,
        noise_static_key: Some(kp.private),
        nonce_tracker,
        delivery_jitter_min_ms: 0,
        delivery_jitter_max_ms: 0,
        relay_signing_key: None,
        metrics: RelayMetrics::new(),
    };

    // Connection 1: routing_token_1 with signed handshake — sends one blob (consumes the token)
    {
        let hs1 = make_signed_handshake_with_routing_token(&key_pair, &routing_token_1);
        let deps1 = make_deps(nonce_tracker.clone());
        let url1 = start_multi_server(deps1).await;
        let mut client1 = connect_noise(&url1, &relay_pub).await;

        let ack = client1.send_recv(&hs1).await;
        assert_eq!(
            ack["payload"]["type"], "HandshakeAck",
            "Connection 1 handshake failed"
        );

        // First message — should succeed (rate limit token consumed)
        let recipient_id = common::generate_test_client_id(99);
        let update = make_encrypted_update(&recipient_id, &[1, 2, 3]);
        let resp = client1.send_recv(&update).await;
        assert_eq!(
            resp["payload"]["status"], "Stored",
            "First message should be stored"
        );

        client1.close().await;
    }

    // Connection 2: routing_token_2 (different token, SAME signing key) — should be rate-limited
    // The nonce for the second handshake uses routing_token_2 bytes so it's unique.
    {
        let hs2 = make_signed_handshake_with_routing_token(&key_pair, &routing_token_2);
        let deps2 = make_deps(nonce_tracker.clone());
        let url2 = start_multi_server(deps2).await;
        let mut client2 = connect_noise(&url2, &relay_pub).await;

        let ack2 = client2.send_recv(&hs2).await;
        assert_eq!(
            ack2["payload"]["type"], "HandshakeAck",
            "Connection 2 handshake failed"
        );

        // Second message with same auth identity — rate limited because bucket is shared
        let recipient_id = common::generate_test_client_id(98);
        let update = make_encrypted_update(&recipient_id, &[4, 5, 6]);
        // No response expected (rate limited, connection stays open but message rejected)
        client2.send_envelope(&update).await;
        let resp = client2.try_recv().await;
        // The rate limiter rejects silently (continue in the loop) — no Ack arrives
        assert!(
            resp.is_none(),
            "Rate-limited message should produce no response; got: {:?}",
            resp
        );

        // Verify blob was NOT stored (rate limited before storage)
        assert_eq!(
            storage.peek(&recipient_id).len(),
            0,
            "Rate-limited message should not be stored"
        );

        client2.close().await;
    }

    // Sanity check: a client with a DIFFERENT signing key should NOT be rate-limited
    {
        let rng2 = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8_2 = Ed25519KeyPair::generate_pkcs8(&rng2).unwrap();
        let key_pair2 = Ed25519KeyPair::from_pkcs8(pkcs8_2.as_ref()).unwrap();

        let routing_token_3 = common::generate_test_client_id(30);
        let hs3 = make_signed_handshake_with_routing_token(&key_pair2, &routing_token_3);
        let deps3 = make_deps(nonce_tracker.clone());
        let url3 = start_multi_server(deps3).await;
        let mut client3 = connect_noise(&url3, &relay_pub).await;

        let ack3 = client3.send_recv(&hs3).await;
        assert_eq!(
            ack3["payload"]["type"], "HandshakeAck",
            "Connection 3 handshake failed"
        );

        let recipient_id2 = common::generate_test_client_id(97);
        let update3 = make_encrypted_update(&recipient_id2, &[7, 8, 9]);
        let resp3 = client3.send_recv(&update3).await;
        assert_eq!(
            resp3["payload"]["status"], "Stored",
            "Different auth identity should have its own rate-limit bucket"
        );

        client3.close().await;
    }
}

// @scenario: relay_network:Routing tokens enable anonymous addressing
#[tokio::test]
async fn test_routing_token_no_auth_required() {
    // routing_token mode should work without authentication
    let (deps, relay_pub, storage, _) = test_deps();
    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    let client_id = common::generate_test_client_id(1);
    let routing_token = common::generate_test_client_id(99);
    let hs = make_handshake_full(&client_id, None, Some(&routing_token), false);
    let ack = client.send_recv(&hs).await;

    assert_eq!(ack["payload"]["type"], "HandshakeAck");

    // Store a blob for a different recipient
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[1, 2, 3]);
    let response = client.send_recv(&update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    // Verify blob was stored under recipient_id
    let blobs = storage.peek(&recipient_id);
    assert_eq!(blobs.len(), 1);

    client.close().await;
}
