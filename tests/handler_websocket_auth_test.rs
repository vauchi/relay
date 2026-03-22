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
use vauchi_relay::device_sync_storage::SqliteDeviceSyncStore;
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
        device_sync_storage: Arc::new(SqliteDeviceSyncStore::in_memory().unwrap()),
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
        device_sync_storage: Arc::new(SqliteDeviceSyncStore::in_memory().unwrap()),
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
