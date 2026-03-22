// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! WebSocket quota enforcement tests: blob count and byte limits.

mod common;

use std::sync::Arc;
use std::time::Duration;

use vauchi_relay::connection_registry::ConnectionRegistry;
use vauchi_relay::device_sync_storage::SqliteDeviceSyncStore;
use vauchi_relay::handler::{self, ConnectionDeps, QuotaLimits};
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::noise_key::generate_relay_keypair;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::recovery_storage::SqliteRecoveryProofStore;
use vauchi_relay::storage::{BlobStore, SqliteBlobStore};

use common::ws_helpers::*;

// @scenario: relay_network:Relay enforces storage quotas
#[tokio::test]
async fn test_quota_blob_count_exceeded() {
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let kp = generate_relay_keypair();
    let relay_pub = kp.public;
    let deps = ConnectionDeps {
        storage: storage.clone() as Arc<dyn BlobStore>,
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        device_sync_storage: Arc::new(SqliteDeviceSyncStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(1000)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(100)),
        registry: registry.clone(),
        blob_sender_map: handler::new_blob_sender_map(),
        max_message_size: 1_048_576,
        idle_timeout: Duration::from_secs(5),
        quota: QuotaLimits {
            max_blobs: 3, // Very low quota
            max_bytes: 0, // Unlimited bytes
        },
        hint_store: None,
        noise_static_key: Some(kp.private),
        nonce_tracker: Arc::new(handler::NonceTracker::new()),
        delivery_jitter_min_ms: 0,
        delivery_jitter_max_ms: 0,
        relay_signing_key: None,
        metrics: RelayMetrics::new(),
    };

    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    let client_id = common::generate_test_client_id(1);
    let _ack = client.do_handshake(&client_id).await;

    let recipient_id = common::generate_test_client_id(2);

    // Store 3 blobs (at limit)
    for _ in 0..3 {
        let update = make_encrypted_update(&recipient_id, &[1]);
        let response = client.send_recv(&update).await;
        assert_eq!(response["payload"]["status"], "Stored");
    }

    // 4th should be rejected
    let update = make_encrypted_update(&recipient_id, &[1]);
    let response = client.send_recv(&update).await;
    assert_eq!(response["payload"]["type"], "Acknowledgment");
    assert_eq!(response["payload"]["status"], "Failed");

    client.close().await;
}

// @scenario: relay_network:Relay enforces storage quotas
#[tokio::test]
async fn test_quota_byte_limit_exceeded() {
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let kp = generate_relay_keypair();
    let relay_pub = kp.public;
    let deps = ConnectionDeps {
        storage: storage.clone() as Arc<dyn BlobStore>,
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        device_sync_storage: Arc::new(SqliteDeviceSyncStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(1000)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(100)),
        registry: Arc::new(ConnectionRegistry::new()),
        blob_sender_map: handler::new_blob_sender_map(),
        max_message_size: 1_048_576,
        idle_timeout: Duration::from_secs(5),
        quota: QuotaLimits {
            max_blobs: 0,   // Unlimited count
            max_bytes: 200, // Very low byte limit
        },
        hint_store: None,
        noise_static_key: Some(kp.private),
        nonce_tracker: Arc::new(handler::NonceTracker::new()),
        delivery_jitter_min_ms: 0,
        delivery_jitter_max_ms: 0,
        relay_signing_key: None,
        metrics: RelayMetrics::new(),
    };

    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    let client_id = common::generate_test_client_id(1);
    let _ack = client.do_handshake(&client_id).await;

    let recipient_id = common::generate_test_client_id(2);

    // First blob: 100 bytes — should succeed
    let update = make_encrypted_update(&recipient_id, &[0u8; 100]);
    let response = client.send_recv(&update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    // Second blob: 100 bytes — should push over the limit
    let update = make_encrypted_update(&recipient_id, &[0u8; 100]);
    let response = client.send_recv(&update).await;
    assert_eq!(response["payload"]["status"], "Failed");

    client.close().await;
}
