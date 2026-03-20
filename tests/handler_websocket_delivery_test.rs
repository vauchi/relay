// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! WebSocket delivery tests: multi-client concurrency, delivered acks,
//! suppress presence, routing tokens, and purge.

mod common;

use std::sync::Arc;
use std::time::Duration;

use futures_util::SinkExt;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

use vauchi_relay::connection_registry::ConnectionRegistry;
use vauchi_relay::device_sync_storage::SqliteDeviceSyncStore;
use vauchi_relay::handler::{self, ConnectionDeps, QuotaLimits};
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::recovery_storage::SqliteRecoveryProofStore;
use vauchi_relay::storage::{BlobStore, SqliteBlobStore, StoredBlob};

use common::ws_helpers::*;

// ============================================================================
// Tests: Purge
// ============================================================================

// @scenario: relay_network:Client purges stored data
#[tokio::test]
async fn test_purge_deletes_blobs() {
    let (deps, storage, _) = test_deps();
    let client_id = common::generate_test_client_id(1);

    // Pre-store some blobs
    storage.store(&client_id, StoredBlob::new(vec![1]));
    storage.store(&client_id, StoredBlob::new(vec![2]));
    storage.store(&client_id, StoredBlob::new(vec![3]));
    assert_eq!(storage.blob_count_for(&client_id), 3);

    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Handshake (will deliver pending blobs first)
    let hs = make_handshake(&client_id);
    ws.send(Message::Binary(encode_envelope(&hs)))
        .await
        .unwrap();

    // Drain HandshakeAck + 3 pending blobs
    for _ in 0..4 {
        let _ = recv(&mut ws).await;
    }

    // Send purge request
    let purge = make_purge_request(false);
    let response = send_recv(&mut ws, &purge).await;

    assert_eq!(response["payload"]["type"], "PurgeResponse");
    // Blobs were already peeked (not removed), so purge should still delete them
    // Actually peek doesn't remove, so they should still be there for purge
    let blobs_deleted = response["payload"]["blobs_deleted"].as_u64().unwrap();
    assert_eq!(blobs_deleted, 3);
    assert_eq!(storage.blob_count_for(&client_id), 0);

    ws.close(None).await.ok();
}

// @scenario: relay_network:Client purges stored data
#[tokio::test]
async fn test_purge_empty_returns_zero() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    let purge = make_purge_request(false);
    let response = send_recv(&mut ws, &purge).await;

    assert_eq!(response["payload"]["type"], "PurgeResponse");
    assert_eq!(response["payload"]["blobs_deleted"], 0);
    assert_eq!(response["payload"]["device_sync_deleted"], 0);

    ws.close(None).await.ok();
}

// ============================================================================
// Tests: Routing token
// ============================================================================

// @scenario: relay_network:Routing tokens enable anonymous addressing
#[tokio::test]
async fn test_routing_token_used_for_storage() {
    let (deps, storage, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let routing_token = common::generate_test_client_id(99);

    // Handshake with routing_token
    let hs = make_handshake_full(&client_id, None, Some(&routing_token), false);
    let ack = send_recv(&mut ws, &hs).await;
    assert_eq!(ack["payload"]["type"], "HandshakeAck");

    // Store a blob addressed to the routing_token
    // (Simulate another client storing a blob for the routing token recipient)
    storage.store(&routing_token, StoredBlob::new(vec![42]));

    // The client connected with that routing_token should be able to purge it
    let purge = make_purge_request(false);
    let response = send_recv(&mut ws, &purge).await;
    assert_eq!(response["payload"]["blobs_deleted"], 1);

    // Original client_id should have no blobs
    assert!(storage.peek(&client_id).is_empty());
    assert!(storage.peek(&routing_token).is_empty());

    ws.close(None).await.ok();
}

// ============================================================================
// Tests: Delivered ack via ConnectionRegistry
// ============================================================================

// @scenario: message_delivery:Sender receives delivery confirmation
#[tokio::test]
async fn test_delivered_ack_to_sender() {
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let blob_sender_map = handler::new_blob_sender_map();

    // Start two servers (one for sender, one for recipient)
    let listener1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr1 = listener1.local_addr().unwrap();
    let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr2 = listener2.local_addr().unwrap();

    let deps1 = ConnectionDeps {
        storage: storage.clone(),
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        device_sync_storage: Arc::new(SqliteDeviceSyncStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(60)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(10)),
        registry: registry.clone(),
        blob_sender_map: blob_sender_map.clone(),
        max_message_size: 1_048_576,
        idle_timeout: Duration::from_secs(5),
        quota: QuotaLimits {
            max_blobs: 100,
            max_bytes: 0,
        },
        hint_store: None,
        noise_static_key: None,
        require_noise_encryption: false,
        nonce_tracker: Arc::new(handler::NonceTracker::new()),
        delivery_jitter_min_ms: 0,
        delivery_jitter_max_ms: 0,
        relay_signing_key: None,
        metrics: RelayMetrics::new(),
    };
    let deps2 = ConnectionDeps {
        storage: storage.clone(),
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        device_sync_storage: Arc::new(SqliteDeviceSyncStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(60)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(10)),
        registry: registry.clone(),
        blob_sender_map: blob_sender_map.clone(),
        max_message_size: 1_048_576,
        idle_timeout: Duration::from_secs(5),
        quota: QuotaLimits {
            max_blobs: 100,
            max_bytes: 0,
        },
        hint_store: None,
        noise_static_key: None,
        require_noise_encryption: false,
        nonce_tracker: Arc::new(handler::NonceTracker::new()),
        delivery_jitter_min_ms: 0,
        delivery_jitter_max_ms: 0,
        relay_signing_key: None,
        metrics: RelayMetrics::new(),
    };

    // Spawn both servers
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener1.accept().await
            && let Ok(ws) = accept_async(stream).await
        {
            handler::handle_connection(ws, deps1).await;
        }
    });
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener2.accept().await
            && let Ok(ws) = accept_async(stream).await
        {
            handler::handle_connection(ws, deps2).await;
        }
    });

    let sender_id = common::generate_test_client_id(1);
    let recipient_id = common::generate_test_client_id(2);

    // 1. Connect sender
    let (mut sender_ws, _) = connect_async(format!("ws://127.0.0.1:{}", addr1.port()))
        .await
        .unwrap();
    let _ack = do_handshake(&mut sender_ws, &sender_id).await;

    // 2. Sender stores a blob for recipient
    let update = make_encrypted_update(&recipient_id, &[1, 2, 3]);
    let stored_ack = send_recv(&mut sender_ws, &update).await;
    assert_eq!(stored_ack["payload"]["status"], "Stored");

    // 3. Connect recipient — should get pending blob + trigger Delivered to sender
    let (mut recipient_ws, _) = connect_async(format!("ws://127.0.0.1:{}", addr2.port()))
        .await
        .unwrap();

    let hs = make_handshake(&recipient_id);
    recipient_ws
        .send(Message::Binary(encode_envelope(&hs)))
        .await
        .unwrap();

    // Recipient gets HandshakeAck
    let ack = recv(&mut recipient_ws).await;
    assert_eq!(ack["payload"]["type"], "HandshakeAck");

    // Recipient gets the blob delivery
    let blob = recv(&mut recipient_ws).await;
    assert_eq!(blob["payload"]["type"], "EncryptedUpdate");

    // 4. Sender should receive Delivered ack via registry
    let delivered = timeout(Duration::from_secs(2), async {
        loop {
            if let Some(msg) = try_recv(&mut sender_ws).await
                && msg["payload"]["type"] == "Acknowledgment"
                && msg["payload"]["status"] == "Delivered"
            {
                return msg;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("Should receive Delivered ack");

    assert_eq!(delivered["payload"]["status"], "Delivered");

    sender_ws.close(None).await.ok();
    recipient_ws.close(None).await.ok();
}

// ============================================================================
// Tests: Suppress presence
// ============================================================================

// @scenario: relay_network:Suppress presence hides delivery notifications
#[tokio::test]
async fn test_suppress_presence_no_delivered_ack() {
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let blob_sender_map = handler::new_blob_sender_map();

    let listener1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr1 = listener1.local_addr().unwrap();
    let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr2 = listener2.local_addr().unwrap();

    let deps1 = ConnectionDeps {
        storage: storage.clone(),
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        device_sync_storage: Arc::new(SqliteDeviceSyncStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(60)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(10)),
        registry: registry.clone(),
        blob_sender_map: blob_sender_map.clone(),
        max_message_size: 1_048_576,
        idle_timeout: Duration::from_secs(5),
        quota: QuotaLimits {
            max_blobs: 100,
            max_bytes: 0,
        },
        hint_store: None,
        noise_static_key: None,
        require_noise_encryption: false,
        nonce_tracker: Arc::new(handler::NonceTracker::new()),
        delivery_jitter_min_ms: 0,
        delivery_jitter_max_ms: 0,
        relay_signing_key: None,
        metrics: RelayMetrics::new(),
    };
    let deps2 = ConnectionDeps {
        storage: storage.clone(),
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        device_sync_storage: Arc::new(SqliteDeviceSyncStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(60)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(10)),
        registry: registry.clone(),
        blob_sender_map: blob_sender_map.clone(),
        max_message_size: 1_048_576,
        idle_timeout: Duration::from_secs(5),
        quota: QuotaLimits {
            max_blobs: 100,
            max_bytes: 0,
        },
        hint_store: None,
        noise_static_key: None,
        require_noise_encryption: false,
        nonce_tracker: Arc::new(handler::NonceTracker::new()),
        delivery_jitter_min_ms: 0,
        delivery_jitter_max_ms: 0,
        relay_signing_key: None,
        metrics: RelayMetrics::new(),
    };

    tokio::spawn(async move {
        if let Ok((stream, _)) = listener1.accept().await
            && let Ok(ws) = accept_async(stream).await
        {
            handler::handle_connection(ws, deps1).await;
        }
    });
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener2.accept().await
            && let Ok(ws) = accept_async(stream).await
        {
            handler::handle_connection(ws, deps2).await;
        }
    });

    let sender_id = common::generate_test_client_id(1);
    let recipient_id = common::generate_test_client_id(2);

    // Sender connects and stores a blob
    let (mut sender_ws, _) = connect_async(format!("ws://127.0.0.1:{}", addr1.port()))
        .await
        .unwrap();
    let _ack = do_handshake(&mut sender_ws, &sender_id).await;
    let update = make_encrypted_update(&recipient_id, &[1, 2, 3]);
    let stored_ack = send_recv(&mut sender_ws, &update).await;
    assert_eq!(stored_ack["payload"]["status"], "Stored");

    // Recipient connects WITH suppress_presence = true
    let (mut recipient_ws, _) = connect_async(format!("ws://127.0.0.1:{}", addr2.port()))
        .await
        .unwrap();
    let hs = make_handshake_full(&recipient_id, None, None, true);
    recipient_ws
        .send(Message::Binary(encode_envelope(&hs)))
        .await
        .unwrap();

    // Recipient gets HandshakeAck + blob
    let _ack = recv(&mut recipient_ws).await;
    let _blob = recv(&mut recipient_ws).await;

    // Verify sender does NOT receive Delivered ack (CC-06: try_recv has its own timeout)
    let msg = try_recv(&mut sender_ws).await;
    assert!(
        msg.is_none(),
        "Sender should NOT receive Delivered ack when recipient has suppress_presence"
    );

    sender_ws.close(None).await.ok();
    recipient_ws.close(None).await.ok();
}

// ============================================================================
// Tests: Multi-client concurrency
// ============================================================================

// @scenario: sync_updates:Pending updates delivered on connect
#[tokio::test]
async fn test_concurrent_store_and_receive() {
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let blob_sender_map = handler::new_blob_sender_map();

    let make_deps = |s: Arc<SqliteBlobStore>,
                     r: Arc<ConnectionRegistry>,
                     bsm: handler::BlobSenderMap|
     -> ConnectionDeps {
        ConnectionDeps {
            storage: s as Arc<dyn BlobStore>,
            recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
            device_sync_storage: Arc::new(SqliteDeviceSyncStore::in_memory().unwrap()),
            rate_limiter: Arc::new(RateLimiter::new(60)),
            recovery_rate_limiter: Arc::new(RateLimiter::new(10)),
            registry: r,
            blob_sender_map: bsm,
            max_message_size: 1_048_576,
            idle_timeout: Duration::from_secs(5),
            quota: QuotaLimits {
                max_blobs: 100,
                max_bytes: 0,
            },
            hint_store: None,
            noise_static_key: None,
            require_noise_encryption: false,
            nonce_tracker: Arc::new(handler::NonceTracker::new()),
            delivery_jitter_min_ms: 0,
            delivery_jitter_max_ms: 0,
            relay_signing_key: None,
            metrics: RelayMetrics::new(),
        }
    };

    let deps = make_deps(storage.clone(), registry.clone(), blob_sender_map.clone());
    let url = start_multi_server(deps).await;

    let sender_id = common::generate_test_client_id(1);
    let recipient_id = common::generate_test_client_id(2);

    // Connect sender
    let (mut sender_ws, _) = connect_async(&url).await.unwrap();
    let _ack = do_handshake(&mut sender_ws, &sender_id).await;

    // Sender stores a blob for the recipient
    let update = make_encrypted_update(&recipient_id, &[1, 2, 3]);
    let stored_ack = send_recv(&mut sender_ws, &update).await;
    assert_eq!(stored_ack["payload"]["status"], "Stored");

    // Connect recipient — should get pending blob
    let (mut recipient_ws, _) = connect_async(&url).await.unwrap();
    let hs = make_handshake(&recipient_id);
    recipient_ws
        .send(Message::Binary(encode_envelope(&hs)))
        .await
        .unwrap();

    // HandshakeAck
    let ack = recv(&mut recipient_ws).await;
    assert_eq!(ack["payload"]["type"], "HandshakeAck");

    // Pending blob delivery
    let blob = recv(&mut recipient_ws).await;
    assert_eq!(blob["payload"]["type"], "EncryptedUpdate");
    assert_eq!(blob["payload"]["ciphertext"], json!([1, 2, 3]));

    sender_ws.close(None).await.ok();
    recipient_ws.close(None).await.ok();
}

// @scenario: message_delivery:Sender receives delivery confirmation
#[tokio::test]
async fn test_received_by_recipient_after_delivered_not_forwarded() {
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let blob_sender_map = handler::new_blob_sender_map();

    let make_deps = |s: Arc<SqliteBlobStore>,
                     r: Arc<ConnectionRegistry>,
                     bsm: handler::BlobSenderMap|
     -> ConnectionDeps {
        ConnectionDeps {
            storage: s as Arc<dyn BlobStore>,
            recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
            device_sync_storage: Arc::new(SqliteDeviceSyncStore::in_memory().unwrap()),
            rate_limiter: Arc::new(RateLimiter::new(60)),
            recovery_rate_limiter: Arc::new(RateLimiter::new(10)),
            registry: r,
            blob_sender_map: bsm,
            max_message_size: 1_048_576,
            idle_timeout: Duration::from_secs(5),
            quota: QuotaLimits {
                max_blobs: 100,
                max_bytes: 0,
            },
            hint_store: None,
            noise_static_key: None,
            require_noise_encryption: false,
            nonce_tracker: Arc::new(handler::NonceTracker::new()),
            delivery_jitter_min_ms: 0,
            delivery_jitter_max_ms: 0,
            relay_signing_key: None,
            metrics: RelayMetrics::new(),
        }
    };

    let deps = make_deps(storage.clone(), registry.clone(), blob_sender_map.clone());
    let url = start_multi_server(deps).await;

    let sender_id = common::generate_test_client_id(1);
    let recipient_id = common::generate_test_client_id(2);

    // 1. Connect sender
    let (mut sender_ws, _) = connect_async(&url).await.unwrap();
    let _ack = do_handshake(&mut sender_ws, &sender_id).await;

    // 2. Sender stores a blob for recipient
    let update = make_encrypted_update(&recipient_id, &[1, 2, 3]);
    let stored_ack = send_recv(&mut sender_ws, &update).await;
    assert_eq!(stored_ack["payload"]["status"], "Stored");

    // 3. Connect recipient — receives blob + sender gets Delivered ack
    let (mut recipient_ws, _) = connect_async(&url).await.unwrap();
    let hs = make_handshake(&recipient_id);
    recipient_ws
        .send(Message::Binary(encode_envelope(&hs)))
        .await
        .unwrap();

    // Recipient: HandshakeAck
    let _ack = recv(&mut recipient_ws).await;
    // Recipient: blob delivery
    let blob = recv(&mut recipient_ws).await;
    assert_eq!(blob["payload"]["type"], "EncryptedUpdate");
    let blob_id = blob["message_id"].as_str().unwrap().to_string();

    // Sender should get Delivered ack (via registry)
    let delivered = timeout(Duration::from_secs(2), async {
        loop {
            if let Some(msg) = try_recv(&mut sender_ws).await
                && msg["payload"]["type"] == "Acknowledgment"
                && msg["payload"]["status"] == "Delivered"
            {
                return msg;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("Should receive Delivered ack");
    assert_eq!(delivered["payload"]["status"], "Delivered");

    // 4. Recipient sends ReceivedByRecipient ack
    let rbr_ack = make_ack(&blob_id, "ReceivedByRecipient");
    recipient_ws
        .send(Message::Binary(encode_envelope(&rbr_ack)))
        .await
        .unwrap();

    // Note: The Delivered ack path (line 572 of handler.rs) already removed
    // the blob_sender_map entry, so ReceivedByRecipient cannot be forwarded
    // for blobs that were delivered from the pending queue. This is by design —
    // delivery notifications are ephemeral and one-shot.
    // CC-06: try_recv has its own 200ms timeout for absence check
    let msg = try_recv(&mut sender_ws).await;
    assert!(
        msg.is_none(),
        "ReceivedByRecipient should not be forwarded after Delivered already cleaned up sender map"
    );

    sender_ws.close(None).await.ok();
    recipient_ws.close(None).await.ok();
}

// @scenario: relay_network:Suppress presence hides delivery notifications
#[tokio::test]
async fn test_suppress_presence_blocks_received_by_recipient() {
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let blob_sender_map = handler::new_blob_sender_map();

    let make_deps = |s: Arc<SqliteBlobStore>,
                     r: Arc<ConnectionRegistry>,
                     bsm: handler::BlobSenderMap|
     -> ConnectionDeps {
        ConnectionDeps {
            storage: s as Arc<dyn BlobStore>,
            recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
            device_sync_storage: Arc::new(SqliteDeviceSyncStore::in_memory().unwrap()),
            rate_limiter: Arc::new(RateLimiter::new(60)),
            recovery_rate_limiter: Arc::new(RateLimiter::new(10)),
            registry: r,
            blob_sender_map: bsm,
            max_message_size: 1_048_576,
            idle_timeout: Duration::from_secs(5),
            quota: QuotaLimits {
                max_blobs: 100,
                max_bytes: 0,
            },
            hint_store: None,
            noise_static_key: None,
            require_noise_encryption: false,
            nonce_tracker: Arc::new(handler::NonceTracker::new()),
            delivery_jitter_min_ms: 0,
            delivery_jitter_max_ms: 0,
            relay_signing_key: None,
            metrics: RelayMetrics::new(),
        }
    };

    let deps = make_deps(storage.clone(), registry.clone(), blob_sender_map.clone());
    let url = start_multi_server(deps).await;

    let sender_id = common::generate_test_client_id(1);
    let recipient_id = common::generate_test_client_id(2);

    // 1. Connect sender
    let (mut sender_ws, _) = connect_async(&url).await.unwrap();
    let _ack = do_handshake(&mut sender_ws, &sender_id).await;

    // 2. Sender stores a blob
    let update = make_encrypted_update(&recipient_id, &[1, 2, 3]);
    let stored_ack = send_recv(&mut sender_ws, &update).await;
    assert_eq!(stored_ack["payload"]["status"], "Stored");

    // 3. Recipient connects WITH suppress_presence = true
    let (mut recipient_ws, _) = connect_async(&url).await.unwrap();
    let hs = make_handshake_full(&recipient_id, None, None, true);
    recipient_ws
        .send(Message::Binary(encode_envelope(&hs)))
        .await
        .unwrap();

    let _ack = recv(&mut recipient_ws).await;
    let blob = recv(&mut recipient_ws).await;
    assert_eq!(blob["payload"]["type"], "EncryptedUpdate");
    let blob_id = blob["message_id"].as_str().unwrap().to_string();

    // CC-06: try_recv has its own 200ms timeout for absence check
    let msg = try_recv(&mut sender_ws).await;
    assert!(
        msg.is_none(),
        "Sender should NOT receive Delivered ack with suppress_presence"
    );

    // 4. Recipient sends ReceivedByRecipient ack
    let rbr_ack = make_ack(&blob_id, "ReceivedByRecipient");
    recipient_ws
        .send(Message::Binary(encode_envelope(&rbr_ack)))
        .await
        .unwrap();

    // Sender should NOT receive forwarded ReceivedByRecipient either
    // CC-06: try_recv has its own 200ms timeout for absence check
    let msg = try_recv(&mut sender_ws).await;
    assert!(
        msg.is_none(),
        "Sender should NOT receive ReceivedByRecipient with suppress_presence"
    );

    sender_ws.close(None).await.ok();
    recipient_ws.close(None).await.ok();
}
