// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! WebSocket delivery tests: multi-client concurrency, delivered acks,
//! suppress presence, routing tokens, and purge.

mod common;

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::accept_async;

use vauchi_relay::connection_registry::ConnectionRegistry;
use vauchi_relay::handler::{self, ConnectionDeps, QuotaLimits};
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::noise_key::generate_relay_keypair;
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
    let (deps, relay_pub, storage, _) = test_deps();
    let client_id = common::generate_test_client_id(1);

    // Pre-store some blobs under client_id (= the mailbox token for this test)
    storage.store(&client_id, StoredBlob::new(vec![1]));
    storage.store(&client_id, StoredBlob::new(vec![2]));
    storage.store(&client_id, StoredBlob::new(vec![3]));
    assert_eq!(storage.blob_count_for(&client_id), 3);

    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    // Handshake (will deliver pending blobs first)
    let hs = make_handshake(&client_id);
    client.send_envelope(&hs).await;

    // Drain HandshakeAck
    let _ = client.recv().await;

    // SP-33: Register mailbox token to trigger pending delivery
    let reg = make_register_mailbox(&[&client_id]);
    client.send_envelope(&reg).await;

    // Drain 3 pending blobs
    for _ in 0..3 {
        let _ = client.recv().await;
    }

    // SP-33: Purge request must use the actual mailbox token as purge_token.
    // Blobs are stored by mailbox token (recipient_id), so the purge_token must
    // match the token under which blobs were stored.
    let purge = make_purge_request_for_token(&client_id);
    let response = client.send_recv(&purge).await;

    assert_eq!(response["payload"]["type"], "PurgeResponse");
    // Counts no longer in response (T0-10) — verify via storage directly
    assert_eq!(storage.blob_count_for(&client_id), 0);

    client.close().await;
}

// @scenario: relay_network:Client purges stored data
#[tokio::test]
async fn test_purge_empty_returns_zero() {
    let (deps, relay_pub, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    let client_id = common::generate_test_client_id(1);
    let _ack = client.do_handshake(&client_id).await;

    let purge = make_purge_request();
    let response = client.send_recv(&purge).await;

    assert_eq!(response["payload"]["type"], "PurgeResponse");
    client.close().await;
}

// ============================================================================
// Tests: Routing token
// ============================================================================

// @scenario: relay_network:Routing tokens enable anonymous addressing
#[tokio::test]
async fn test_routing_token_used_for_storage() {
    let (deps, relay_pub, storage, _) = test_deps();
    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    let client_id = common::generate_test_client_id(1);
    let routing_token = common::generate_test_client_id(99);

    // Handshake with routing_token
    let hs = make_handshake_full(&client_id, None, Some(&routing_token), false);
    let ack = client.send_recv(&hs).await;
    assert_eq!(ack["payload"]["type"], "HandshakeAck");

    // Store a blob addressed to the routing_token (= the mailbox token)
    storage.store(&routing_token, StoredBlob::new(vec![42]));

    // SP-33: Purge using the routing_token as purge_token — blobs are stored
    // under the mailbox token (routing_token here), so the purge must target it.
    let purge = make_purge_request_for_token(&routing_token);
    let response = client.send_recv(&purge).await;
    assert_eq!(response["payload"]["type"], "PurgeResponse");

    // Verify purge worked via storage (counts no longer in response — T0-10)
    assert!(storage.peek(&client_id).is_empty());
    assert!(storage.peek(&routing_token).is_empty());

    client.close().await;
}

// ============================================================================
// Tests: Delivered ack via ConnectionRegistry
// ============================================================================

/// Creates a ConnectionDeps for multi-connection delivery tests.
fn make_shared_deps(
    storage: Arc<SqliteBlobStore>,
    registry: Arc<ConnectionRegistry>,
    blob_sender_map: handler::BlobSenderMap,
    noise_key: [u8; 32],
) -> ConnectionDeps {
    ConnectionDeps {
        storage: storage as Arc<dyn BlobStore>,
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(60)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(10)),
        registry,
        blob_sender_map,
        max_message_size: 1_048_576,
        idle_timeout: Duration::from_secs(5),
        quota: QuotaLimits {
            max_blobs: 100,
            max_bytes: 0,
        },
        hint_store: None,
        noise_static_key: Some(noise_key),
        nonce_tracker: Arc::new(handler::NonceTracker::new()),
        delivery_jitter_min_ms: 0,
        delivery_jitter_max_ms: 0,
        relay_signing_key: None,
        metrics: RelayMetrics::new(),
        mailbox_registry: std::sync::Arc::new(parking_lot::RwLock::new(
            vauchi_relay::mailbox_registry::MailboxRegistry::new(),
        )),
    }
}

// @scenario: message_delivery:Sender receives delivery confirmation
#[tokio::test]
async fn test_delivered_ack_to_sender() {
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let blob_sender_map = handler::new_blob_sender_map();
    let kp = generate_relay_keypair();

    // Start two servers (one for sender, one for recipient)
    let listener1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr1 = listener1.local_addr().unwrap();
    let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr2 = listener2.local_addr().unwrap();

    let deps1 = make_shared_deps(
        storage.clone(),
        registry.clone(),
        blob_sender_map.clone(),
        kp.private,
    );
    let deps2 = make_shared_deps(
        storage.clone(),
        registry.clone(),
        blob_sender_map.clone(),
        kp.private,
    );

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
    let url1 = format!("ws://127.0.0.1:{}", addr1.port());
    let mut sender = connect_noise(&url1, &kp.public).await;
    let _ack = sender.do_handshake(&sender_id).await;

    // 2. Sender stores a blob for recipient
    let update = make_encrypted_update(&recipient_id, &[1, 2, 3]);
    let stored_ack = sender.send_recv(&update).await;
    assert_eq!(stored_ack["payload"]["status"], "Stored");

    // 3. Connect recipient — should get pending blob + trigger Delivered to sender
    let url2 = format!("ws://127.0.0.1:{}", addr2.port());
    let mut recipient = connect_noise(&url2, &kp.public).await;

    let hs = make_handshake(&recipient_id);
    recipient.send_envelope(&hs).await;

    // Recipient gets HandshakeAck
    let ack = recipient.recv().await;
    assert_eq!(ack["payload"]["type"], "HandshakeAck");

    // SP-33: Register mailbox token to trigger pending delivery
    let reg = make_register_mailbox(&[&recipient_id]);
    recipient.send_envelope(&reg).await;

    // Recipient gets the blob delivery
    let blob = recipient.recv().await;
    assert_eq!(blob["payload"]["type"], "EncryptedUpdate");

    // 4. Sender should receive Delivered ack via registry
    let delivered = timeout(Duration::from_secs(2), async {
        loop {
            if let Some(msg) = sender.try_recv().await
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

    sender.close().await;
    recipient.close().await;
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
    let kp = generate_relay_keypair();

    let listener1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr1 = listener1.local_addr().unwrap();
    let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr2 = listener2.local_addr().unwrap();

    let deps1 = make_shared_deps(
        storage.clone(),
        registry.clone(),
        blob_sender_map.clone(),
        kp.private,
    );
    let deps2 = make_shared_deps(
        storage.clone(),
        registry.clone(),
        blob_sender_map.clone(),
        kp.private,
    );

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
    let url1 = format!("ws://127.0.0.1:{}", addr1.port());
    let mut sender = connect_noise(&url1, &kp.public).await;
    let _ack = sender.do_handshake(&sender_id).await;
    let update = make_encrypted_update(&recipient_id, &[1, 2, 3]);
    let stored_ack = sender.send_recv(&update).await;
    assert_eq!(stored_ack["payload"]["status"], "Stored");

    // Recipient connects WITH suppress_presence = true
    let url2 = format!("ws://127.0.0.1:{}", addr2.port());
    let mut recipient = connect_noise(&url2, &kp.public).await;
    let hs = make_handshake_full(&recipient_id, None, None, true);
    recipient.send_envelope(&hs).await;

    // Recipient gets HandshakeAck
    let _ack = recipient.recv().await;

    // SP-33: Register mailbox token to trigger pending delivery
    let reg = make_register_mailbox(&[&recipient_id]);
    recipient.send_envelope(&reg).await;

    let _blob = recipient.recv().await;

    // Verify sender does NOT receive Delivered ack (CC-06: try_recv has its own timeout)
    let msg = sender.try_recv().await;
    assert!(
        msg.is_none(),
        "Sender should NOT receive Delivered ack when recipient has suppress_presence"
    );

    sender.close().await;
    recipient.close().await;
}

// ============================================================================
// Tests: Multi-client concurrency
// ============================================================================

// @scenario: sync_updates:Pending updates delivered on connect
#[tokio::test]
async fn test_concurrent_store_and_receive() {
    let kp = generate_relay_keypair();
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let blob_sender_map = handler::new_blob_sender_map();

    let deps = make_shared_deps(
        storage.clone(),
        registry.clone(),
        blob_sender_map.clone(),
        kp.private,
    );
    let url = start_multi_server(deps).await;

    let sender_id = common::generate_test_client_id(1);
    let recipient_id = common::generate_test_client_id(2);

    // Connect sender
    let mut sender = connect_noise(&url, &kp.public).await;
    let _ack = sender.do_handshake(&sender_id).await;

    // Sender stores a blob for the recipient
    let update = make_encrypted_update(&recipient_id, &[1, 2, 3]);
    let stored_ack = sender.send_recv(&update).await;
    assert_eq!(stored_ack["payload"]["status"], "Stored");

    // Connect recipient — should get pending blob
    let mut recipient = connect_noise(&url, &kp.public).await;
    let hs = make_handshake(&recipient_id);
    recipient.send_envelope(&hs).await;

    // HandshakeAck
    let ack = recipient.recv().await;
    assert_eq!(ack["payload"]["type"], "HandshakeAck");

    // SP-33: Register mailbox token to trigger pending delivery
    let reg = make_register_mailbox(&[&recipient_id]);
    recipient.send_envelope(&reg).await;

    // Pending blob delivery
    let blob = recipient.recv().await;
    assert_eq!(blob["payload"]["type"], "EncryptedUpdate");
    let ciphertext = blob["payload"]["ciphertext"].as_array().unwrap();
    assert_eq!(
        ciphertext
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect::<Vec<_>>(),
        vec![1u8, 2, 3]
    );

    sender.close().await;
    recipient.close().await;
}

// @scenario: message_delivery:Sender receives delivery confirmation
#[tokio::test]
async fn test_received_by_recipient_after_delivered_not_forwarded() {
    let kp = generate_relay_keypair();
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let blob_sender_map = handler::new_blob_sender_map();

    let deps = make_shared_deps(
        storage.clone(),
        registry.clone(),
        blob_sender_map.clone(),
        kp.private,
    );
    let url = start_multi_server(deps).await;

    let sender_id = common::generate_test_client_id(1);
    let recipient_id = common::generate_test_client_id(2);

    // 1. Connect sender
    let mut sender = connect_noise(&url, &kp.public).await;
    let _ack = sender.do_handshake(&sender_id).await;

    // 2. Sender stores a blob for recipient
    let update = make_encrypted_update(&recipient_id, &[1, 2, 3]);
    let stored_ack = sender.send_recv(&update).await;
    assert_eq!(stored_ack["payload"]["status"], "Stored");

    // 3. Connect recipient — receives blob + sender gets Delivered ack
    let mut recipient = connect_noise(&url, &kp.public).await;
    let hs = make_handshake(&recipient_id);
    recipient.send_envelope(&hs).await;

    // Recipient: HandshakeAck
    let _ack = recipient.recv().await;

    // SP-33: Register mailbox token to trigger pending delivery
    let reg = make_register_mailbox(&[&recipient_id]);
    recipient.send_envelope(&reg).await;

    // Recipient: blob delivery
    let blob = recipient.recv().await;
    assert_eq!(blob["payload"]["type"], "EncryptedUpdate");
    let blob_id = blob["message_id"].as_str().unwrap().to_string();

    // Sender should get Delivered ack (via registry)
    let delivered = timeout(Duration::from_secs(2), async {
        loop {
            if let Some(msg) = sender.try_recv().await
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
    recipient.send_envelope(&rbr_ack).await;

    // Delivered ack already removed the blob_sender_map entry, so no further forwarding
    // CC-06: try_recv has its own 200ms timeout for absence check
    let msg = sender.try_recv().await;
    assert!(
        msg.is_none(),
        "ReceivedByRecipient should not be forwarded after Delivered already cleaned up sender map"
    );

    sender.close().await;
    recipient.close().await;
}

// @scenario: relay_network:Suppress presence hides delivery notifications
#[tokio::test]
async fn test_suppress_presence_blocks_received_by_recipient() {
    let kp = generate_relay_keypair();
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let blob_sender_map = handler::new_blob_sender_map();

    let deps = make_shared_deps(
        storage.clone(),
        registry.clone(),
        blob_sender_map.clone(),
        kp.private,
    );
    let url = start_multi_server(deps).await;

    let sender_id = common::generate_test_client_id(1);
    let recipient_id = common::generate_test_client_id(2);

    // 1. Connect sender
    let mut sender = connect_noise(&url, &kp.public).await;
    let _ack = sender.do_handshake(&sender_id).await;

    // 2. Sender stores a blob
    let update = make_encrypted_update(&recipient_id, &[1, 2, 3]);
    let stored_ack = sender.send_recv(&update).await;
    assert_eq!(stored_ack["payload"]["status"], "Stored");

    // 3. Recipient connects WITH suppress_presence = true
    let mut recipient = connect_noise(&url, &kp.public).await;
    let hs = make_handshake_full(&recipient_id, None, None, true);
    recipient.send_envelope(&hs).await;

    let _ack = recipient.recv().await;

    // SP-33: Register mailbox token to trigger pending delivery
    let reg = make_register_mailbox(&[&recipient_id]);
    recipient.send_envelope(&reg).await;

    let blob = recipient.recv().await;
    assert_eq!(blob["payload"]["type"], "EncryptedUpdate");
    let blob_id = blob["message_id"].as_str().unwrap().to_string();

    // CC-06: try_recv has its own 200ms timeout for absence check
    let msg = sender.try_recv().await;
    assert!(
        msg.is_none(),
        "Sender should NOT receive Delivered ack with suppress_presence"
    );

    // 4. Recipient sends ReceivedByRecipient ack
    let rbr_ack = make_ack(&blob_id, "ReceivedByRecipient");
    recipient.send_envelope(&rbr_ack).await;

    // CC-06: try_recv has its own 200ms timeout for absence check
    let msg = sender.try_recv().await;
    assert!(
        msg.is_none(),
        "Sender should NOT receive ReceivedByRecipient with suppress_presence"
    );

    sender.close().await;
    recipient.close().await;
}
