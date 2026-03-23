// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Multi-device forwarding integration tests (SP-12b).
//!
//! Verifies that the relay correctly handles multiple devices for a single
//! identity: blob delivery, ACK forwarding, and per-device tracking.

mod common;

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::time::timeout;

use vauchi_relay::connection_registry::ConnectionRegistry;
use vauchi_relay::handler::{self, ConnectionDeps, QuotaLimits};
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::noise_key::generate_relay_keypair;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::recovery_storage::SqliteRecoveryProofStore;
use vauchi_relay::storage::{BlobStore, SqliteBlobStore};

use common::ws_helpers::{
    NoiseClient, connect_noise, make_ack, make_encrypted_update, make_handshake,
    make_register_mailbox,
};

// ============================================================================
// Test infrastructure
// ============================================================================

/// Creates shared deps for multi-connection tests.
/// Returns (storage, registry, blob_sender_map, noise_private_key, noise_public_key).
fn shared_deps() -> (
    Arc<SqliteBlobStore>,
    Arc<ConnectionRegistry>,
    handler::BlobSenderMap,
    [u8; 32],
    [u8; 32],
) {
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let blob_sender_map = handler::new_blob_sender_map();
    let kp = generate_relay_keypair();
    (storage, registry, blob_sender_map, kp.private, kp.public)
}

/// Creates ConnectionDeps from shared components.
fn make_deps(
    storage: Arc<SqliteBlobStore>,
    registry: Arc<ConnectionRegistry>,
    blob_sender_map: handler::BlobSenderMap,
    noise_private_key: [u8; 32],
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
        noise_static_key: Some(noise_private_key),
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

/// Spawns a single-connection test server and returns its URL.
async fn spawn_handler(deps: ConnectionDeps) -> String {
    use tokio_tungstenite::accept_async;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://127.0.0.1:{}", addr.port());
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await
            && let Ok(ws) = accept_async(stream).await
        {
            handler::handle_connection(ws, deps).await;
        }
    });
    url
}

// ============================================================================
// Tests: Multi-device blob delivery
// ============================================================================

// @scenario: message_delivery.feature:Message delivered to all registered devices
#[tokio::test]
async fn test_message_forwarded_to_all_connected_devices() {
    let (storage, registry, sender_map, noise_priv, noise_pub) = shared_deps();

    let sender_id = common::generate_test_client_id(1);
    let recipient_id = common::generate_test_client_id(2);

    // Spawn 3 handlers: sender + 2 recipient devices
    let sender_url = spawn_handler(make_deps(
        storage.clone(),
        registry.clone(),
        sender_map.clone(),
        noise_priv,
    ))
    .await;
    let device1_url = spawn_handler(make_deps(
        storage.clone(),
        registry.clone(),
        sender_map.clone(),
        noise_priv,
    ))
    .await;
    let device2_url = spawn_handler(make_deps(
        storage.clone(),
        registry.clone(),
        sender_map.clone(),
        noise_priv,
    ))
    .await;

    // 1. Connect sender and store a blob for recipient
    let mut sender = connect_noise(&sender_url, &noise_pub).await;
    let _ack = sender.do_handshake(&sender_id).await;

    let update = make_encrypted_update(&recipient_id, &[10, 20, 30]);
    let stored_ack = sender.send_recv(&update).await;
    assert_eq!(
        stored_ack["payload"]["status"], "Stored",
        "Sender should receive Stored ack"
    );

    // 2. Connect device-1 with recipient's routing_id → should get the blob
    let mut device1: NoiseClient = connect_noise(&device1_url, &noise_pub).await;
    let hs = make_handshake(&recipient_id);
    device1.send_envelope(&hs).await;
    let ack1 = device1.recv().await;
    assert_eq!(ack1["payload"]["type"], "HandshakeAck");
    let reg = make_register_mailbox(&[&recipient_id]);
    device1.send_envelope(&reg).await;
    let blob1 = device1.recv().await;
    assert_eq!(
        blob1["payload"]["type"], "EncryptedUpdate",
        "Device-1 should receive the pending blob"
    );

    // 3. Connect device-2 with SAME routing_id → should also get the blob
    //    (blob stays in storage until acknowledged)
    let mut device2: NoiseClient = connect_noise(&device2_url, &noise_pub).await;
    let hs = make_handshake(&recipient_id);
    device2.send_envelope(&hs).await;
    let ack2 = device2.recv().await;
    assert_eq!(ack2["payload"]["type"], "HandshakeAck");
    let reg = make_register_mailbox(&[&recipient_id]);
    device2.send_envelope(&reg).await;
    let blob2 = device2.recv().await;
    assert_eq!(
        blob2["payload"]["type"], "EncryptedUpdate",
        "Device-2 should also receive the pending blob (not yet acknowledged)"
    );

    // Both devices received the same ciphertext
    assert_eq!(
        blob1["payload"]["ciphertext"], blob2["payload"]["ciphertext"],
        "Both devices should receive identical ciphertext"
    );

    sender.close().await;
    device1.close().await;
    device2.close().await;
}

// @scenario: message_delivery.feature:Partial delivery tracked per device
#[tokio::test]
async fn test_partial_delivery_when_one_device_offline() {
    let (storage, registry, sender_map, noise_priv, noise_pub) = shared_deps();

    let sender_id = common::generate_test_client_id(3);
    let recipient_id = common::generate_test_client_id(4);

    // Spawn only sender + one device (device-2 stays offline)
    let sender_url = spawn_handler(make_deps(
        storage.clone(),
        registry.clone(),
        sender_map.clone(),
        noise_priv,
    ))
    .await;
    let device1_url = spawn_handler(make_deps(
        storage.clone(),
        registry.clone(),
        sender_map.clone(),
        noise_priv,
    ))
    .await;

    // 1. Sender stores blob
    let mut sender = connect_noise(&sender_url, &noise_pub).await;
    let _ack = sender.do_handshake(&sender_id).await;
    let update = make_encrypted_update(&recipient_id, &[40, 50, 60]);
    let stored = sender.send_recv(&update).await;
    assert_eq!(stored["payload"]["status"], "Stored");

    // 2. Device-1 connects and receives the blob
    let mut device1: NoiseClient = connect_noise(&device1_url, &noise_pub).await;
    let hs = make_handshake(&recipient_id);
    device1.send_envelope(&hs).await;
    let _ack = device1.recv().await;
    let reg = make_register_mailbox(&[&recipient_id]);
    device1.send_envelope(&reg).await;
    let blob = device1.recv().await;
    assert_eq!(
        blob["payload"]["type"], "EncryptedUpdate",
        "Online device should receive the blob"
    );

    // 3. Blob should still be in storage (not yet acknowledged by any device)
    let pending = storage.peek(&recipient_id);
    assert_eq!(
        pending.len(),
        1,
        "Blob should remain in storage until acknowledged (offline device can still retrieve it)"
    );

    sender.close().await;
    device1.close().await;
}

// @scenario: message_delivery.feature:All-delivered only when every device acknowledges
#[tokio::test]
async fn test_blob_removed_only_after_device_acknowledges() {
    let (storage, registry, sender_map, noise_priv, noise_pub) = shared_deps();

    let sender_id = common::generate_test_client_id(5);
    let recipient_id = common::generate_test_client_id(6);

    let sender_url = spawn_handler(make_deps(
        storage.clone(),
        registry.clone(),
        sender_map.clone(),
        noise_priv,
    ))
    .await;
    let device1_url = spawn_handler(make_deps(
        storage.clone(),
        registry.clone(),
        sender_map.clone(),
        noise_priv,
    ))
    .await;

    // 1. Sender stores blob
    let mut sender = connect_noise(&sender_url, &noise_pub).await;
    let _ack = sender.do_handshake(&sender_id).await;
    let update = make_encrypted_update(&recipient_id, &[70, 80, 90]);
    let stored = sender.send_recv(&update).await;
    assert_eq!(stored["payload"]["status"], "Stored");

    // 2. Device-1 connects and gets the blob
    let mut device1: NoiseClient = connect_noise(&device1_url, &noise_pub).await;
    let hs = make_handshake(&recipient_id);
    device1.send_envelope(&hs).await;
    let _ack = device1.recv().await;
    let reg = make_register_mailbox(&[&recipient_id]);
    device1.send_envelope(&reg).await;
    let blob = device1.recv().await;
    assert_eq!(blob["payload"]["type"], "EncryptedUpdate");

    // Extract the blob_id from the delivery envelope's message_id
    let blob_id = blob["message_id"]
        .as_str()
        .expect("blob delivery envelope should have message_id")
        .to_string();

    // 3. Before acknowledgment: blob still in storage
    assert_eq!(
        storage.peek(&recipient_id).len(),
        1,
        "Blob should persist until acknowledged"
    );

    // 4. Device-1 sends ReceivedByRecipient acknowledgment
    let ack_msg = make_ack(&blob_id, "ReceivedByRecipient");
    device1.send_envelope(&ack_msg).await;

    // Poll until handler processes the ack (CC-06: no bare sleeps)
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if storage.peek(&recipient_id).is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Timed out: blob should be removed after device acknowledges");

    // 5. After acknowledgment: blob removed from storage
    assert_eq!(
        storage.peek(&recipient_id).len(),
        0,
        "Blob should be removed after device acknowledges"
    );

    sender.close().await;
    device1.close().await;
}

// ============================================================================
// Tests: Registry multi-device ACK forwarding
// ============================================================================

// @scenario: message_delivery.feature:Delivery notifications reach all sender devices
#[tokio::test]
async fn test_registry_forwards_ack_to_all_sender_devices() {
    let (storage, registry, sender_map, noise_priv, noise_pub) = shared_deps();

    let sender_id = common::generate_test_client_id(7);
    let recipient_id = common::generate_test_client_id(8);

    // Sender has TWO devices, recipient has one
    let sender_dev1_url = spawn_handler(make_deps(
        storage.clone(),
        registry.clone(),
        sender_map.clone(),
        noise_priv,
    ))
    .await;
    let sender_dev2_url = spawn_handler(make_deps(
        storage.clone(),
        registry.clone(),
        sender_map.clone(),
        noise_priv,
    ))
    .await;
    let recipient_url = spawn_handler(make_deps(
        storage.clone(),
        registry.clone(),
        sender_map.clone(),
        noise_priv,
    ))
    .await;

    // 1. Connect sender device-1
    let mut sender1 = connect_noise(&sender_dev1_url, &noise_pub).await;
    let _ack = sender1.do_handshake(&sender_id).await;

    // 2. Connect sender device-2 (same identity/routing_id)
    let mut sender2 = connect_noise(&sender_dev2_url, &noise_pub).await;
    let _ack = sender2.do_handshake(&sender_id).await;

    // 3. Sender device-1 stores a blob for recipient
    let update = make_encrypted_update(&recipient_id, &[1, 2, 3]);
    let stored = sender1.send_recv(&update).await;
    assert_eq!(stored["payload"]["status"], "Stored");

    // 4. Recipient connects → receives blob → triggers Delivered ack to sender
    let mut recipient = connect_noise(&recipient_url, &noise_pub).await;
    let hs = make_handshake(&recipient_id);
    recipient.send_envelope(&hs).await;
    let _ack = recipient.recv().await; // HandshakeAck
    let reg = make_register_mailbox(&[&recipient_id]);
    recipient.send_envelope(&reg).await;
    let _blob = recipient.recv().await; // Blob delivery

    // 5. BOTH sender devices should receive the Delivered ack
    let delivered1 = timeout(Duration::from_secs(2), async {
        loop {
            if let Some(msg) = sender1.try_recv().await
                && msg["payload"]["type"] == "Acknowledgment"
                && msg["payload"]["status"] == "Delivered"
            {
                return msg;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    let delivered2 = timeout(Duration::from_secs(2), async {
        loop {
            if let Some(msg) = sender2.try_recv().await
                && msg["payload"]["type"] == "Acknowledgment"
                && msg["payload"]["status"] == "Delivered"
            {
                return msg;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    assert!(
        delivered1.is_ok(),
        "Sender device-1 should receive Delivered ack"
    );
    assert!(
        delivered2.is_ok(),
        "Sender device-2 should also receive Delivered ack (registry fan-out)"
    );

    sender1.close().await;
    sender2.close().await;
    recipient.close().await;
}
