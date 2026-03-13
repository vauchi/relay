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

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_async, connect_async};

use vauchi_relay::connection_registry::ConnectionRegistry;
use vauchi_relay::device_sync_storage::SqliteDeviceSyncStore;
use vauchi_relay::handler::{self, ConnectionDeps, QuotaLimits};
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::recovery_storage::SqliteRecoveryProofStore;
use vauchi_relay::storage::{BlobStore, SqliteBlobStore};

// ============================================================================
// Protocol helpers (same as handler_websocket_test.rs)
// ============================================================================

const FRAME_HEADER_SIZE: usize = 4;

fn encode_envelope(envelope: &Value) -> Vec<u8> {
    let json = serde_json::to_vec(envelope).unwrap();
    let len = json.len() as u32;
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + json.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&json);
    frame
}

fn decode_envelope(data: &[u8]) -> Value {
    assert!(data.len() >= FRAME_HEADER_SIZE, "Frame too short");
    let json = &data[FRAME_HEADER_SIZE..];
    serde_json::from_slice(json).unwrap()
}

fn make_handshake(client_id: &str) -> Value {
    json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "Handshake",
            "client_id": client_id
        }
    })
}

fn make_encrypted_update(recipient_id: &str, ciphertext: &[u8]) -> Value {
    json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "EncryptedUpdate",
            "recipient_id": recipient_id,
            "ciphertext": ciphertext.to_vec()
        }
    })
}

fn make_ack(message_id: &str, status: &str) -> Value {
    json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "Acknowledgment",
            "message_id": message_id,
            "status": status
        }
    })
}

// ============================================================================
// Test infrastructure
// ============================================================================

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Creates shared deps for multi-connection tests.
fn shared_deps() -> (
    Arc<SqliteBlobStore>,
    Arc<ConnectionRegistry>,
    handler::BlobSenderMap,
) {
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let blob_sender_map = handler::new_blob_sender_map();
    (storage, registry, blob_sender_map)
}

/// Creates ConnectionDeps from shared components.
fn make_deps(
    storage: Arc<SqliteBlobStore>,
    registry: Arc<ConnectionRegistry>,
    blob_sender_map: handler::BlobSenderMap,
) -> ConnectionDeps {
    ConnectionDeps {
        storage: storage as Arc<dyn BlobStore>,
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        device_sync_storage: Arc::new(SqliteDeviceSyncStore::in_memory().unwrap()),
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
        noise_static_key: None,
        require_noise_encryption: false,
        nonce_tracker: Arc::new(handler::NonceTracker::new()),
        delivery_jitter_min_ms: 0,
        delivery_jitter_max_ms: 0,
        relay_signing_key: None,
        metrics: RelayMetrics::new(),
    }
}

/// Spawns a single-connection test server and returns its URL.
async fn spawn_handler(deps: ConnectionDeps) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://127.0.0.1:{}", addr.port());
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            if let Ok(ws) = accept_async(stream).await {
                handler::handle_connection(ws, deps).await;
            }
        }
    });
    url
}

/// Sends a binary frame and receives the next binary response.
async fn send_recv(ws: &mut WsStream, msg: &Value) -> Value {
    let frame = encode_envelope(msg);
    ws.send(Message::Binary(frame)).await.unwrap();
    recv(ws).await
}

/// Receives the next binary message as JSON.
async fn recv(ws: &mut WsStream) -> Value {
    let msg = timeout(Duration::from_secs(3), ws.next())
        .await
        .expect("Timeout waiting for message")
        .expect("Stream ended")
        .expect("WebSocket error");
    match msg {
        Message::Binary(data) => decode_envelope(&data),
        other => panic!("Expected Binary message, got {:?}", other),
    }
}

/// Try to receive a message with a short timeout.
async fn try_recv(ws: &mut WsStream) -> Option<Value> {
    match timeout(Duration::from_millis(300), ws.next()).await {
        Ok(Some(Ok(Message::Binary(data)))) => Some(decode_envelope(&data)),
        _ => None,
    }
}

/// Perform handshake and return the HandshakeAck.
async fn do_handshake(ws: &mut WsStream, client_id: &str) -> Value {
    send_recv(ws, &make_handshake(client_id)).await
}

// ============================================================================
// Tests: Multi-device blob delivery
// ============================================================================

// @scenario: message_delivery.feature:Message delivered to all registered devices
#[tokio::test]
async fn test_message_forwarded_to_all_connected_devices() {
    let (storage, registry, sender_map) = shared_deps();

    let sender_id = common::generate_test_client_id(1);
    let recipient_id = common::generate_test_client_id(2);

    // Spawn 3 handlers: sender + 2 recipient devices
    let sender_url = spawn_handler(make_deps(
        storage.clone(),
        registry.clone(),
        sender_map.clone(),
    ))
    .await;
    let device1_url = spawn_handler(make_deps(
        storage.clone(),
        registry.clone(),
        sender_map.clone(),
    ))
    .await;
    let device2_url = spawn_handler(make_deps(
        storage.clone(),
        registry.clone(),
        sender_map.clone(),
    ))
    .await;

    // 1. Connect sender and store a blob for recipient
    let (mut sender_ws, _) = connect_async(&sender_url).await.unwrap();
    let _ack = do_handshake(&mut sender_ws, &sender_id).await;

    let update = make_encrypted_update(&recipient_id, &[10, 20, 30]);
    let stored_ack = send_recv(&mut sender_ws, &update).await;
    assert_eq!(
        stored_ack["payload"]["status"], "Stored",
        "Sender should receive Stored ack"
    );

    // 2. Connect device-1 with recipient's routing_id → should get the blob
    let (mut device1_ws, _) = connect_async(&device1_url).await.unwrap();
    device1_ws
        .send(Message::Binary(encode_envelope(&make_handshake(
            &recipient_id,
        ))))
        .await
        .unwrap();
    let ack1 = recv(&mut device1_ws).await;
    assert_eq!(ack1["payload"]["type"], "HandshakeAck");
    let blob1 = recv(&mut device1_ws).await;
    assert_eq!(
        blob1["payload"]["type"], "EncryptedUpdate",
        "Device-1 should receive the pending blob"
    );

    // 3. Connect device-2 with SAME routing_id → should also get the blob
    //    (blob stays in storage until acknowledged)
    let (mut device2_ws, _) = connect_async(&device2_url).await.unwrap();
    device2_ws
        .send(Message::Binary(encode_envelope(&make_handshake(
            &recipient_id,
        ))))
        .await
        .unwrap();
    let ack2 = recv(&mut device2_ws).await;
    assert_eq!(ack2["payload"]["type"], "HandshakeAck");
    let blob2 = recv(&mut device2_ws).await;
    assert_eq!(
        blob2["payload"]["type"], "EncryptedUpdate",
        "Device-2 should also receive the pending blob (not yet acknowledged)"
    );

    // Both devices received the same ciphertext
    assert_eq!(
        blob1["payload"]["ciphertext"], blob2["payload"]["ciphertext"],
        "Both devices should receive identical ciphertext"
    );

    sender_ws.close(None).await.ok();
    device1_ws.close(None).await.ok();
    device2_ws.close(None).await.ok();
}

// @scenario: message_delivery.feature:Partial delivery tracked per device
#[tokio::test]
async fn test_partial_delivery_when_one_device_offline() {
    let (storage, registry, sender_map) = shared_deps();

    let sender_id = common::generate_test_client_id(3);
    let recipient_id = common::generate_test_client_id(4);

    // Spawn only sender + one device (device-2 stays offline)
    let sender_url = spawn_handler(make_deps(
        storage.clone(),
        registry.clone(),
        sender_map.clone(),
    ))
    .await;
    let device1_url = spawn_handler(make_deps(
        storage.clone(),
        registry.clone(),
        sender_map.clone(),
    ))
    .await;

    // 1. Sender stores blob
    let (mut sender_ws, _) = connect_async(&sender_url).await.unwrap();
    let _ack = do_handshake(&mut sender_ws, &sender_id).await;
    let update = make_encrypted_update(&recipient_id, &[40, 50, 60]);
    let stored = send_recv(&mut sender_ws, &update).await;
    assert_eq!(stored["payload"]["status"], "Stored");

    // 2. Device-1 connects and receives the blob
    let (mut device1_ws, _) = connect_async(&device1_url).await.unwrap();
    device1_ws
        .send(Message::Binary(encode_envelope(&make_handshake(
            &recipient_id,
        ))))
        .await
        .unwrap();
    let _ack = recv(&mut device1_ws).await;
    let blob = recv(&mut device1_ws).await;
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

    sender_ws.close(None).await.ok();
    device1_ws.close(None).await.ok();
}

// @scenario: message_delivery.feature:All-delivered only when every device acknowledges
#[tokio::test]
async fn test_blob_removed_only_after_device_acknowledges() {
    let (storage, registry, sender_map) = shared_deps();

    let sender_id = common::generate_test_client_id(5);
    let recipient_id = common::generate_test_client_id(6);

    let sender_url = spawn_handler(make_deps(
        storage.clone(),
        registry.clone(),
        sender_map.clone(),
    ))
    .await;
    let device1_url = spawn_handler(make_deps(
        storage.clone(),
        registry.clone(),
        sender_map.clone(),
    ))
    .await;

    // 1. Sender stores blob
    let (mut sender_ws, _) = connect_async(&sender_url).await.unwrap();
    let _ack = do_handshake(&mut sender_ws, &sender_id).await;
    let update = make_encrypted_update(&recipient_id, &[70, 80, 90]);
    let stored = send_recv(&mut sender_ws, &update).await;
    assert_eq!(stored["payload"]["status"], "Stored");

    // 2. Device-1 connects and gets the blob
    let (mut device1_ws, _) = connect_async(&device1_url).await.unwrap();
    device1_ws
        .send(Message::Binary(encode_envelope(&make_handshake(
            &recipient_id,
        ))))
        .await
        .unwrap();
    let _ack = recv(&mut device1_ws).await;
    let blob = recv(&mut device1_ws).await;
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
    device1_ws
        .send(Message::Binary(encode_envelope(&ack_msg)))
        .await
        .unwrap();

    // Short delay for async processing
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 5. After acknowledgment: blob removed from storage
    assert_eq!(
        storage.peek(&recipient_id).len(),
        0,
        "Blob should be removed after device acknowledges"
    );

    sender_ws.close(None).await.ok();
    device1_ws.close(None).await.ok();
}

// ============================================================================
// Tests: Registry multi-device ACK forwarding
// ============================================================================

// @scenario: message_delivery.feature:Delivery notifications reach all sender devices
#[tokio::test]
async fn test_registry_forwards_ack_to_all_sender_devices() {
    let (storage, registry, sender_map) = shared_deps();

    let sender_id = common::generate_test_client_id(7);
    let recipient_id = common::generate_test_client_id(8);

    // Sender has TWO devices, recipient has one
    let sender_dev1_url = spawn_handler(make_deps(
        storage.clone(),
        registry.clone(),
        sender_map.clone(),
    ))
    .await;
    let sender_dev2_url = spawn_handler(make_deps(
        storage.clone(),
        registry.clone(),
        sender_map.clone(),
    ))
    .await;
    let recipient_url = spawn_handler(make_deps(
        storage.clone(),
        registry.clone(),
        sender_map.clone(),
    ))
    .await;

    // 1. Connect sender device-1
    let (mut sender1_ws, _) = connect_async(&sender_dev1_url).await.unwrap();
    let _ack = do_handshake(&mut sender1_ws, &sender_id).await;

    // 2. Connect sender device-2 (same identity/routing_id)
    let (mut sender2_ws, _) = connect_async(&sender_dev2_url).await.unwrap();
    let _ack = do_handshake(&mut sender2_ws, &sender_id).await;

    // 3. Sender device-1 stores a blob for recipient
    let update = make_encrypted_update(&recipient_id, &[1, 2, 3]);
    let stored = send_recv(&mut sender1_ws, &update).await;
    assert_eq!(stored["payload"]["status"], "Stored");

    // 4. Recipient connects → receives blob → triggers Delivered ack to sender
    let (mut recipient_ws, _) = connect_async(&recipient_url).await.unwrap();
    recipient_ws
        .send(Message::Binary(encode_envelope(&make_handshake(
            &recipient_id,
        ))))
        .await
        .unwrap();
    let _ack = recv(&mut recipient_ws).await; // HandshakeAck
    let _blob = recv(&mut recipient_ws).await; // Blob delivery

    // 5. BOTH sender devices should receive the Delivered ack
    let delivered1 = timeout(Duration::from_secs(2), async {
        loop {
            if let Some(msg) = try_recv(&mut sender1_ws).await {
                if msg["payload"]["type"] == "Acknowledgment"
                    && msg["payload"]["status"] == "Delivered"
                {
                    return msg;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    let delivered2 = timeout(Duration::from_secs(2), async {
        loop {
            if let Some(msg) = try_recv(&mut sender2_ws).await {
                if msg["payload"]["type"] == "Acknowledgment"
                    && msg["payload"]["status"] == "Delivered"
                {
                    return msg;
                }
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

    sender1_ws.close(None).await.ok();
    sender2_ws.close(None).await.ok();
    recipient_ws.close(None).await.ok();
}
