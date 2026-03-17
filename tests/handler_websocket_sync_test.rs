// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! WebSocket device sync tests: store, delivery, ack, and purge interactions.

mod common;

use std::time::Duration;

use futures_util::SinkExt;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

use vauchi_relay::device_sync_storage::{DeviceSyncStore, StoredDeviceSyncMessage};
use vauchi_relay::handler::QuotaLimits;
use vauchi_relay::storage::{BlobStore, StoredBlob};

use common::ws_helpers::*;

// ============================================================================
// Tests: Device sync store & identity mismatch
// ============================================================================

// @scenario: device_management:Device sync messages stored and acknowledged
#[tokio::test]
async fn test_device_sync_store_and_ack() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let device_id = common::generate_test_client_id(10);

    // Handshake with device_id
    let hs = make_handshake_full(&client_id, Some(&device_id), None, false);
    let ack = send_recv(&mut ws, &hs).await;
    assert_eq!(ack["payload"]["type"], "HandshakeAck");

    // Send a device sync message to another device
    let target_device = common::generate_test_client_id(11);
    let sync_msg = make_device_sync(&client_id, &target_device, &device_id, &[1, 2, 3], 1);
    let response = send_recv(&mut ws, &sync_msg).await;
    assert_eq!(response["payload"]["type"], "Acknowledgment");
    assert_eq!(response["payload"]["status"], "Stored");

    ws.close(None).await.ok();
}

// @scenario: security:Device sync identity mismatch rejected
#[tokio::test]
async fn test_device_sync_identity_mismatch_rejected() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let device_id = common::generate_test_client_id(10);

    let hs = make_handshake_full(&client_id, Some(&device_id), None, false);
    let _ack = send_recv(&mut ws, &hs).await;

    // Send device sync with mismatched identity_id
    let wrong_identity = common::generate_test_client_id(99);
    let target_device = common::generate_test_client_id(11);
    let sync_msg = make_device_sync(&wrong_identity, &target_device, &device_id, &[1], 1);
    ws.send(Message::Binary(encode_envelope(&sync_msg)))
        .await
        .unwrap();

    // Should NOT get a Stored ack (identity mismatch is silently dropped with warning)
    let msg = try_recv(&mut ws).await;
    assert!(
        msg.is_none(),
        "Should not receive ack for mismatched identity"
    );

    ws.close(None).await.ok();
}

// ============================================================================
// Tests: Device sync delivery & ack
// ============================================================================

// @scenario: sync_updates:Pending device sync delivered on connect
#[tokio::test]
async fn test_pending_device_sync_delivered_on_connect() {
    let (deps, _, _, device_sync_storage) = test_deps_custom(
        60,
        10,
        1_048_576,
        Duration::from_secs(5),
        QuotaLimits {
            max_blobs: 100,
            max_bytes: 0,
        },
    );

    let client_id = common::generate_test_client_id(1);
    let device_id = common::generate_test_client_id(10);

    // Pre-store device sync messages
    device_sync_storage.store(StoredDeviceSyncMessage::new(
        client_id.clone(),
        device_id.clone(),
        common::generate_test_client_id(11),
        vec![1, 2, 3],
        1,
    ));
    device_sync_storage.store(StoredDeviceSyncMessage::new(
        client_id.clone(),
        device_id.clone(),
        common::generate_test_client_id(11),
        vec![4, 5, 6],
        2,
    ));

    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Handshake with device_id
    let hs = make_handshake_full(&client_id, Some(&device_id), None, false);
    ws.send(Message::Binary(encode_envelope(&hs)))
        .await
        .unwrap();

    // Receive HandshakeAck
    let ack = recv(&mut ws).await;
    assert_eq!(ack["payload"]["type"], "HandshakeAck");

    // Receive 2 pending device sync messages
    let sync1 = recv(&mut ws).await;
    assert_eq!(sync1["payload"]["type"], "DeviceSyncMessage");

    let sync2 = recv(&mut ws).await;
    assert_eq!(sync2["payload"]["type"], "DeviceSyncMessage");

    ws.close(None).await.ok();
}

// @scenario: device_management:Device sync requires device identifier
#[tokio::test]
async fn test_device_sync_not_delivered_without_device_id() {
    let (deps, _, _, device_sync_storage) = test_deps_custom(
        60,
        10,
        1_048_576,
        Duration::from_secs(5),
        QuotaLimits {
            max_blobs: 100,
            max_bytes: 0,
        },
    );

    let client_id = common::generate_test_client_id(1);
    let some_device_id = common::generate_test_client_id(10);

    // Pre-store device sync messages
    device_sync_storage.store(StoredDeviceSyncMessage::new(
        client_id.clone(),
        some_device_id.clone(),
        common::generate_test_client_id(11),
        vec![1, 2, 3],
        1,
    ));

    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Handshake WITHOUT device_id
    let ack = do_handshake(&mut ws, &client_id).await;
    assert_eq!(ack["payload"]["type"], "HandshakeAck");

    // No device sync messages should be delivered
    let msg = try_recv(&mut ws).await;
    assert!(msg.is_none(), "No device sync messages without device_id");

    ws.close(None).await.ok();
}

// @scenario: sync_updates:Device sync acknowledged and removed
#[tokio::test]
async fn test_device_sync_ack_removes_message() {
    let (deps, _, _, device_sync_storage) = test_deps_custom(
        60,
        10,
        1_048_576,
        Duration::from_secs(5),
        QuotaLimits {
            max_blobs: 100,
            max_bytes: 0,
        },
    );

    let client_id = common::generate_test_client_id(1);
    let device_id = common::generate_test_client_id(10);

    // Pre-store a device sync message
    let msg = StoredDeviceSyncMessage::new(
        client_id.clone(),
        device_id.clone(),
        common::generate_test_client_id(11),
        vec![1, 2, 3],
        1,
    );
    let msg_id = msg.id.clone();
    device_sync_storage.store(msg);

    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Handshake with device_id
    let hs = make_handshake_full(&client_id, Some(&device_id), None, false);
    ws.send(Message::Binary(encode_envelope(&hs)))
        .await
        .unwrap();

    // Receive HandshakeAck
    let _ack = recv(&mut ws).await;

    // Receive the pending device sync message
    let delivered = recv(&mut ws).await;
    assert_eq!(delivered["payload"]["type"], "DeviceSyncMessage");

    // Send DeviceSyncAck
    let ack_msg = make_device_sync_ack(&msg_id, 1);
    ws.send(Message::Binary(encode_envelope(&ack_msg)))
        .await
        .unwrap();

    // Poll until handler processes the ack (CC-06: no bare sleeps)
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if device_sync_storage.peek(&client_id, &device_id).is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Timed out: DeviceSyncAck should remove message from storage");

    ws.close(None).await.ok();
}

// @scenario: device_management:Device sync ack ignored without device id
#[tokio::test]
async fn test_device_sync_ack_without_device_id_ignored() {
    let (deps, _, _, device_sync_storage) = test_deps_custom(
        60,
        10,
        1_048_576,
        Duration::from_secs(5),
        QuotaLimits {
            max_blobs: 100,
            max_bytes: 0,
        },
    );

    let client_id = common::generate_test_client_id(1);
    let device_id = common::generate_test_client_id(10);

    // Pre-store a device sync message
    let msg = StoredDeviceSyncMessage::new(
        client_id.clone(),
        device_id.clone(),
        common::generate_test_client_id(11),
        vec![1, 2, 3],
        1,
    );
    let msg_id = msg.id.clone();
    device_sync_storage.store(msg);

    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Handshake WITHOUT device_id
    let _ack = do_handshake(&mut ws, &client_id).await;

    // Send DeviceSyncAck anyway — should be ignored
    let ack_msg = make_device_sync_ack(&msg_id, 1);
    ws.send(Message::Binary(encode_envelope(&ack_msg)))
        .await
        .unwrap();

    // Give handler time to process — use short yield instead of bare sleep (CC-06)
    // This is a negative assertion: we verify the message is NOT removed.
    // We yield to let the handler task run, then verify state is unchanged.
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Message should still be in storage (ack was ignored)
    let remaining = device_sync_storage.peek(&client_id, &device_id);
    assert_eq!(
        remaining.len(),
        1,
        "DeviceSyncAck without device_id should be ignored"
    );

    ws.close(None).await.ok();
}

// ============================================================================
// Tests: Purge with device sync
// ============================================================================

// @scenario: relay_network:Client purges stored data
#[tokio::test]
async fn test_purge_with_device_sync_deletes_both() {
    let (deps, storage, _, device_sync_storage) = test_deps_custom(
        60,
        10,
        1_048_576,
        Duration::from_secs(5),
        QuotaLimits {
            max_blobs: 100,
            max_bytes: 10_000_000,
        },
    );

    let client_id = common::generate_test_client_id(1);
    let device_id = common::generate_test_client_id(10);

    // Pre-store blobs
    storage.store(&client_id, StoredBlob::new(vec![1]));
    storage.store(&client_id, StoredBlob::new(vec![2]));

    // Pre-store device sync messages (identity-based)
    device_sync_storage.store(StoredDeviceSyncMessage::new(
        client_id.clone(),
        device_id.clone(),
        common::generate_test_client_id(11),
        vec![10],
        1,
    ));

    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Handshake (which will deliver pending blobs)
    let hs = make_handshake(&client_id);
    ws.send(Message::Binary(encode_envelope(&hs)))
        .await
        .unwrap();

    // Drain HandshakeAck + 2 pending blobs
    for _ in 0..3 {
        let _ = recv(&mut ws).await;
    }

    // Purge with include_device_sync=true
    let purge = make_purge_request(true);
    let response = send_recv(&mut ws, &purge).await;
    assert_eq!(response["payload"]["type"], "PurgeResponse");
    assert_eq!(response["payload"]["blobs_deleted"], 2);
    assert_eq!(response["payload"]["device_sync_deleted"], 1);

    ws.close(None).await.ok();
}

// @scenario: relay_network:Client purges stored data
#[tokio::test]
async fn test_purge_without_device_sync_preserves_sync() {
    let (deps, storage, _, device_sync_storage) = test_deps_custom(
        60,
        10,
        1_048_576,
        Duration::from_secs(5),
        QuotaLimits {
            max_blobs: 100,
            max_bytes: 10_000_000,
        },
    );

    let client_id = common::generate_test_client_id(1);
    let device_id = common::generate_test_client_id(10);

    // Pre-store blobs
    storage.store(&client_id, StoredBlob::new(vec![1]));

    // Pre-store device sync messages
    device_sync_storage.store(StoredDeviceSyncMessage::new(
        client_id.clone(),
        device_id.clone(),
        common::generate_test_client_id(11),
        vec![10],
        1,
    ));

    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Handshake (delivers pending blob)
    let hs = make_handshake(&client_id);
    ws.send(Message::Binary(encode_envelope(&hs)))
        .await
        .unwrap();

    // Drain HandshakeAck + 1 pending blob
    for _ in 0..2 {
        let _ = recv(&mut ws).await;
    }

    // Purge with include_device_sync=false
    let purge = make_purge_request(false);
    let response = send_recv(&mut ws, &purge).await;
    assert_eq!(response["payload"]["type"], "PurgeResponse");
    assert_eq!(response["payload"]["blobs_deleted"], 1);
    assert_eq!(response["payload"]["device_sync_deleted"], 0);

    // Device sync messages should still exist
    let remaining = device_sync_storage.peek(&client_id, &device_id);
    assert_eq!(
        remaining.len(),
        1,
        "Device sync should not be deleted when include_device_sync=false"
    );

    ws.close(None).await.ok();
}
