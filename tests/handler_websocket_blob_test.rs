// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! WebSocket blob storage tests: store, pending delivery, acknowledgment removal.

mod common;

use std::time::Duration;

use futures_util::SinkExt;
use tokio_tungstenite::connect_async;

use vauchi_relay::storage::{BlobStore, StoredBlob};

use common::ws_helpers::*;

// ============================================================================
// Tests: EncryptedUpdate → Stored ack
// ============================================================================

// @scenario: message_delivery:Messages persist until acknowledged
#[tokio::test]
async fn test_store_blob_returns_stored_ack() {
    let (deps, storage, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    // Send an encrypted update
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[10, 20, 30]);
    let response = send_recv(&mut ws, &update).await;

    assert_eq!(response["payload"]["type"], "Acknowledgment");
    assert_eq!(response["payload"]["status"], "Stored");

    // Verify blob was actually stored
    let blobs = storage.peek(&recipient_id);
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].data, vec![10, 20, 30]);

    ws.close(None).await.ok();
}

// @scenario: message_delivery:Messages persist until acknowledged
#[tokio::test]
async fn test_store_multiple_blobs() {
    let (deps, storage, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    let recipient_id = common::generate_test_client_id(2);
    for i in 0..5u8 {
        let update = make_encrypted_update(&recipient_id, &[i]);
        let response = send_recv(&mut ws, &update).await;
        assert_eq!(response["payload"]["status"], "Stored");
    }

    assert_eq!(storage.peek(&recipient_id).len(), 5);
    ws.close(None).await.ok();
}

// ============================================================================
// Tests: Pending blob delivery on connect
// ============================================================================

// @scenario: sync_updates:Pending updates delivered on connect
// @scenario: sync_updates.feature:Relay stores updates for offline contacts
#[tokio::test]
async fn test_pending_blobs_delivered_on_connect() {
    let (deps, storage, _) = test_deps();
    let recipient_id = common::generate_test_client_id(5);

    // Pre-store blobs for the recipient
    storage.store(&recipient_id, StoredBlob::new(vec![1, 2, 3]));
    storage.store(&recipient_id, StoredBlob::new(vec![4, 5, 6]));

    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Handshake → HandshakeAck
    let hs = make_handshake(&recipient_id);
    let frame = encode_envelope(&hs);
    ws.send(tokio_tungstenite::tungstenite::Message::Binary(frame))
        .await
        .unwrap();

    // Receive HandshakeAck
    let ack = recv(&mut ws).await;
    assert_eq!(ack["payload"]["type"], "HandshakeAck");

    // Receive 2 pending blobs
    let blob1 = recv(&mut ws).await;
    assert_eq!(blob1["payload"]["type"], "EncryptedUpdate");

    let blob2 = recv(&mut ws).await;
    assert_eq!(blob2["payload"]["type"], "EncryptedUpdate");

    ws.close(None).await.ok();
}

// @scenario: sync_updates:Pending updates delivered on connect
#[tokio::test]
async fn test_no_pending_blobs_no_delivery() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    // No pending blobs — sending an update should be the next interaction
    // Verify no extra messages arrive
    let extra = try_recv(&mut ws).await;
    assert!(extra.is_none(), "Should not receive any pending blobs");

    ws.close(None).await.ok();
}

// ============================================================================
// Tests: Acknowledgment → blob removal
// ============================================================================

// @scenario: message_delivery:Client acknowledges message receipt
#[tokio::test]
async fn test_acknowledge_removes_blob() {
    let (deps, storage, _) = test_deps();
    let client_id = common::generate_test_client_id(5);
    let blob = StoredBlob::new(vec![99]);
    let blob_id = blob.id.clone();
    storage.store(&client_id, blob);

    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Handshake
    let hs = make_handshake(&client_id);
    ws.send(tokio_tungstenite::tungstenite::Message::Binary(
        encode_envelope(&hs),
    ))
    .await
    .unwrap();

    // Receive HandshakeAck
    let _ack = recv(&mut ws).await;
    // Receive the pending blob
    let delivered = recv(&mut ws).await;
    assert_eq!(delivered["payload"]["type"], "EncryptedUpdate");

    // Send acknowledgment
    let ack_msg = make_ack(&blob_id, "ReceivedByRecipient");
    ws.send(tokio_tungstenite::tungstenite::Message::Binary(
        encode_envelope(&ack_msg),
    ))
    .await
    .unwrap();

    // Poll until handler processes the ack (CC-06: no bare sleeps)
    let removed = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if storage.peek(&client_id).is_empty() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Timed out waiting for blob removal");

    assert!(removed, "Blob should be removed from storage after ack");

    ws.close(None).await.ok();
}

// @scenario: message_delivery:Messages persist until acknowledged
#[tokio::test]
async fn test_zero_length_ciphertext_stored() {
    let (deps, storage, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[]);
    let response = send_recv(&mut ws, &update).await;
    assert_eq!(response["payload"]["type"], "Acknowledgment");
    assert_eq!(response["payload"]["status"], "Stored");

    let blobs = storage.peek(&recipient_id);
    assert_eq!(blobs.len(), 1);
    assert!(blobs[0].data.is_empty());

    ws.close(None).await.ok();
}
