// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! WebSocket blob storage tests: store, pending delivery, acknowledgment removal.

mod common;

use std::time::Duration;

use vauchi_relay::storage::{BlobStore, StoredBlob};

use common::ws_helpers::*;

// ============================================================================
// Tests: EncryptedUpdate → Stored ack
// ============================================================================

// @scenario: message_delivery:Messages persist until acknowledged
#[tokio::test]
async fn test_store_blob_returns_stored_ack() {
    let (deps, relay_pub, storage, _) = test_deps();
    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    let client_id = common::generate_test_client_id(1);
    let _ack = client.do_handshake(&client_id).await;

    // Send an encrypted update
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[10, 20, 30]);
    let response = client.send_recv(&update).await;

    assert_eq!(response["payload"]["type"], "Acknowledgment");
    assert_eq!(response["payload"]["status"], "Stored");

    // Verify blob was actually stored
    let blobs = storage.peek(&recipient_id);
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].data, vec![10, 20, 30]);

    client.close().await;
}

// @scenario: message_delivery:Messages persist until acknowledged
#[tokio::test]
async fn test_store_multiple_blobs() {
    let (deps, relay_pub, storage, _) = test_deps();
    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    let client_id = common::generate_test_client_id(1);
    let _ack = client.do_handshake(&client_id).await;

    let recipient_id = common::generate_test_client_id(2);
    for i in 0..5u8 {
        let update = make_encrypted_update(&recipient_id, &[i]);
        let response = client.send_recv(&update).await;
        assert_eq!(response["payload"]["status"], "Stored");
    }

    assert_eq!(storage.peek(&recipient_id).len(), 5);
    client.close().await;
}

// ============================================================================
// Tests: Pending blob delivery on connect
// ============================================================================

// @scenario: sync_updates:Pending updates delivered on connect
// @scenario: sync_updates.feature:Relay stores updates for offline contacts
#[tokio::test]
async fn test_pending_blobs_delivered_on_connect() {
    let (deps, relay_pub, storage, _) = test_deps();
    let recipient_id = common::generate_test_client_id(5);

    // Pre-store blobs for the recipient
    storage.store(&recipient_id, StoredBlob::new(vec![1, 2, 3]));
    storage.store(&recipient_id, StoredBlob::new(vec![4, 5, 6]));

    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    // Send protocol Handshake over Noise
    let hs = make_handshake(&recipient_id);
    client.send_envelope(&hs).await;

    // Receive HandshakeAck
    let ack = client.recv().await;
    assert_eq!(ack["payload"]["type"], "HandshakeAck");

    // Receive 2 pending blobs
    let blob1 = client.recv().await;
    assert_eq!(blob1["payload"]["type"], "EncryptedUpdate");

    let blob2 = client.recv().await;
    assert_eq!(blob2["payload"]["type"], "EncryptedUpdate");

    client.close().await;
}

// @scenario: sync_updates:Pending updates delivered on connect
#[tokio::test]
async fn test_no_pending_blobs_no_delivery() {
    let (deps, relay_pub, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    let client_id = common::generate_test_client_id(1);
    let _ack = client.do_handshake(&client_id).await;

    // No pending blobs — verify no extra messages arrive
    let extra = client.try_recv().await;
    assert!(extra.is_none(), "Should not receive any pending blobs");

    client.close().await;
}

// ============================================================================
// Tests: Acknowledgment → blob removal
// ============================================================================

// @scenario: message_delivery:Client acknowledges message receipt
#[tokio::test]
async fn test_acknowledge_removes_blob() {
    let (deps, relay_pub, storage, _) = test_deps();
    let client_id = common::generate_test_client_id(5);
    let blob = StoredBlob::new(vec![99]);
    let blob_id = blob.id.clone();
    storage.store(&client_id, blob);

    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    // Send protocol Handshake
    let hs = make_handshake(&client_id);
    client.send_envelope(&hs).await;

    // Receive HandshakeAck
    let _ack = client.recv().await;
    // Receive the pending blob
    let delivered = client.recv().await;
    assert_eq!(delivered["payload"]["type"], "EncryptedUpdate");

    // Send acknowledgment
    let ack_msg = make_ack(&blob_id, "ReceivedByRecipient");
    client.send_envelope(&ack_msg).await;

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

    client.close().await;
}

// @scenario: message_delivery:Messages persist until acknowledged
#[tokio::test]
async fn test_zero_length_ciphertext_stored() {
    let (deps, relay_pub, storage, _) = test_deps();
    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    let client_id = common::generate_test_client_id(1);
    let _ack = client.do_handshake(&client_id).await;

    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[]);
    let response = client.send_recv(&update).await;
    assert_eq!(response["payload"]["type"], "Acknowledgment");
    assert_eq!(response["payload"]["status"], "Stored");

    let blobs = storage.peek(&recipient_id);
    assert_eq!(blobs.len(), 1);
    assert!(blobs[0].data.is_empty());

    client.close().await;
}
