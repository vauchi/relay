// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! WebSocket recovery proof tests: store, query, and validation.

mod common;

use futures_util::SinkExt;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

use common::ws_helpers::*;

// ============================================================================
// Tests: Recovery proof store and query
// ============================================================================

// @scenario: identity_management:Store and query recovery proofs
#[tokio::test]
async fn test_recovery_proof_store_and_query() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    // Store a recovery proof
    let key_hash = common::generate_test_client_id(42); // 64 hex chars
    let proof_data = vec![10, 20, 30, 40];
    let store_msg = make_recovery_store(&key_hash, &proof_data);
    let response = send_recv(&mut ws, &store_msg).await;
    assert_eq!(response["payload"]["type"], "Acknowledgment");
    assert_eq!(response["payload"]["status"], "Stored");

    // Query for the proof
    let query = make_recovery_query(&[&key_hash]);
    let response = send_recv(&mut ws, &query).await;
    assert_eq!(response["payload"]["type"], "RecoveryProofResponse");

    let proofs = response["payload"]["proofs"].as_array().unwrap();
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0]["key_hash"], key_hash);

    ws.close(None).await.ok();
}

// @scenario: identity_management:Store and query recovery proofs
#[tokio::test]
async fn test_recovery_query_nonexistent() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    let key_hash = common::generate_test_client_id(99);
    let query = make_recovery_query(&[&key_hash]);
    let response = send_recv(&mut ws, &query).await;
    assert_eq!(response["payload"]["type"], "RecoveryProofResponse");
    assert_eq!(response["payload"]["proofs"].as_array().unwrap().len(), 0);

    ws.close(None).await.ok();
}

// @scenario: identity_management:Invalid recovery key hash rejected
#[tokio::test]
async fn test_recovery_store_invalid_key_hash() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    // Send RecoveryProofStore with a non-hex key_hash (contains 'g')
    let bad_key_hash = "g".repeat(64);
    let store_msg = make_recovery_store(&bad_key_hash, &[1, 2, 3]);
    let frame = encode_envelope(&store_msg);
    ws.send(Message::Binary(frame)).await.unwrap();

    // No ack expected (invalid key hash is silently dropped)
    let msg = try_recv(&mut ws).await;
    assert!(
        msg.is_none(),
        "Invalid key_hash should not produce a response"
    );

    // Connection should still work
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[1]);
    let response = send_recv(&mut ws, &update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    ws.close(None).await.ok();
}
