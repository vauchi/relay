// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! WebSocket integration tests for the relay handler.
//!
//! These tests spin up a real TCP listener, connect via WebSocket, and exercise
//! the full handler flow end-to-end. Each test binds to port 0 for isolation.

mod common;

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_async, connect_async};

use ring::signature::{Ed25519KeyPair, KeyPair};
use vauchi_relay::connection_registry::ConnectionRegistry;
use vauchi_relay::device_sync_storage::SqliteDeviceSyncStore;
use vauchi_relay::handler::{self, ConnectionDeps, QuotaLimits};
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::recovery_storage::SqliteRecoveryProofStore;
use vauchi_relay::storage::{BlobStore, SqliteBlobStore, StoredBlob};

// ============================================================================
// Protocol helpers (external perspective — validates wire format)
// ============================================================================

const FRAME_HEADER_SIZE: usize = 4;

/// Encodes a JSON value into a binary frame (4-byte BE length prefix + JSON).
fn encode_envelope(envelope: &Value) -> Vec<u8> {
    let json = serde_json::to_vec(envelope).unwrap();
    let len = json.len() as u32;
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + json.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&json);
    frame
}

/// Decodes a binary frame back to a JSON value.
fn decode_envelope(data: &[u8]) -> Value {
    assert!(data.len() >= FRAME_HEADER_SIZE, "Frame too short");
    let json = &data[FRAME_HEADER_SIZE..];
    serde_json::from_slice(json).unwrap()
}

/// Builds a Handshake envelope.
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

/// Builds a Handshake with extra fields.
fn make_handshake_full(
    client_id: &str,
    device_id: Option<&str>,
    routing_token: Option<&str>,
    suppress_presence: bool,
) -> Value {
    let mut payload = json!({
        "type": "Handshake",
        "client_id": client_id,
        "suppress_presence": suppress_presence,
    });
    if let Some(did) = device_id {
        payload["device_id"] = json!(did);
    }
    if let Some(rt) = routing_token {
        payload["routing_token"] = json!(rt);
    }
    json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": payload
    })
}

/// Builds an EncryptedUpdate envelope.
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

/// Builds an Acknowledgment envelope.
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

/// Builds a RecoveryProofStore envelope.
fn make_recovery_store(key_hash: &str, proof_data: &[u8]) -> Value {
    json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "RecoveryProofStore",
            "key_hash": key_hash,
            "proof_data": proof_data.to_vec()
        }
    })
}

/// Builds a RecoveryProofQuery envelope.
fn make_recovery_query(key_hashes: &[&str]) -> Value {
    json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "RecoveryProofQuery",
            "key_hashes": key_hashes
        }
    })
}

/// Builds a PurgeRequest envelope.
fn make_purge_request(include_device_sync: bool) -> Value {
    json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "PurgeRequest",
            "include_device_sync": include_device_sync
        }
    })
}

/// Builds a DeviceSyncMessage envelope.
fn make_device_sync(
    identity_id: &str,
    target_device_id: &str,
    sender_device_id: &str,
    payload: &[u8],
    version: u64,
) -> Value {
    json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "DeviceSyncMessage",
            "identity_id": identity_id,
            "target_device_id": target_device_id,
            "sender_device_id": sender_device_id,
            "encrypted_payload": payload.to_vec(),
            "version": version
        }
    })
}

// ============================================================================
// Test infrastructure
// ============================================================================

/// Creates a default set of test dependencies using in-memory storage.
fn test_deps() -> (
    ConnectionDeps,
    Arc<SqliteBlobStore>,
    Arc<ConnectionRegistry>,
) {
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let deps = ConnectionDeps {
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
        noise_static_key: None,
        require_noise_encryption: false,
        nonce_tracker: Arc::new(handler::NonceTracker::new()),
    };
    (deps, storage, registry)
}

/// Starts a test server that handles exactly one WebSocket connection, then returns.
/// Returns the address to connect to.
async fn start_test_server(deps: ConnectionDeps) -> String {
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

/// Sends a binary frame and receives the next binary response, decoded as JSON.
async fn send_recv(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    msg: &Value,
) -> Value {
    let frame = encode_envelope(msg);
    ws.send(Message::Binary(frame)).await.unwrap();
    recv(ws).await
}

/// Receives the next binary message as JSON.
async fn recv(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Value {
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

/// Try to receive a message with a short timeout. Returns None if no message arrives.
async fn try_recv(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Option<Value> {
    match timeout(Duration::from_millis(200), ws.next()).await {
        Ok(Some(Ok(Message::Binary(data)))) => Some(decode_envelope(&data)),
        _ => None,
    }
}

/// Perform a handshake and return the HandshakeAck response.
async fn do_handshake(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    client_id: &str,
) -> Value {
    send_recv(ws, &make_handshake(client_id)).await
}

// ============================================================================
// Tests: Handshake
// ============================================================================

#[tokio::test]
async fn test_handshake_returns_ack_with_version() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let ack = do_handshake(&mut ws, &client_id).await;

    assert_eq!(ack["payload"]["type"], "HandshakeAck");
    assert_eq!(ack["payload"]["protocol_version"], 1);
    assert!(ack["payload"]["server_version"].is_string());
    let features = ack["payload"]["features"].as_array().unwrap();
    assert!(features.iter().any(|f| f == "routing_token"));
    assert!(features.iter().any(|f| f == "purge"));

    ws.close(None).await.ok();
}

#[tokio::test]
async fn test_handshake_invalid_client_id_disconnects() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Send handshake with invalid (too short) client_id
    let hs = make_handshake("abcd1234");
    let frame = encode_envelope(&hs);
    ws.send(Message::Binary(frame)).await.unwrap();

    // Server should close the connection
    // The handler drops the WebSocket without sending a Close frame, so we may get
    // ResetWithoutClosingHandshake (Ok(Some(Err(_)))) which is valid disconnection.
    let msg = timeout(Duration::from_secs(2), ws.next()).await;
    match msg {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {
            // Expected: close frame, stream end, timeout, or reset
        }
        other => panic!("Expected close/disconnect, got {:?}", other),
    }
}

#[tokio::test]
async fn test_handshake_non_handshake_message_disconnects() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Send an EncryptedUpdate instead of Handshake
    let msg = make_encrypted_update(&common::generate_test_client_id(2), &[1, 2, 3]);
    let frame = encode_envelope(&msg);
    ws.send(Message::Binary(frame)).await.unwrap();

    // Server should close the connection
    let result = timeout(Duration::from_secs(2), ws.next()).await;
    match result {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {}
        other => panic!("Expected close/disconnect, got {:?}", other),
    }
}

// ============================================================================
// Tests: EncryptedUpdate → Stored ack
// ============================================================================

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
    ws.send(Message::Binary(frame)).await.unwrap();

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
    ws.send(Message::Binary(encode_envelope(&hs)))
        .await
        .unwrap();

    // Receive HandshakeAck
    let _ack = recv(&mut ws).await;
    // Receive the pending blob
    let delivered = recv(&mut ws).await;
    assert_eq!(delivered["payload"]["type"], "EncryptedUpdate");

    // Send acknowledgment
    let ack_msg = make_ack(&blob_id, "ReceivedByRecipient");
    ws.send(Message::Binary(encode_envelope(&ack_msg)))
        .await
        .unwrap();

    // Give handler a moment to process
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Blob should be removed from storage
    assert!(storage.peek(&client_id).is_empty());

    ws.close(None).await.ok();
}

// ============================================================================
// Tests: Quota enforcement
// ============================================================================

#[tokio::test]
async fn test_quota_blob_count_exceeded() {
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
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
        noise_static_key: None,
        require_noise_encryption: false,
        nonce_tracker: Arc::new(handler::NonceTracker::new()),
    };

    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    let recipient_id = common::generate_test_client_id(2);

    // Store 3 blobs (at limit)
    for _ in 0..3 {
        let update = make_encrypted_update(&recipient_id, &[1]);
        let response = send_recv(&mut ws, &update).await;
        assert_eq!(response["payload"]["status"], "Stored");
    }

    // 4th should be rejected
    let update = make_encrypted_update(&recipient_id, &[1]);
    let response = send_recv(&mut ws, &update).await;
    assert_eq!(response["payload"]["type"], "Acknowledgment");
    assert_eq!(response["payload"]["status"], "Failed");

    ws.close(None).await.ok();
}

#[tokio::test]
async fn test_quota_byte_limit_exceeded() {
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
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
        noise_static_key: None,
        require_noise_encryption: false,
        nonce_tracker: Arc::new(handler::NonceTracker::new()),
    };

    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    let recipient_id = common::generate_test_client_id(2);

    // First blob: 100 bytes — should succeed
    let update = make_encrypted_update(&recipient_id, &[0u8; 100]);
    let response = send_recv(&mut ws, &update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    // Second blob: 100 bytes — should push over the limit
    let update = make_encrypted_update(&recipient_id, &[0u8; 100]);
    let response = send_recv(&mut ws, &update).await;
    assert_eq!(response["payload"]["status"], "Failed");

    ws.close(None).await.ok();
}

// ============================================================================
// Tests: Recovery proof store and query
// ============================================================================

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

// ============================================================================
// Tests: PurgeRequest
// ============================================================================

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
    };

    // Spawn both servers
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener1.accept().await {
            if let Ok(ws) = accept_async(stream).await {
                handler::handle_connection(ws, deps1).await;
            }
        }
    });
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener2.accept().await {
            if let Ok(ws) = accept_async(stream).await {
                handler::handle_connection(ws, deps2).await;
            }
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
            if let Some(msg) = try_recv(&mut sender_ws).await {
                if msg["payload"]["type"] == "Acknowledgment"
                    && msg["payload"]["status"] == "Delivered"
                {
                    return msg;
                }
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
    };

    tokio::spawn(async move {
        if let Ok((stream, _)) = listener1.accept().await {
            if let Ok(ws) = accept_async(stream).await {
                handler::handle_connection(ws, deps1).await;
            }
        }
    });
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener2.accept().await {
            if let Ok(ws) = accept_async(stream).await {
                handler::handle_connection(ws, deps2).await;
            }
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

    // Wait a bit and check that sender does NOT receive Delivered ack
    tokio::time::sleep(Duration::from_millis(300)).await;
    let msg = try_recv(&mut sender_ws).await;
    assert!(
        msg.is_none(),
        "Sender should NOT receive Delivered ack when recipient has suppress_presence"
    );

    sender_ws.close(None).await.ok();
    recipient_ws.close(None).await.ok();
}

// ============================================================================
// Tests: Device sync
// ============================================================================

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
// Tests: Connection close
// ============================================================================

#[tokio::test]
async fn test_clean_close() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    // Send close frame
    ws.close(None).await.unwrap();

    // Stream should end
    let result = timeout(Duration::from_secs(2), ws.next()).await;
    match result {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {} // OK
        other => panic!("Expected clean shutdown, got {:?}", other),
    }
}

#[tokio::test]
async fn test_ping_pong() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    // Send ping
    ws.send(Message::Ping(vec![1, 2, 3])).await.unwrap();

    // Should get pong back
    let msg = timeout(Duration::from_secs(2), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(msg, Message::Pong(vec![1, 2, 3]));

    ws.close(None).await.ok();
}

// ============================================================================
// Tests: Unknown message type
// ============================================================================

// ============================================================================
// Parameterised test infrastructure
// ============================================================================

/// Creates a customised set of test dependencies.
fn test_deps_custom(
    rate_limit: u32,
    recovery_rate_limit: u32,
    max_msg_size: usize,
    idle_timeout: Duration,
    quota: QuotaLimits,
) -> (
    ConnectionDeps,
    Arc<SqliteBlobStore>,
    Arc<ConnectionRegistry>,
    Arc<SqliteDeviceSyncStore>,
) {
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let device_sync_storage = Arc::new(SqliteDeviceSyncStore::in_memory().unwrap());
    let deps = ConnectionDeps {
        storage: storage.clone() as Arc<dyn BlobStore>,
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        device_sync_storage: device_sync_storage.clone(),
        rate_limiter: Arc::new(RateLimiter::new(rate_limit)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(recovery_rate_limit)),
        registry: registry.clone(),
        blob_sender_map: handler::new_blob_sender_map(),
        max_message_size: max_msg_size,
        idle_timeout,
        quota,
        hint_store: None,
        noise_static_key: None,
        require_noise_encryption: false,
        nonce_tracker: Arc::new(handler::NonceTracker::new()),
    };
    (deps, storage, registry, device_sync_storage)
}

/// Builds a DeviceSyncAck envelope.
fn make_device_sync_ack(message_id: &str, synced_version: u64) -> Value {
    json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "DeviceSyncAck",
            "message_id": message_id,
            "synced_version": synced_version
        }
    })
}

/// Starts a test server that handles multiple WebSocket connections.
/// Returns the address to connect to.
async fn start_multi_server(deps: ConnectionDeps) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://127.0.0.1:{}", addr.port());

    // Wrap shared deps so multiple tasks can use them.
    let storage = deps.storage;
    let recovery_storage = deps.recovery_storage;
    let device_sync_storage = deps.device_sync_storage;
    let rate_limiter = deps.rate_limiter;
    let recovery_rate_limiter = deps.recovery_rate_limiter;
    let registry = deps.registry;
    let blob_sender_map = deps.blob_sender_map;
    let max_message_size = deps.max_message_size;
    let idle_timeout = deps.idle_timeout;
    let quota = deps.quota;

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let per_conn = ConnectionDeps {
                storage: storage.clone(),
                recovery_storage: recovery_storage.clone(),
                device_sync_storage: device_sync_storage.clone(),
                rate_limiter: rate_limiter.clone(),
                recovery_rate_limiter: recovery_rate_limiter.clone(),
                registry: registry.clone(),
                blob_sender_map: blob_sender_map.clone(),
                max_message_size,
                idle_timeout,
                quota,
                hint_store: None,
                noise_static_key: None,
                require_noise_encryption: false,
                nonce_tracker: Arc::new(handler::NonceTracker::new()),
            };
            tokio::spawn(async move {
                if let Ok(ws) = accept_async(stream).await {
                    handler::handle_connection(ws, per_conn).await;
                }
            });
        }
    });

    url
}

// ============================================================================
// Tests: Unknown message type
// ============================================================================

#[tokio::test]
async fn test_unknown_message_type_ignored() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    // Send a message with unknown type
    let unknown = json!({
        "version": 1,
        "message_id": "test-unknown",
        "timestamp": 1000,
        "payload": {
            "type": "FutureFeature",
            "data": "something"
        }
    });
    ws.send(Message::Binary(encode_envelope(&unknown)))
        .await
        .unwrap();

    // Should be silently ignored — no response
    let msg = try_recv(&mut ws).await;
    assert!(msg.is_none(), "Unknown message type should be ignored");

    // Connection should still work — send a valid update
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[1]);
    let response = send_recv(&mut ws, &update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    ws.close(None).await.ok();
}

// ============================================================================
// Group A: Message encoding edge cases
// ============================================================================

#[tokio::test]
async fn test_malformed_json_continues_connection() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    // Send valid length prefix + garbage JSON
    let garbage = b"this is not json at all!!!";
    let len = garbage.len() as u32;
    let mut frame = Vec::with_capacity(4 + garbage.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(garbage);
    ws.send(Message::Binary(frame)).await.unwrap();

    // No response expected for malformed message
    let msg = try_recv(&mut ws).await;
    assert!(
        msg.is_none(),
        "Malformed JSON should not produce a response"
    );

    // Connection should still work
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[42]);
    let response = send_recv(&mut ws, &update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    ws.close(None).await.ok();
}

#[tokio::test]
async fn test_truncated_frame_too_short() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    // Send a 2-byte message (too short for the 4-byte length header)
    ws.send(Message::Binary(vec![0, 1])).await.unwrap();

    // No response expected
    let msg = try_recv(&mut ws).await;
    assert!(
        msg.is_none(),
        "Truncated frame should not produce a response"
    );

    // Connection should still work
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[10]);
    let response = send_recv(&mut ws, &update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    ws.close(None).await.ok();
}

#[tokio::test]
async fn test_oversized_message_silently_dropped() {
    let (deps, storage, _, _) = test_deps_custom(
        60,
        10,
        512, // small max_message_size but large enough for envelope overhead
        Duration::from_secs(5),
        QuotaLimits {
            max_blobs: 100,
            max_bytes: 0,
        },
    );
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    // Send a message that exceeds max_message_size (512 bytes)
    let recipient_id = common::generate_test_client_id(2);
    let large_data = vec![0u8; 600]; // > 512 after envelope encoding
    let update = make_encrypted_update(&recipient_id, &large_data);
    let frame = encode_envelope(&update);
    ws.send(Message::Binary(frame)).await.unwrap();

    // No ack expected for oversized message
    let msg = try_recv(&mut ws).await;
    assert!(
        msg.is_none(),
        "Oversized message should not produce a response"
    );

    // Nothing stored
    assert!(storage.peek(&recipient_id).is_empty());

    // Connection should still work with a small message
    let small_update = make_encrypted_update(&recipient_id, &[1]);
    let response = send_recv(&mut ws, &small_update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    ws.close(None).await.ok();
}

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

#[tokio::test]
async fn test_empty_binary_message() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    // Send empty binary message
    ws.send(Message::Binary(vec![])).await.unwrap();

    // No response expected
    let msg = try_recv(&mut ws).await;
    assert!(
        msg.is_none(),
        "Empty binary message should not produce a response"
    );

    // Connection should still work
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[1]);
    let response = send_recv(&mut ws, &update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    ws.close(None).await.ok();
}

// ============================================================================
// Group B: Rate limiting integration
// ============================================================================

#[tokio::test]
async fn test_rate_limit_silently_drops_excess_messages() {
    let (deps, storage, _, _) = test_deps_custom(
        3, // Only allow 3 messages (token bucket starts with 3 tokens)
        10,
        1_048_576,
        Duration::from_secs(5),
        QuotaLimits {
            max_blobs: 100,
            max_bytes: 0,
        },
    );
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    let recipient_id = common::generate_test_client_id(2);

    // Send 3 messages — all should get Stored acks
    for _ in 0..3 {
        let update = make_encrypted_update(&recipient_id, &[1]);
        let response = send_recv(&mut ws, &update).await;
        assert_eq!(response["payload"]["status"], "Stored");
    }

    // 4th message should be silently dropped (rate limited)
    let update = make_encrypted_update(&recipient_id, &[1]);
    let frame = encode_envelope(&update);
    ws.send(Message::Binary(frame)).await.unwrap();

    let msg = try_recv(&mut ws).await;
    assert!(
        msg.is_none(),
        "Rate-limited message should not produce a response"
    );

    // Only 3 blobs stored
    assert_eq!(storage.peek(&recipient_id).len(), 3);

    ws.close(None).await.ok();
}

#[tokio::test]
async fn test_recovery_rate_limit_separate_from_general() {
    let (deps, _, _, _) = test_deps_custom(
        60, // general rate limit is generous
        2,  // recovery rate limit is very low
        1_048_576,
        Duration::from_secs(5),
        QuotaLimits {
            max_blobs: 100,
            max_bytes: 0,
        },
    );
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    // Send 2 recovery stores — both should succeed
    for i in 0..2u8 {
        let key_hash = common::generate_test_client_id(40 + i);
        let store_msg = make_recovery_store(&key_hash, &[i]);
        let response = send_recv(&mut ws, &store_msg).await;
        assert_eq!(response["payload"]["status"], "Stored");
    }

    // 3rd recovery store should be silently dropped
    let key_hash = common::generate_test_client_id(42);
    let store_msg = make_recovery_store(&key_hash, &[99]);
    let frame = encode_envelope(&store_msg);
    ws.send(Message::Binary(frame)).await.unwrap();

    let msg = try_recv(&mut ws).await;
    assert!(
        msg.is_none(),
        "Rate-limited recovery store should not produce a response"
    );

    // General message should still work (different rate limiter)
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[1]);
    let response = send_recv(&mut ws, &update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    ws.close(None).await.ok();
}

#[tokio::test]
async fn test_recovery_query_rate_limited() {
    let (deps, _, _, _) = test_deps_custom(
        60,
        2, // Only allow 2 recovery operations
        1_048_576,
        Duration::from_secs(5),
        QuotaLimits {
            max_blobs: 100,
            max_bytes: 0,
        },
    );
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    // 2 recovery queries should succeed
    for _ in 0..2 {
        let key_hash = common::generate_test_client_id(50);
        let query = make_recovery_query(&[&key_hash]);
        let response = send_recv(&mut ws, &query).await;
        assert_eq!(response["payload"]["type"], "RecoveryProofResponse");
    }

    // 3rd should be silently dropped
    let key_hash = common::generate_test_client_id(50);
    let query = make_recovery_query(&[&key_hash]);
    let frame = encode_envelope(&query);
    ws.send(Message::Binary(frame)).await.unwrap();

    let msg = try_recv(&mut ws).await;
    assert!(
        msg.is_none(),
        "Rate-limited recovery query should not produce a response"
    );

    ws.close(None).await.ok();
}

// ============================================================================
// Group C: Connection lifecycle & timeout
// ============================================================================

#[tokio::test]
async fn test_idle_timeout_disconnects_client() {
    let (deps, _, _, _) = test_deps_custom(
        60,
        10,
        1_048_576,
        Duration::from_millis(500), // 500ms idle timeout
        QuotaLimits {
            max_blobs: 100,
            max_bytes: 0,
        },
    );
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    // Wait longer than idle timeout
    tokio::time::sleep(Duration::from_millis(700)).await;

    // Server should have closed the connection
    let msg = timeout(Duration::from_secs(2), ws.next()).await;
    match msg {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {
            // Expected: connection closed
        }
        other => panic!("Expected disconnection after idle timeout, got {:?}", other),
    }
}

#[tokio::test]
async fn test_handshake_timeout_disconnects() {
    let (deps, _, _, _) = test_deps_custom(
        60,
        10,
        1_048_576,
        Duration::from_millis(300), // 300ms timeout
        QuotaLimits {
            max_blobs: 100,
            max_bytes: 0,
        },
    );
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Don't send handshake — just wait
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Server should have closed the connection
    let msg = timeout(Duration::from_secs(2), ws.next()).await;
    match msg {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {
            // Expected: connection closed due to handshake timeout
        }
        other => panic!(
            "Expected disconnection after handshake timeout, got {:?}",
            other
        ),
    }
}

#[tokio::test]
async fn test_text_message_ignored_connection_stays() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    // Send a text frame (handler ignores text)
    ws.send(Message::Text("hello world".to_string()))
        .await
        .unwrap();

    // No response expected
    let msg = try_recv(&mut ws).await;
    assert!(msg.is_none(), "Text message should not produce a response");

    // Binary still works
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[1]);
    let response = send_recv(&mut ws, &update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    ws.close(None).await.ok();
}

#[tokio::test]
async fn test_duplicate_handshake_ignored() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let ack = do_handshake(&mut ws, &client_id).await;
    assert_eq!(ack["payload"]["type"], "HandshakeAck");

    // Send a second handshake — should be silently ignored
    let hs2 = make_handshake(&client_id);
    let frame = encode_envelope(&hs2);
    ws.send(Message::Binary(frame)).await.unwrap();

    // No second HandshakeAck
    let msg = try_recv(&mut ws).await;
    assert!(
        msg.is_none(),
        "Duplicate handshake should not produce a response"
    );

    // Connection should still work
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[1]);
    let response = send_recv(&mut ws, &update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    ws.close(None).await.ok();
}

// ============================================================================
// Group D: Device sync delivery & ack
// ============================================================================

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
    use vauchi_relay::device_sync_storage::{DeviceSyncStore, StoredDeviceSyncMessage};
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
    use vauchi_relay::device_sync_storage::{DeviceSyncStore, StoredDeviceSyncMessage};
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
    use vauchi_relay::device_sync_storage::{DeviceSyncStore, StoredDeviceSyncMessage};
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

    // Give handler time to process
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Message should be removed from storage
    let remaining = device_sync_storage.peek(&client_id, &device_id);
    assert!(
        remaining.is_empty(),
        "DeviceSyncAck should remove message from storage"
    );

    ws.close(None).await.ok();
}

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
    use vauchi_relay::device_sync_storage::{DeviceSyncStore, StoredDeviceSyncMessage};
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

    // Give handler time to process
    tokio::time::sleep(Duration::from_millis(100)).await;

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
// Group E: Purge with device sync
// ============================================================================

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
    use vauchi_relay::device_sync_storage::{DeviceSyncStore, StoredDeviceSyncMessage};
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
    use vauchi_relay::device_sync_storage::{DeviceSyncStore, StoredDeviceSyncMessage};
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

// ============================================================================
// Group F: Multi-client concurrency
// ============================================================================

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
            if let Some(msg) = try_recv(&mut sender_ws).await {
                if msg["payload"]["type"] == "Acknowledgment"
                    && msg["payload"]["status"] == "Delivered"
                {
                    return msg;
                }
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
    tokio::time::sleep(Duration::from_millis(300)).await;
    let msg = try_recv(&mut sender_ws).await;
    assert!(
        msg.is_none(),
        "ReceivedByRecipient should not be forwarded after Delivered already cleaned up sender map"
    );

    sender_ws.close(None).await.ok();
    recipient_ws.close(None).await.ok();
}

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

    // Wait — sender should NOT get Delivered ack
    tokio::time::sleep(Duration::from_millis(300)).await;
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
    tokio::time::sleep(Duration::from_millis(300)).await;
    let msg = try_recv(&mut sender_ws).await;
    assert!(
        msg.is_none(),
        "Sender should NOT receive ReceivedByRecipient with suppress_presence"
    );

    sender_ws.close(None).await.ok();
    recipient_ws.close(None).await.ok();
}

// ============================================================================
// Group G: Additional edge cases
// ============================================================================

#[tokio::test]
async fn test_invalid_routing_token_format_disconnects() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Handshake with invalid routing_token (too short)
    let client_id = common::generate_test_client_id(1);
    let hs = make_handshake_full(&client_id, None, Some("abcd1234"), false);
    ws.send(Message::Binary(encode_envelope(&hs)))
        .await
        .unwrap();

    // Server should disconnect
    let msg = timeout(Duration::from_secs(2), ws.next()).await;
    match msg {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {
            // Expected: disconnection
        }
        other => panic!(
            "Expected disconnect for invalid routing_token, got {:?}",
            other
        ),
    }
}

#[tokio::test]
async fn test_invalid_device_id_format_disconnects() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Handshake with invalid device_id (too short)
    let client_id = common::generate_test_client_id(1);
    let hs = make_handshake_full(&client_id, Some("short"), None, false);
    ws.send(Message::Binary(encode_envelope(&hs)))
        .await
        .unwrap();

    // Server should disconnect
    let msg = timeout(Duration::from_secs(2), ws.next()).await;
    match msg {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {
            // Expected: disconnection
        }
        other => panic!("Expected disconnect for invalid device_id, got {:?}", other),
    }
}

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

// ============================================================================
// Authenticated Handshake tests
// ============================================================================

/// Generates an Ed25519 keypair and builds a signed handshake JSON envelope.
/// Returns (handshake_value, client_id_hex).
fn make_signed_handshake_envelope() -> (Value, String) {
    let rng = ring::rand::SystemRandom::new();
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
fn make_signed_handshake_with_nonce(nonce_bytes: &[u8; 32]) -> (Value, String) {
    let rng = ring::rand::SystemRandom::new();
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

#[tokio::test]
async fn test_authenticated_handshake_accepted() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let (hs, _client_id) = make_signed_handshake_envelope();
    let ack = send_recv(&mut ws, &hs).await;

    assert_eq!(ack["payload"]["type"], "HandshakeAck");
    assert_eq!(ack["payload"]["protocol_version"], 1);
    let features = ack["payload"]["features"].as_array().unwrap();
    assert!(features.iter().any(|f| f == "authenticated_handshake"));

    ws.close(None).await.ok();
}

#[tokio::test]
async fn test_invalid_signature_rejected() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let (mut hs, _) = make_signed_handshake_envelope();
    // Corrupt the signature by changing its first two hex chars
    let bad_sig = format!("ff{}", &hs["payload"]["signature"].as_str().unwrap()[2..]);
    hs["payload"]["signature"] = json!(bad_sig);

    let frame = encode_envelope(&hs);
    ws.send(Message::Binary(frame)).await.unwrap();

    // Server should close the connection (auth failed)
    let msg = timeout(Duration::from_secs(2), ws.next()).await;
    match msg {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {
            // Expected: disconnected
        }
        other => panic!("Expected close/disconnect, got {:?}", other),
    }
}

#[tokio::test]
async fn test_client_id_mismatch_rejected() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let (mut hs, _) = make_signed_handshake_envelope();
    // Change client_id to a different valid hex string (not matching the public key)
    hs["payload"]["client_id"] = json!("a".repeat(64));

    let frame = encode_envelope(&hs);
    ws.send(Message::Binary(frame)).await.unwrap();

    // Server should close the connection (client_id mismatch)
    let msg = timeout(Duration::from_secs(2), ws.next()).await;
    match msg {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {
            // Expected: disconnected
        }
        other => panic!("Expected close/disconnect, got {:?}", other),
    }
}

#[tokio::test]
async fn test_nonce_replay_rejected() {
    // Two connections share the same nonce_tracker via shared deps
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let nonce_tracker = Arc::new(handler::NonceTracker::new());

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
        noise_static_key: None,
        require_noise_encryption: false,
        nonce_tracker: nonce_tracker.clone(),
    };

    let url1 = start_test_server(deps1).await;
    let (mut ws1, _) = connect_async(&url1).await.unwrap();

    // First connection succeeds
    let ack1 = send_recv(&mut ws1, &hs1).await;
    assert_eq!(ack1["payload"]["type"], "HandshakeAck");
    ws1.close(None).await.ok();

    // Second connection with same nonce (different keypair but same nonce bytes)
    // The nonce_tracker is shared, so this should be rejected
    let (hs2, _) = make_signed_handshake_with_nonce(&nonce_bytes);

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
        noise_static_key: None,
        require_noise_encryption: false,
        nonce_tracker: nonce_tracker.clone(),
    };

    let url2 = start_test_server(deps2).await;
    let (mut ws2, _) = connect_async(&url2).await.unwrap();

    let frame = encode_envelope(&hs2);
    ws2.send(Message::Binary(frame)).await.unwrap();

    // Should be rejected (nonce replay)
    let msg = timeout(Duration::from_secs(2), ws2.next()).await;
    match msg {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {
            // Expected: disconnected
        }
        other => panic!("Expected close/disconnect, got {:?}", other),
    }
}

#[tokio::test]
async fn test_expired_timestamp_rejected() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Generate keypair and sign with a timestamp that's 120s old
    let rng = ring::rand::SystemRandom::new();
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

    let frame = encode_envelope(&hs);
    ws.send(Message::Binary(frame)).await.unwrap();

    // Should be rejected (expired timestamp)
    let msg = timeout(Duration::from_secs(2), ws.next()).await;
    match msg {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {
            // Expected: disconnected
        }
        other => panic!("Expected close/disconnect, got {:?}", other),
    }
}

#[tokio::test]
async fn test_unauthenticated_handshake_still_accepted() {
    // Legacy clients without auth fields should still work
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let ack = do_handshake(&mut ws, &client_id).await;

    assert_eq!(ack["payload"]["type"], "HandshakeAck");
    assert_eq!(ack["payload"]["protocol_version"], 1);

    // Can still store blobs
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[10, 20]);
    let response = send_recv(&mut ws, &update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    ws.close(None).await.ok();
}

#[tokio::test]
async fn test_routing_token_no_auth_required() {
    // routing_token mode should work without authentication
    let (deps, storage, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let routing_token = common::generate_test_client_id(99);
    let hs = make_handshake_full(&client_id, None, Some(&routing_token), false);
    let ack = send_recv(&mut ws, &hs).await;

    assert_eq!(ack["payload"]["type"], "HandshakeAck");

    // Store a blob for a different recipient
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[1, 2, 3]);
    let response = send_recv(&mut ws, &update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    // Verify blob was stored under recipient_id
    let blobs = storage.peek(&recipient_id);
    assert_eq!(blobs.len(), 1);

    ws.close(None).await.ok();
}
