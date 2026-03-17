// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared WebSocket test helpers for relay handler integration tests.
//!
//! Provides protocol encoding/decoding, envelope builders, and test
//! infrastructure used across all `handler_websocket_*_test.rs` files.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

use vauchi_relay::connection_registry::ConnectionRegistry;
use vauchi_relay::device_sync_storage::SqliteDeviceSyncStore;
use vauchi_relay::handler::{self, ConnectionDeps, QuotaLimits};
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::recovery_storage::SqliteRecoveryProofStore;
use vauchi_relay::storage::{BlobStore, SqliteBlobStore};

// ============================================================================
// Protocol helpers (external perspective — validates wire format)
// ============================================================================

const FRAME_HEADER_SIZE: usize = 4;

/// Encodes a JSON value into a binary frame (4-byte BE length prefix + JSON).
pub fn encode_envelope(envelope: &Value) -> Vec<u8> {
    let json = serde_json::to_vec(envelope).unwrap();
    let len = json.len() as u32;
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + json.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&json);
    frame
}

/// Decodes a binary frame back to a JSON value.
pub fn decode_envelope(data: &[u8]) -> Value {
    assert!(data.len() >= FRAME_HEADER_SIZE, "Frame too short");
    let json = &data[FRAME_HEADER_SIZE..];
    serde_json::from_slice(json).unwrap()
}

/// Builds a Handshake envelope.
pub fn make_handshake(client_id: &str) -> Value {
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
pub fn make_handshake_full(
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
pub fn make_encrypted_update(recipient_id: &str, ciphertext: &[u8]) -> Value {
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
pub fn make_ack(message_id: &str, status: &str) -> Value {
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
pub fn make_recovery_store(key_hash: &str, proof_data: &[u8]) -> Value {
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
pub fn make_recovery_query(key_hashes: &[&str]) -> Value {
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

/// Builds a PurgeRequest envelope with valid Ed25519 signature.
pub fn make_purge_request(include_device_sync: bool) -> Value {
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};

    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

    let public_key = key_pair.public_key().as_ref();
    let pk_hex: String = public_key.iter().map(|b| format!("{:02x}", b)).collect();

    let purge_token = [0x42u8; 32];
    let token_hex: String = purge_token.iter().map(|b| format!("{:02x}", b)).collect();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Sign: public_key || purge_token || timestamp_be_bytes
    let mut message = Vec::with_capacity(32 + 32 + 8);
    message.extend_from_slice(public_key);
    message.extend_from_slice(&purge_token);
    message.extend_from_slice(&timestamp.to_be_bytes());

    let signature = key_pair.sign(&message);
    let sig_hex: String = signature
        .as_ref()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "PurgeRequest",
            "include_device_sync": include_device_sync,
            "public_key": pk_hex,
            "signature": sig_hex,
            "purge_token": token_hex,
            "timestamp": timestamp
        }
    })
}

/// Builds a DeviceSyncMessage envelope.
pub fn make_device_sync(
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

/// Builds a DeviceSyncAck envelope.
pub fn make_device_sync_ack(message_id: &str, synced_version: u64) -> Value {
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

// ============================================================================
// Test infrastructure
// ============================================================================

/// WebSocket stream type alias for test readability.
pub type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Creates a default set of test dependencies using in-memory storage.
pub fn test_deps() -> (
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
        delivery_jitter_min_ms: 0,
        delivery_jitter_max_ms: 0,
        relay_signing_key: None,
        metrics: RelayMetrics::new(),
    };
    (deps, storage, registry)
}

/// Creates a customised set of test dependencies.
pub fn test_deps_custom(
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
        delivery_jitter_min_ms: 0,
        delivery_jitter_max_ms: 0,
        relay_signing_key: None,
        metrics: RelayMetrics::new(),
    };
    (deps, storage, registry, device_sync_storage)
}

/// Starts a test server that handles exactly one WebSocket connection, then returns.
/// Returns the address to connect to.
pub async fn start_test_server(deps: ConnectionDeps) -> String {
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

/// Starts a test server that handles multiple WebSocket connections.
/// Returns the address to connect to.
pub async fn start_multi_server(deps: ConnectionDeps) -> String {
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
                delivery_jitter_min_ms: 0,
                delivery_jitter_max_ms: 0,
                relay_signing_key: None,
                metrics: RelayMetrics::new(),
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

/// Sends a binary frame and receives the next binary response, decoded as JSON.
pub async fn send_recv(ws: &mut WsStream, msg: &Value) -> Value {
    let frame = encode_envelope(msg);
    ws.send(Message::Binary(frame)).await.unwrap();
    recv(ws).await
}

/// Receives the next binary message as JSON.
pub async fn recv(ws: &mut WsStream) -> Value {
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
pub async fn try_recv(ws: &mut WsStream) -> Option<Value> {
    match timeout(Duration::from_millis(200), ws.next()).await {
        Ok(Some(Ok(Message::Binary(data)))) => Some(decode_envelope(&data)),
        _ => None,
    }
}

/// Perform a handshake and return the HandshakeAck response.
pub async fn do_handshake(ws: &mut WsStream, client_id: &str) -> Value {
    send_recv(ws, &make_handshake(client_id)).await
}
