// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Noise Encryption Enforcement Tests
//!
//! CRIT-07: Verifies that the relay rejects plaintext (v1) connections
//! when `require_noise_encryption = true`.
//!
//! security.feature: Noise NK inner encryption

mod common;

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_async, connect_async};

use vauchi_relay::connection_registry::ConnectionRegistry;
use vauchi_relay::device_sync_storage::SqliteDeviceSyncStore;
use vauchi_relay::handler::{self, ConnectionDeps, QuotaLimits};
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::recovery_storage::SqliteRecoveryProofStore;
use vauchi_relay::storage::{BlobStore, SqliteBlobStore};

// ============================================================================
// Protocol helpers
// ============================================================================

const FRAME_HEADER_SIZE: usize = 4;

fn encode_envelope(envelope: &serde_json::Value) -> Vec<u8> {
    let json = serde_json::to_vec(envelope).unwrap();
    let len = json.len() as u32;
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + json.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&json);
    frame
}

// ============================================================================
// Test helpers
// ============================================================================

fn make_deps(require_noise: bool) -> ConnectionDeps {
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    ConnectionDeps {
        storage: storage as Arc<dyn BlobStore>,
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        device_sync_storage: Arc::new(SqliteDeviceSyncStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(60)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(10)),
        registry,
        blob_sender_map: handler::new_blob_sender_map(),
        max_message_size: 1_048_576,
        idle_timeout: Duration::from_secs(5),
        quota: QuotaLimits {
            max_blobs: 100,
            max_bytes: 10_000_000,
        },
        hint_store: None,
        noise_static_key: None,
        require_noise_encryption: require_noise,
        nonce_tracker: Arc::new(handler::NonceTracker::new()),
        delivery_jitter_min_ms: 0,
        delivery_jitter_max_ms: 0,
    }
}

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

// ============================================================================
// Tests
// ============================================================================

/// When `require_noise_encryption = true`, a plaintext (v1) handshake should
/// be rejected: the server closes the connection without sending a HandshakeAck.
// @scenario: noise_protocol:Plaintext rejected when noise encryption required
// @scenario: noise_protocol.feature:Relay optionally requires Noise for v2+ clients
#[tokio::test]
async fn test_plaintext_rejected_when_noise_required() {
    let deps = make_deps(true);
    let url = start_test_server(deps).await;

    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Send a valid v1 plaintext Handshake
    let client_id = common::generate_test_client_id(1);
    let handshake = json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "Handshake",
            "client_id": client_id
        }
    });
    let frame = encode_envelope(&handshake);
    ws.send(Message::Binary(frame)).await.unwrap();

    // The server should close the connection without a HandshakeAck.
    let result = timeout(Duration::from_secs(2), ws.next()).await;
    match result {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) => {
            // Connection closed or timed out — correct behavior
        }
        Ok(Some(Ok(Message::Binary(data)))) => {
            // If we got a response, it must NOT be a successful HandshakeAck
            if data.len() >= FRAME_HEADER_SIZE {
                let json: serde_json::Value =
                    serde_json::from_slice(&data[FRAME_HEADER_SIZE..]).unwrap_or_default();
                let payload_type = json
                    .get("payload")
                    .and_then(|p| p.get("type"))
                    .and_then(|t| t.as_str())
                    .unwrap_or("");
                assert_ne!(
                    payload_type, "HandshakeAck",
                    "Plaintext connection must NOT receive HandshakeAck when noise is required"
                );
            }
        }
        Ok(Some(Err(_))) => {
            // WebSocket error — connection was dropped, correct behavior
        }
        other => {
            panic!("Unexpected response when noise required: {:?}", other);
        }
    }
}

/// When `require_noise_encryption = false`, a plaintext (v1) handshake should
/// succeed normally with a HandshakeAck response.
// @scenario: noise_protocol:Plaintext accepted when noise not required
// @scenario: noise_protocol.feature:Client connects to relay without Noise support
#[tokio::test]
async fn test_plaintext_accepted_when_noise_not_required() {
    let deps = make_deps(false);
    let url = start_test_server(deps).await;

    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Send a valid v1 plaintext Handshake
    let client_id = common::generate_test_client_id(2);
    let handshake = json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "Handshake",
            "client_id": client_id
        }
    });
    let frame = encode_envelope(&handshake);
    ws.send(Message::Binary(frame)).await.unwrap();

    // Should receive a HandshakeAck
    let result = timeout(Duration::from_secs(2), ws.next()).await;
    match result {
        Ok(Some(Ok(Message::Binary(data)))) => {
            assert!(data.len() >= FRAME_HEADER_SIZE, "Response frame too short");
            let json: serde_json::Value =
                serde_json::from_slice(&data[FRAME_HEADER_SIZE..]).unwrap();
            let payload_type = json
                .get("payload")
                .and_then(|p| p.get("type"))
                .and_then(|t| t.as_str())
                .unwrap_or("");
            assert_eq!(
                payload_type, "HandshakeAck",
                "Plaintext connection should receive HandshakeAck when noise not required"
            );
        }
        other => {
            panic!(
                "Expected HandshakeAck for plaintext connection, got: {:?}",
                other
            );
        }
    }

    ws.close(None).await.ok();
}
