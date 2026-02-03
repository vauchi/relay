// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! WebSocket load tests for the relay server.
//!
//! Tests concurrent connections, message throughput, rate limiting under load,
//! delivery notification latency, idle timeout recovery, and connection limits.
//!
//! Reuses protocol patterns from handler_websocket_test.rs with independent
//! helper functions.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_async, connect_async};

use vauchi_relay::connection_registry::ConnectionRegistry;
use vauchi_relay::device_sync_storage::MemoryDeviceSyncStore;
use vauchi_relay::handler::{self, ConnectionDeps, QuotaLimits};
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::recovery_storage::MemoryRecoveryProofStore;
use vauchi_relay::storage::{BlobStore, MemoryBlobStore};

// ============================================================================
// Protocol helpers (duplicated from handler_websocket_test.rs for isolation)
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
    serde_json::from_slice(&data[FRAME_HEADER_SIZE..]).unwrap()
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

// ============================================================================
// Test infrastructure
// ============================================================================

fn test_deps() -> (
    ConnectionDeps,
    Arc<MemoryBlobStore>,
    Arc<ConnectionRegistry>,
) {
    let storage = Arc::new(MemoryBlobStore::new());
    let registry = Arc::new(ConnectionRegistry::new());
    let deps = ConnectionDeps {
        storage: storage.clone() as Arc<dyn BlobStore>,
        recovery_storage: Arc::new(MemoryRecoveryProofStore::new()),
        device_sync_storage: Arc::new(MemoryDeviceSyncStore::new()),
        rate_limiter: Arc::new(RateLimiter::new(1000)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(100)),
        registry: registry.clone(),
        blob_sender_map: handler::new_blob_sender_map(),
        max_message_size: 1_048_576,
        idle_timeout: Duration::from_secs(30),
        quota: QuotaLimits {
            max_blobs: 10_000,
            max_bytes: 100_000_000,
        },
        hint_store: None,
    };
    (deps, storage, registry)
}

fn test_deps_custom(
    rate_limit: u32,
    idle_timeout: Duration,
    quota: QuotaLimits,
) -> (
    ConnectionDeps,
    Arc<MemoryBlobStore>,
    Arc<ConnectionRegistry>,
) {
    let storage = Arc::new(MemoryBlobStore::new());
    let registry = Arc::new(ConnectionRegistry::new());
    let deps = ConnectionDeps {
        storage: storage.clone() as Arc<dyn BlobStore>,
        recovery_storage: Arc::new(MemoryRecoveryProofStore::new()),
        device_sync_storage: Arc::new(MemoryDeviceSyncStore::new()),
        rate_limiter: Arc::new(RateLimiter::new(rate_limit)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(100)),
        registry: registry.clone(),
        blob_sender_map: handler::new_blob_sender_map(),
        max_message_size: 1_048_576,
        idle_timeout,
        quota,
        hint_store: None,
    };
    (deps, storage, registry)
}

/// Starts a multi-connection test server. Returns the URL.
async fn start_multi_server(deps: ConnectionDeps) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://127.0.0.1:{}", addr.port());

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

/// Perform handshake, return the ack response.
async fn do_handshake(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    client_id: &str,
) -> Value {
    let frame = encode_envelope(&make_handshake(client_id));
    ws.send(Message::Binary(frame)).await.unwrap();
    recv(ws).await
}

/// Receive next binary message as JSON.
async fn recv(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Value {
    let msg = timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("Timeout waiting for message")
        .expect("Stream ended")
        .expect("WebSocket error");
    match msg {
        Message::Binary(data) => decode_envelope(&data),
        other => panic!("Expected Binary, got {:?}", other),
    }
}

/// Send a message and receive the response.
async fn send_recv(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    msg: &Value,
) -> Value {
    ws.send(Message::Binary(encode_envelope(msg)))
        .await
        .unwrap();
    recv(ws).await
}

/// Try to receive with short timeout.
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

// ============================================================================
// Test 1: Concurrent connections
// ============================================================================

/// 1000 concurrent WebSocket clients all do handshake + hold + close.
/// Assert >= 900 succeed (some may fail under OS resource pressure).
///
/// NOTE: Requires sufficient file descriptor limits (ulimit -n >= 4096).
/// Each connection uses ~2 fds (client + server side).
#[tokio::test]
async fn test_1000_concurrent_websocket_connections() {
    let (deps, _, registry) = test_deps();
    let url = start_multi_server(deps).await;

    let num_clients = 1000u16;
    let mut handles = vec![];

    for i in 0..num_clients {
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let client_id = common::generate_test_client_id_wide(i);
            match timeout(Duration::from_secs(15), connect_async(&url)).await {
                Ok(Ok((mut ws, _))) => {
                    let frame = encode_envelope(&make_handshake(&client_id));
                    if ws.send(Message::Binary(frame)).await.is_err() {
                        return false;
                    }
                    // Wait for HandshakeAck
                    match timeout(Duration::from_secs(10), ws.next()).await {
                        Ok(Some(Ok(Message::Binary(data)))) => {
                            let resp = decode_envelope(&data);
                            let ok = resp["payload"]["type"] == "HandshakeAck";
                            // Hold connection briefly
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            ws.close(None).await.ok();
                            ok
                        }
                        _ => false,
                    }
                }
                _ => false,
            }
        }));
    }

    let mut successes = 0;
    for handle in handles {
        if handle.await.unwrap_or(false) {
            successes += 1;
        }
    }

    assert!(
        successes >= 900,
        "Expected >= 900 successful connections, got {}",
        successes
    );

    // After all close, registry should be empty
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        registry.connected_count(),
        0,
        "Registry should be empty after all close"
    );
}

// ============================================================================
// Test 2: Message throughput (single client)
// ============================================================================

/// Single client sends 1000 messages to different recipients.
/// Assert > 100 msgs/sec (conservative for test environment).
#[tokio::test]
async fn test_message_throughput_sustained() {
    let (deps, storage, _) = test_deps();
    let url = start_multi_server(deps).await;

    let (mut ws, _) = connect_async(&url).await.unwrap();
    let sender_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &sender_id).await;

    let start = Instant::now();
    let msg_count = 1000;

    for i in 0..msg_count {
        let recipient_id = common::generate_test_client_id((i % 200 + 2) as u8);
        let update = make_encrypted_update(&recipient_id, &[i as u8; 32]);
        let response = send_recv(&mut ws, &update).await;
        assert_eq!(response["payload"]["status"], "Stored");
    }

    let elapsed = start.elapsed();
    let msgs_per_sec = msg_count as f64 / elapsed.as_secs_f64();

    assert!(
        msgs_per_sec > 100.0,
        "Throughput too low: {:.0} msgs/sec (expected > 100)",
        msgs_per_sec
    );

    assert_eq!(storage.blob_count(), msg_count);

    ws.close(None).await.ok();
}

// ============================================================================
// Test 3: Multi-client message throughput
// ============================================================================

/// 10 concurrent clients each sending 100 messages.
/// Assert all messages stored. Measure aggregate throughput.
#[tokio::test]
async fn test_multi_client_throughput() {
    let (deps, storage, _) = test_deps();
    let url = start_multi_server(deps).await;

    let num_clients = 10;
    let msgs_per_client = 100;
    let start = Instant::now();

    let mut handles = vec![];
    for c in 0..num_clients {
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let client_id = common::generate_test_client_id(c as u8);
            let (mut ws, _) = connect_async(&url).await.unwrap();
            let _ack = do_handshake(&mut ws, &client_id).await;

            let mut stored = 0usize;
            for i in 0..msgs_per_client {
                // Each client sends to a unique set of recipients
                let recipient_id =
                    common::generate_test_client_id(((c * msgs_per_client + i) % 200 + 50) as u8);
                let update = make_encrypted_update(&recipient_id, &[i as u8; 16]);
                let response = send_recv(&mut ws, &update).await;
                if response["payload"]["status"] == "Stored" {
                    stored += 1;
                }
            }

            ws.close(None).await.ok();
            stored
        }));
    }

    let mut total_stored = 0;
    for handle in handles {
        total_stored += handle.await.unwrap();
    }

    let elapsed = start.elapsed();

    assert_eq!(
        total_stored,
        num_clients * msgs_per_client,
        "All messages should be stored"
    );
    assert_eq!(storage.blob_count(), total_stored);

    let aggregate_throughput = total_stored as f64 / elapsed.as_secs_f64();
    // Just log — the main assertion is all messages stored
    eprintln!(
        "Multi-client throughput: {:.0} msgs/sec ({} clients × {} msgs in {:?})",
        aggregate_throughput, num_clients, msgs_per_client, elapsed
    );
}

// ============================================================================
// Test 4: Rate limit enforcement under load
// ============================================================================

/// 5 clients with rate_limit=10, each sending 20 messages.
/// Assert total stored <= 50 (rate limit caps it).
#[tokio::test]
async fn test_rate_limit_enforcement_concurrent() {
    let (deps, storage, _) = test_deps_custom(
        10, // 10 messages per minute (token bucket starts with 10 tokens)
        Duration::from_secs(30),
        QuotaLimits {
            max_blobs: 10_000,
            max_bytes: 0,
        },
    );
    let url = start_multi_server(deps).await;

    let num_clients = 5;
    let msgs_per_client = 20;

    let mut handles = vec![];
    for c in 0..num_clients {
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let client_id = common::generate_test_client_id(c as u8);
            let (mut ws, _) = connect_async(&url).await.unwrap();
            let _ack = do_handshake(&mut ws, &client_id).await;

            let mut stored = 0usize;
            let recipient_id = common::generate_test_client_id(200 + c as u8);
            for i in 0..msgs_per_client {
                let update = make_encrypted_update(&recipient_id, &[i as u8]);
                let frame = encode_envelope(&update);
                ws.send(Message::Binary(frame)).await.unwrap();

                // Check response — rate-limited messages get no response
                match timeout(Duration::from_millis(500), ws.next()).await {
                    Ok(Some(Ok(Message::Binary(data)))) => {
                        let resp = decode_envelope(&data);
                        if resp["payload"]["status"] == "Stored" {
                            stored += 1;
                        }
                    }
                    _ => {
                        // No response = rate limited, continue
                    }
                }
            }

            ws.close(None).await.ok();
            stored
        }));
    }

    let mut total_stored = 0;
    for handle in handles {
        total_stored += handle.await.unwrap();
    }

    // Each client has 10 tokens, so max 10 stored per client = 50 total
    assert!(
        total_stored <= (num_clients * 10) as usize,
        "Total stored {} should be <= {} (rate limit enforced)",
        total_stored,
        num_clients * 10
    );

    // Verify in storage too
    assert!(storage.blob_count() <= (num_clients * 10) as usize);
}

// ============================================================================
// Test 5: Delivery notification round-trip
// ============================================================================

/// Sender stores blob, recipient connects and receives it, sender gets "Delivered" ack.
/// Assert round-trip < 2s.
#[tokio::test]
async fn test_delivery_notification_latency() {
    let storage = Arc::new(MemoryBlobStore::new());
    let registry = Arc::new(ConnectionRegistry::new());
    let blob_sender_map = handler::new_blob_sender_map();

    let make_deps = |s: Arc<MemoryBlobStore>,
                     r: Arc<ConnectionRegistry>,
                     bsm: handler::BlobSenderMap|
     -> ConnectionDeps {
        ConnectionDeps {
            storage: s as Arc<dyn BlobStore>,
            recovery_storage: Arc::new(MemoryRecoveryProofStore::new()),
            device_sync_storage: Arc::new(MemoryDeviceSyncStore::new()),
            rate_limiter: Arc::new(RateLimiter::new(1000)),
            recovery_rate_limiter: Arc::new(RateLimiter::new(100)),
            registry: r,
            blob_sender_map: bsm,
            max_message_size: 1_048_576,
            idle_timeout: Duration::from_secs(30),
            quota: QuotaLimits {
                max_blobs: 1000,
                max_bytes: 0,
            },
            hint_store: None,
        }
    };

    let deps = make_deps(storage.clone(), registry.clone(), blob_sender_map.clone());
    let url = start_multi_server(deps).await;

    let sender_id = common::generate_test_client_id(1);
    let recipient_id = common::generate_test_client_id(2);

    // Connect sender
    let (mut sender_ws, _) = connect_async(&url).await.unwrap();
    let _ack = do_handshake(&mut sender_ws, &sender_id).await;

    // Sender stores a blob
    let update = make_encrypted_update(&recipient_id, &[1, 2, 3, 4, 5]);
    let stored_ack = send_recv(&mut sender_ws, &update).await;
    assert_eq!(stored_ack["payload"]["status"], "Stored");

    let start = Instant::now();

    // Recipient connects — triggers delivery + Delivered ack to sender
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

    // Sender: wait for Delivered ack
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
    .expect("Should receive Delivered ack within 2s");

    let round_trip = start.elapsed();

    assert_eq!(delivered["payload"]["status"], "Delivered");
    assert!(
        round_trip < Duration::from_secs(2),
        "Round-trip took {:?}, expected < 2s",
        round_trip
    );

    sender_ws.close(None).await.ok();
    recipient_ws.close(None).await.ok();
}

// ============================================================================
// Test 6: Connection lifecycle (idle timeout + reconnect)
// ============================================================================

/// Connect with short idle timeout, wait for timeout, reconnect.
/// Assert second connection works.
#[tokio::test]
async fn test_idle_timeout_and_reconnect() {
    let (deps, _, _) = test_deps_custom(
        1000,
        Duration::from_millis(500), // 500ms idle timeout
        QuotaLimits {
            max_blobs: 1000,
            max_bytes: 0,
        },
    );
    let url = start_multi_server(deps).await;

    let client_id = common::generate_test_client_id(1);

    // First connection
    let (mut ws1, _) = connect_async(&url).await.unwrap();
    let ack = do_handshake(&mut ws1, &client_id).await;
    assert_eq!(ack["payload"]["type"], "HandshakeAck");

    // Wait for idle timeout
    tokio::time::sleep(Duration::from_millis(700)).await;

    // Server should have closed the connection
    let msg = timeout(Duration::from_secs(2), ws1.next()).await;
    match msg {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {
            // Expected: connection closed
        }
        other => panic!("Expected disconnection after idle timeout, got {:?}", other),
    }

    // Reconnect — should work
    let (mut ws2, _) = connect_async(&url).await.unwrap();
    let ack2 = do_handshake(&mut ws2, &client_id).await;
    assert_eq!(ack2["payload"]["type"], "HandshakeAck");

    // Verify the reconnected session works
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[42]);
    let response = send_recv(&mut ws2, &update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    ws2.close(None).await.ok();
}

// ============================================================================
// Test 7: Connection limit enforcement
// ============================================================================

/// Use ConnectionLimiter directly: set max=10, try 15 acquires.
/// Assert exactly 10 connected, 5 rejected.
///
/// Note: ConnectionLimiter is enforced in main.rs's accept loop, not in the
/// handler. Testing it at the handler level would require a full server.
/// Instead, we test the limiter directly to verify the enforcement logic.
#[tokio::test]
async fn test_connection_limit_enforcement() {
    use vauchi_relay::connection_limit::ConnectionLimiter;

    let limiter = ConnectionLimiter::new(10);
    let mut guards = vec![];
    let mut rejected = 0;

    for _ in 0..15 {
        match limiter.try_acquire() {
            Some(guard) => guards.push(guard),
            None => rejected += 1,
        }
    }

    assert_eq!(guards.len(), 10, "Exactly 10 should be connected");
    assert_eq!(rejected, 5, "Exactly 5 should be rejected");
    assert_eq!(limiter.active_count(), 10);

    // Drop all guards
    guards.clear();
    assert_eq!(
        limiter.active_count(),
        0,
        "All connections should be released"
    );

    // Should be able to acquire again
    let _g = limiter
        .try_acquire()
        .expect("Should acquire after all released");
    assert_eq!(limiter.active_count(), 1);
}
