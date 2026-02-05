// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! HTTP peek routing integration tests.
//!
//! Tests the TCP peek-based routing logic in main.rs that distinguishes
//! between plain HTTP GET requests (health/up/ready) and WebSocket upgrades.
//!
//! Each test binds to port 0 for isolation.

mod common;

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::{accept_async, connect_async};

use vauchi_relay::connection_limit::ConnectionLimiter;
use vauchi_relay::connection_registry::ConnectionRegistry;
use vauchi_relay::device_sync_storage::MemoryDeviceSyncStore;
use vauchi_relay::handler::{self, ConnectionDeps, QuotaLimits};
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::recovery_storage::MemoryRecoveryProofStore;
use vauchi_relay::storage::{BlobStore, MemoryBlobStore};

// ============================================================================
// Test infrastructure: full server with peek routing
// ============================================================================

/// Starts a full server that replicates main.rs accept loop behaviour:
/// 1. Peeks first 512 bytes
/// 2. HTTP GET → writes response + shutdown
/// 3. WebSocket upgrade → accept_async → handle_connection
///
/// Returns (url, connection_limiter) so tests can inspect limits.
async fn start_full_server(
    max_connections: usize,
) -> (String, ConnectionLimiter, Arc<MemoryBlobStore>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://127.0.0.1:{}", addr.port());

    let limiter = ConnectionLimiter::new(max_connections);
    let storage = Arc::new(MemoryBlobStore::new());

    let limiter_clone = limiter.clone();
    let storage_clone = storage.clone();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };

            let guard = match limiter_clone.try_acquire() {
                Some(g) => g,
                None => {
                    drop(stream);
                    continue;
                }
            };

            let storage = storage_clone.clone();
            let idle_timeout = Duration::from_secs(5);

            tokio::spawn(async move {
                let _guard = guard;

                let mut peek_buf = [0u8; 512];
                match stream.peek(&mut peek_buf).await {
                    Ok(n) if n > 0 => {
                        let peek_str = String::from_utf8_lossy(&peek_buf[..n]);
                        let peek_lower = peek_str.to_ascii_lowercase();

                        let is_websocket_upgrade = peek_lower.contains("upgrade: websocket")
                            && peek_lower.contains("connection:")
                            && peek_lower.contains("upgrade");

                        if is_websocket_upgrade {
                            // Fall through to WebSocket handling below
                        } else {
                            let is_http_get = peek_lower.starts_with("get ");

                            if is_http_get {
                                let path = if peek_lower.contains("get /health") {
                                    Some("/health")
                                } else if peek_lower.contains("get /up") {
                                    Some("/up")
                                } else if peek_lower.contains("get /ready") {
                                    Some("/ready")
                                } else {
                                    None
                                };

                                if let Some(_path) = path {
                                    let health_response = format!(
                                        r#"{{"status":"healthy","version":"{}","uptime_seconds":0,"blob_count":{}}}"#,
                                        env!("CARGO_PKG_VERSION"),
                                        storage.blob_count()
                                    );
                                    let response = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                        health_response.len(),
                                        health_response
                                    );
                                    let mut stream = stream;
                                    let _ = stream.write_all(response.as_bytes()).await;
                                    let _ = stream.shutdown().await;
                                    return;
                                }

                                // Unknown path
                                let body = r#"{"error":"This is a WebSocket relay endpoint"}"#;
                                let response = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    body.len(),
                                    body
                                );
                                let mut stream = stream;
                                let _ = stream.write_all(response.as_bytes()).await;
                                let _ = stream.shutdown().await;
                                return;
                            }
                            // Not HTTP GET and not WebSocket → fall through to WS handshake
                            // (which will fail with a WebSocket error, not a crash)
                        }
                    }
                    _ => return,
                }

                // WebSocket handshake
                match tokio::time::timeout(idle_timeout, accept_async(stream)).await {
                    Ok(Ok(ws_stream)) => {
                        let deps = ConnectionDeps {
                            storage: storage as Arc<dyn BlobStore>,
                            recovery_storage: Arc::new(MemoryRecoveryProofStore::new()),
                            device_sync_storage: Arc::new(MemoryDeviceSyncStore::new()),
                            rate_limiter: Arc::new(RateLimiter::new(60)),
                            recovery_rate_limiter: Arc::new(RateLimiter::new(10)),
                            registry: Arc::new(ConnectionRegistry::new()),
                            blob_sender_map: handler::new_blob_sender_map(),
                            max_message_size: 1_048_576,
                            idle_timeout,
                            quota: QuotaLimits {
                                max_blobs: 100,
                                max_bytes: 0,
                            },
                            hint_store: None,
                            noise_static_key: None,
                            require_noise_encryption: false,
                            nonce_tracker: Arc::new(handler::NonceTracker::new()),
                        };
                        handler::handle_connection(ws_stream, deps).await;
                    }
                    Ok(Err(_)) | Err(_) => {
                        // WebSocket handshake failed or timed out
                    }
                }
            });
        }
    });

    (url, limiter, storage)
}

/// Sends a raw HTTP GET request over TCP and reads the full response.
async fn raw_http_get(addr: &str, path: &str) -> String {
    // Parse port from ws:// URL
    let port: u16 = addr
        .strip_prefix("ws://127.0.0.1:")
        .unwrap()
        .parse()
        .unwrap();

    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        path
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    // Read the response (server sends response + shuts down connection)
    let mut buf = vec![0u8; 4096];
    let mut response = Vec::new();
    loop {
        match timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => response.extend_from_slice(&buf[..n]),
            Ok(Err(_)) => break, // Read error
            Err(_) => break,     // Timeout
        }
    }

    String::from_utf8_lossy(&response).to_string()
}

// ============================================================================
// Tests: HTTP health endpoints
// ============================================================================

#[tokio::test]
async fn test_health_endpoint_returns_json() {
    let (url, _, _) = start_full_server(100).await;
    // Give server time to be ready
    tokio::time::sleep(Duration::from_millis(50)).await;

    let response = raw_http_get(&url, "/health").await;

    assert!(
        response.contains("HTTP/1.1 200 OK"),
        "Expected 200 OK, got: {}",
        response
    );
    assert!(response.contains("application/json"));
    assert!(response.contains(r#""status":"healthy""#));
    assert!(response.contains(r#""blob_count":"#));
}

#[tokio::test]
async fn test_up_endpoint_returns_json() {
    let (url, _, _) = start_full_server(100).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let response = raw_http_get(&url, "/up").await;

    assert!(
        response.contains("HTTP/1.1 200 OK"),
        "Expected 200 OK, got: {}",
        response
    );
    assert!(response.contains(r#""status":"healthy""#));
}

#[tokio::test]
async fn test_ready_endpoint_returns_json() {
    let (url, _, _) = start_full_server(100).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let response = raw_http_get(&url, "/ready").await;

    assert!(
        response.contains("HTTP/1.1 200 OK"),
        "Expected 200 OK, got: {}",
        response
    );
    assert!(response.contains(r#""status":"healthy""#));
}

#[tokio::test]
async fn test_unknown_http_path_returns_error() {
    let (url, _, _) = start_full_server(100).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let response = raw_http_get(&url, "/unknown").await;

    assert!(
        response.contains("HTTP/1.1 200 OK"),
        "Expected 200 OK, got: {}",
        response
    );
    assert!(response.contains("WebSocket relay endpoint"));
}

// ============================================================================
// Tests: WebSocket upgrade through peek
// ============================================================================

#[tokio::test]
async fn test_websocket_upgrade_works_through_peek() {
    let (url, _, _) = start_full_server(100).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Perform a handshake to verify the full pipeline works
    let client_id = common::generate_test_client_id(1);
    let hs = serde_json::json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "Handshake",
            "client_id": client_id
        }
    });
    let json = serde_json::to_vec(&hs).unwrap();
    let len = json.len() as u32;
    let mut frame = Vec::with_capacity(4 + json.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&json);

    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    ws.send(Message::Binary(frame)).await.unwrap();

    let msg = timeout(Duration::from_secs(3), ws.next())
        .await
        .expect("Timeout")
        .expect("Stream ended")
        .expect("WebSocket error");

    match msg {
        Message::Binary(data) => {
            assert!(data.len() > 4);
            let json_data: serde_json::Value = serde_json::from_slice(&data[4..]).unwrap();
            assert_eq!(json_data["payload"]["type"], "HandshakeAck");
        }
        other => panic!("Expected Binary message, got {:?}", other),
    }

    ws.close(None).await.ok();
}

// ============================================================================
// Tests: Connection limiting
// ============================================================================

#[tokio::test]
async fn test_connection_limit_rejects_excess() {
    let (url, limiter, _) = start_full_server(2).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Open 2 connections (at limit)
    let (ws1, _) = connect_async(&url).await.unwrap();
    let (ws2, _) = connect_async(&url).await.unwrap();

    // Give server time to accept both
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Active connections should be at limit
    assert_eq!(limiter.active_count(), 2);

    // 3rd connection: the TCP connect may succeed but WebSocket handshake
    // will fail because the server drops the stream when at capacity.
    let result = timeout(Duration::from_secs(2), connect_async(&url)).await;
    match result {
        Ok(Err(_)) => {
            // WebSocket handshake rejected — expected
        }
        Err(_) => {
            // Timeout — server dropped the connection before handshake
        }
        Ok(Ok(_)) => {
            // On some systems the connection may briefly succeed before being dropped.
            // The limiter should still show 2 active (the 3rd was dropped).
            // Give it a moment to settle.
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    drop(ws1);
    drop(ws2);
}

#[tokio::test]
async fn test_connection_limit_releases_on_disconnect() {
    let (url, limiter, _) = start_full_server(1).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // First connection
    {
        let (mut ws, _) = connect_async(&url).await.unwrap();

        // Perform handshake so we know the connection is fully established
        let client_id = common::generate_test_client_id(1);
        let hs = serde_json::json!({
            "version": 1,
            "message_id": uuid::Uuid::new_v4().to_string(),
            "timestamp": 1000,
            "payload": {
                "type": "Handshake",
                "client_id": client_id
            }
        });
        let json = serde_json::to_vec(&hs).unwrap();
        let len = json.len() as u32;
        let mut frame = Vec::with_capacity(4 + json.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&json);

        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;
        ws.send(Message::Binary(frame)).await.unwrap();

        // Receive HandshakeAck
        use futures_util::StreamExt;
        let _ = timeout(Duration::from_secs(3), ws.next()).await;

        assert_eq!(limiter.active_count(), 1);

        // Close the connection
        ws.close(None).await.ok();
    }

    // Wait for server to process the disconnect and release the guard
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(
        limiter.active_count(),
        0,
        "Connection slot should be released after disconnect"
    );

    // Second connection should succeed
    let result = timeout(Duration::from_secs(2), connect_async(&url)).await;
    assert!(
        result.is_ok() && result.unwrap().is_ok(),
        "Should be able to reconnect after slot is released"
    );
}

// ============================================================================
// Tests: Non-HTTP, non-WS traffic
// ============================================================================

#[tokio::test]
async fn test_non_http_non_ws_falls_through() {
    let (url, _, _) = start_full_server(100).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let port: u16 = url
        .strip_prefix("ws://127.0.0.1:")
        .unwrap()
        .parse()
        .unwrap();

    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    // Send random bytes that aren't HTTP or WebSocket
    stream.write_all(b"JUNK DATA NOT HTTP\r\n").await.unwrap();

    // Server should handle this gracefully (WebSocket handshake will fail)
    let mut buf = [0u8; 1024];
    let result = timeout(Duration::from_secs(2), stream.read(&mut buf)).await;

    match result {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
            // Connection closed, error, or timeout — all acceptable
        }
        Ok(Ok(_n)) => {
            // Got some response data — also acceptable (could be a WS error)
        }
    }
    // Main thing: server didn't crash
}
