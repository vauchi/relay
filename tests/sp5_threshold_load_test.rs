// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! SP-5 Threshold-Verifying WebSocket Load Test
//!
//! Spawns a relay server, connects N concurrent WebSocket clients,
//! each sending M messages, and asserts against performance thresholds:
//!
//! - **p95 latency** < 500ms
//! - **Connection setup** < 200ms per client
//! - **No dropped messages** (all messages delivered/stored)
//! - **Server handles 100 concurrent connections** without crash
//!
//! Marked `#[ignore]` — run explicitly with:
//! ```bash
//! cargo test --release sp5_threshold -- --ignored --nocapture
//! ```

mod common;

#[cfg(unix)]
extern crate libc;

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::Barrier;
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
// Thresholds
// ============================================================================

/// Maximum acceptable p95 message round-trip latency.
const P95_LATENCY_THRESHOLD: Duration = Duration::from_millis(500);

/// Maximum acceptable time to connect + handshake a single client.
const CONNECTION_SETUP_THRESHOLD: Duration = Duration::from_millis(200);

/// Number of concurrent WebSocket clients.
const NUM_CLIENTS: usize = 100;

/// Number of messages each client sends.
const MESSAGES_PER_CLIENT: usize = 10;

// ============================================================================
// Protocol helpers
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
    Arc<SqliteBlobStore>,
    Arc<ConnectionRegistry>,
) {
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let deps = ConnectionDeps {
        storage: storage.clone() as Arc<dyn BlobStore>,
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        device_sync_storage: Arc::new(SqliteDeviceSyncStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(10_000)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(1000)),
        registry: registry.clone(),
        blob_sender_map: handler::new_blob_sender_map(),
        max_message_size: 1_048_576,
        idle_timeout: Duration::from_secs(60),
        quota: QuotaLimits {
            max_blobs: 100_000,
            max_bytes: 100_000_000,
        },
        hint_store: None,
        noise_static_key: None,
        nonce_tracker: Arc::new(handler::NonceTracker::new()),
        delivery_jitter_min_ms: 0,
        delivery_jitter_max_ms: 0,
        relay_signing_key: None,
        metrics: RelayMetrics::new(),
    };
    (deps, storage, registry)
}

/// Starts a multi-connection test server. Returns the WebSocket URL.
async fn start_server(deps: ConnectionDeps) -> String {
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
                noise_static_key: None,
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

// ============================================================================
// Per-client result
// ============================================================================

/// Results collected from a single client's session.
struct ClientResult {
    /// Whether connection + handshake succeeded.
    connected: bool,
    /// Time taken to establish WebSocket connection and complete handshake.
    connection_setup_time: Duration,
    /// Number of messages successfully stored (received "Stored" ack).
    messages_stored: usize,
    /// Round-trip latencies for each successfully stored message.
    latencies: Vec<Duration>,
}

// ============================================================================
// p95 calculation
// ============================================================================

/// Computes the p95 value from a sorted slice of durations.
/// Requires at least one element; panics otherwise.
fn percentile_95(sorted: &[Duration]) -> Duration {
    assert!(!sorted.is_empty(), "Cannot compute p95 of empty slice");
    let index = ((sorted.len() as f64) * 0.95).ceil() as usize - 1;
    let index = index.min(sorted.len() - 1);
    sorted[index]
}

// ============================================================================
// Main threshold load test
// ============================================================================

/// SP-5 threshold-verifying WebSocket load test.
///
/// Spawns a relay, connects 100 concurrent clients (each sending 10 messages),
/// and asserts:
/// 1. p95 latency < 500ms
/// 2. Connection setup time < 200ms per client
/// 3. All 1000 messages delivered (zero dropped)
/// 4. Server handles 100 concurrent connections without crash
#[tokio::test]
#[ignore] // Load test — run with: cargo test --release sp5_threshold -- --ignored --nocapture
async fn test_sp5_threshold_concurrent_websocket_load() {
    // ---- fd limit check (skip on constrained environments) ----
    #[cfg(unix)]
    {
        use std::io;
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let ret = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) };
        if ret != 0 {
            eprintln!(
                "Warning: getrlimit failed ({}), proceeding anyway",
                io::Error::last_os_error()
            );
        } else if rlim.rlim_cur < 2048 {
            eprintln!(
                "Skipping test: fd limit {} < 2048 (run `ulimit -n 2048` to enable)",
                rlim.rlim_cur
            );
            return;
        }
    }

    // ---- setup ----
    let (deps, storage, registry) = test_deps();
    let url = start_server(deps).await;

    let expected_total_messages = NUM_CLIENTS * MESSAGES_PER_CLIENT;

    println!("\n=== SP-5 Threshold Load Test ===");
    println!("Clients:            {}", NUM_CLIENTS);
    println!("Messages/client:    {}", MESSAGES_PER_CLIENT);
    println!("Total messages:     {}", expected_total_messages);
    println!(
        "p95 threshold:      {}ms",
        P95_LATENCY_THRESHOLD.as_millis()
    );
    println!(
        "Setup threshold:    {}ms",
        CONNECTION_SETUP_THRESHOLD.as_millis()
    );
    println!();

    // ---- run clients concurrently ----
    // Use a barrier so all clients start their work roughly at the same time.
    let barrier = Arc::new(Barrier::new(NUM_CLIENTS));
    let mut handles = Vec::with_capacity(NUM_CLIENTS);

    for client_index in 0..NUM_CLIENTS {
        let url = url.clone();
        let barrier = barrier.clone();

        handles.push(tokio::spawn(async move {
            // Wait for all tasks to be spawned before starting.
            barrier.wait().await;

            let client_id = common::generate_test_client_id_wide(client_index as u16);

            // ---- connect + handshake ----
            let connect_start = Instant::now();

            let ws_result = timeout(Duration::from_secs(10), connect_async(&url)).await;
            let (mut ws, _) = match ws_result {
                Ok(Ok(pair)) => pair,
                _ => {
                    return ClientResult {
                        connected: false,
                        connection_setup_time: connect_start.elapsed(),
                        messages_stored: 0,
                        latencies: vec![],
                    };
                }
            };

            // Send handshake
            let hs_frame = encode_envelope(&make_handshake(&client_id));
            if ws.send(Message::Binary(hs_frame)).await.is_err() {
                return ClientResult {
                    connected: false,
                    connection_setup_time: connect_start.elapsed(),
                    messages_stored: 0,
                    latencies: vec![],
                };
            }

            // Wait for HandshakeAck
            let ack_ok = match timeout(Duration::from_secs(5), ws.next()).await {
                Ok(Some(Ok(Message::Binary(data)))) => {
                    let resp = decode_envelope(&data);
                    resp["payload"]["type"] == "HandshakeAck"
                }
                _ => false,
            };

            let connection_setup_time = connect_start.elapsed();

            if !ack_ok {
                return ClientResult {
                    connected: false,
                    connection_setup_time,
                    messages_stored: 0,
                    latencies: vec![],
                };
            }

            // ---- send messages ----
            let mut messages_stored = 0usize;
            let mut latencies = Vec::with_capacity(MESSAGES_PER_CLIENT);

            for msg_index in 0..MESSAGES_PER_CLIENT {
                // Each message goes to a distinct recipient to avoid contention
                let recipient_seed =
                    (NUM_CLIENTS + client_index * MESSAGES_PER_CLIENT + msg_index) as u16;
                let recipient_id = common::generate_test_client_id_wide(recipient_seed);
                let payload = vec![msg_index as u8; 64];
                let update = make_encrypted_update(&recipient_id, &payload);
                let frame = encode_envelope(&update);

                let send_start = Instant::now();
                if ws.send(Message::Binary(frame)).await.is_err() {
                    continue;
                }

                // Read response, skipping any pushed EncryptedUpdate or Delivered messages
                let deadline = Instant::now() + Duration::from_secs(10);
                loop {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }

                    match timeout(remaining, ws.next()).await {
                        Ok(Some(Ok(Message::Binary(data)))) => {
                            let resp = decode_envelope(&data);
                            let msg_type = resp["payload"]["type"].as_str().unwrap_or("");
                            // Skip pushed deliveries and delivered acks
                            if msg_type == "EncryptedUpdate" {
                                continue;
                            }
                            if msg_type == "Acknowledgment"
                                && resp["payload"]["status"] == "Delivered"
                            {
                                continue;
                            }
                            // This should be a Stored ack
                            if resp["payload"]["status"] == "Stored" {
                                let latency = send_start.elapsed();
                                messages_stored += 1;
                                latencies.push(latency);
                            }
                            break;
                        }
                        Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
                        _ => break,
                    }
                }
            }

            ws.close(None).await.ok();

            ClientResult {
                connected: true,
                connection_setup_time,
                messages_stored,
                latencies,
            }
        }));
    }

    // ---- collect results ----
    let mut total_connected = 0usize;
    let mut total_stored = 0usize;
    let mut all_latencies: Vec<Duration> = Vec::with_capacity(expected_total_messages);
    let mut all_setup_times: Vec<Duration> = Vec::with_capacity(NUM_CLIENTS);

    for handle in handles {
        let result = handle.await.expect("Client task panicked");
        if result.connected {
            total_connected += 1;
        }
        total_stored += result.messages_stored;
        all_latencies.extend(result.latencies);
        all_setup_times.push(result.connection_setup_time);
    }

    all_latencies.sort();
    all_setup_times.sort();

    // ---- compute metrics ----
    let p95_latency = if all_latencies.is_empty() {
        Duration::ZERO
    } else {
        percentile_95(&all_latencies)
    };

    let median_latency = if all_latencies.is_empty() {
        Duration::ZERO
    } else {
        all_latencies[all_latencies.len() / 2]
    };

    let max_latency = all_latencies.last().copied().unwrap_or(Duration::ZERO);
    let min_latency = all_latencies.first().copied().unwrap_or(Duration::ZERO);

    let max_setup_time = all_setup_times.last().copied().unwrap_or(Duration::ZERO);
    let p95_setup_time = if all_setup_times.is_empty() {
        Duration::ZERO
    } else {
        percentile_95(&all_setup_times)
    };

    let total_elapsed = all_latencies.iter().sum::<Duration>();
    let avg_latency = if all_latencies.is_empty() {
        Duration::ZERO
    } else {
        total_elapsed / all_latencies.len() as u32
    };

    let stored_in_storage = storage.blob_count();

    // ---- report ----
    println!("=== Results ===");
    println!(
        "Connections:        {}/{} succeeded",
        total_connected, NUM_CLIENTS
    );
    println!(
        "Messages stored:    {}/{}",
        total_stored, expected_total_messages
    );
    println!("Storage blob count: {}", stored_in_storage);
    println!();
    println!("--- Latency (message round-trip) ---");
    println!("  Min:    {:>8.2}ms", min_latency.as_secs_f64() * 1000.0);
    println!("  Median: {:>8.2}ms", median_latency.as_secs_f64() * 1000.0);
    println!("  Avg:    {:>8.2}ms", avg_latency.as_secs_f64() * 1000.0);
    println!("  p95:    {:>8.2}ms", p95_latency.as_secs_f64() * 1000.0);
    println!("  Max:    {:>8.2}ms", max_latency.as_secs_f64() * 1000.0);
    println!();
    println!("--- Connection setup ---");
    println!("  p95:    {:>8.2}ms", p95_setup_time.as_secs_f64() * 1000.0);
    println!("  Max:    {:>8.2}ms", max_setup_time.as_secs_f64() * 1000.0);
    println!();

    // Wait for cleanup before checking registry
    tokio::time::sleep(Duration::from_millis(500)).await;
    let remaining_connections = registry.connected_count();
    println!(
        "Registry after cleanup: {} connections",
        remaining_connections
    );
    println!();

    // ---- assertions ----

    // 1. Server handles 100 concurrent connections without crash
    assert_eq!(
        total_connected, NUM_CLIENTS,
        "All {} clients must connect successfully, but only {} did",
        NUM_CLIENTS, total_connected
    );

    // 2. No dropped messages — every message must be stored
    assert_eq!(
        total_stored,
        expected_total_messages,
        "All {} messages must be stored, but only {} were (dropped: {})",
        expected_total_messages,
        total_stored,
        expected_total_messages - total_stored
    );

    // Cross-check: storage layer must agree
    assert_eq!(
        stored_in_storage, expected_total_messages,
        "Storage blob count ({}) must equal expected ({})",
        stored_in_storage, expected_total_messages
    );

    // 3. p95 latency < 500ms
    assert!(
        p95_latency < P95_LATENCY_THRESHOLD,
        "p95 latency {:?} exceeds threshold {:?}",
        p95_latency,
        P95_LATENCY_THRESHOLD
    );

    // 4. Connection setup time p95 < 200ms
    assert!(
        p95_setup_time < CONNECTION_SETUP_THRESHOLD,
        "p95 connection setup time {:?} exceeds threshold {:?}",
        p95_setup_time,
        CONNECTION_SETUP_THRESHOLD
    );

    // 5. Registry should be empty after all connections closed
    assert_eq!(
        remaining_connections, 0,
        "Registry should be empty after all clients disconnect, but has {} connections",
        remaining_connections
    );

    println!("=== All SP-5 thresholds PASSED ===");
}

// ============================================================================
// Unit tests for the p95 helper
// ============================================================================

#[cfg(test)]
mod p95_tests {
    use super::*;

    #[test]
    fn test_percentile_95_single_element() {
        let values = [Duration::from_millis(42)];
        assert_eq!(percentile_95(&values), Duration::from_millis(42));
    }

    #[test]
    fn test_percentile_95_twenty_elements() {
        // 20 elements: p95 index = ceil(20 * 0.95) - 1 = ceil(19) - 1 = 18
        let mut values: Vec<Duration> = (1..=20).map(Duration::from_millis).collect();
        values.sort();
        assert_eq!(percentile_95(&values), Duration::from_millis(19));
    }

    #[test]
    fn test_percentile_95_hundred_elements() {
        // 100 elements: p95 index = ceil(100 * 0.95) - 1 = 95 - 1 = 94
        let mut values: Vec<Duration> = (1..=100).map(Duration::from_millis).collect();
        values.sort();
        assert_eq!(percentile_95(&values), Duration::from_millis(95));
    }

    #[test]
    fn test_percentile_95_all_equal() {
        let values = vec![Duration::from_millis(10); 50];
        assert_eq!(percentile_95(&values), Duration::from_millis(10));
    }

    #[test]
    #[should_panic(expected = "Cannot compute p95 of empty slice")]
    fn test_percentile_95_empty_panics() {
        let empty: Vec<Duration> = vec![];
        percentile_95(&empty);
    }
}
