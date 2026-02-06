// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Realistic Load Tests for the Relay Server
//!
//! Simulates real-world usage patterns to measure relay performance under
//! sustained, production-like conditions.
//!
//! ## Test Scenario
//!
//! - **Users**: 100 users, each with 50 contacts
//! - **Update Pattern**: 1 update per day to each contact
//! - **Simulation**: 30 days compressed into ~5 minutes
//! - **Measurements**: Memory usage, blob storage growth, sync latency
//!
//! ## Load Model
//!
//! Per simulated day:
//! - Each user sends 1 update to each of their 50 contacts
//! - Total: 100 users * 50 contacts = 5,000 updates per simulated day
//! - 30 days: 150,000 total updates
//!
//! Compression ratio: 30 days / 5 minutes = 8,640x time compression
//! - 1 simulated day = ~10 seconds real time
//!
//! ## Realistic Blob Sizes
//!
//! Contact card updates typically contain:
//! - Name, phone, email: ~200 bytes plaintext
//! - With encryption overhead (ChaCha20-Poly1305 nonce + tag): ~232 bytes
//! - With envelope metadata: ~300-500 bytes total
//!
//! This test uses 512-byte blobs to simulate realistic encrypted payloads.

mod common;

#[cfg(unix)]
extern crate libc;

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::Barrier;
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
// Test Configuration
// ============================================================================

/// Number of simulated users.
const NUM_USERS: usize = 100;

/// Number of contacts per user.
const CONTACTS_PER_USER: usize = 50;

/// Number of simulated days.
const SIMULATED_DAYS: usize = 30;

/// Target test duration in seconds (~5 minutes).
const TARGET_DURATION_SECS: u64 = 300;

/// Blob size in bytes (realistic encrypted contact update).
const BLOB_SIZE_BYTES: usize = 512;

/// Calculate updates per simulated day.
const fn updates_per_day() -> usize {
    NUM_USERS * CONTACTS_PER_USER
}

/// Calculate total updates for the entire simulation.
const fn total_updates() -> usize {
    updates_per_day() * SIMULATED_DAYS
}

/// Calculate real-time delay between simulated days (seconds).
const fn seconds_per_simulated_day() -> f64 {
    TARGET_DURATION_SECS as f64 / SIMULATED_DAYS as f64
}

// ============================================================================
// Protocol Helpers
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
// Test Infrastructure
// ============================================================================

/// Metrics collected during the load test.
#[derive(Debug, Default)]
struct LoadTestMetrics {
    /// Total messages sent successfully.
    messages_sent: AtomicUsize,
    /// Total messages that failed to store.
    messages_failed: AtomicUsize,
    /// Cumulative latency in microseconds (for average calculation).
    total_latency_us: AtomicU64,
    /// Maximum latency observed in microseconds.
    max_latency_us: AtomicU64,
    /// Minimum latency observed in microseconds.
    min_latency_us: AtomicU64,
}

impl LoadTestMetrics {
    fn new() -> Self {
        Self {
            messages_sent: AtomicUsize::new(0),
            messages_failed: AtomicUsize::new(0),
            total_latency_us: AtomicU64::new(0),
            max_latency_us: AtomicU64::new(0),
            min_latency_us: AtomicU64::new(u64::MAX),
        }
    }

    fn record_success(&self, latency: Duration) {
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
        let latency_us = latency.as_micros() as u64;
        self.total_latency_us
            .fetch_add(latency_us, Ordering::Relaxed);

        // Update max latency
        let mut current_max = self.max_latency_us.load(Ordering::Relaxed);
        while latency_us > current_max {
            match self.max_latency_us.compare_exchange_weak(
                current_max,
                latency_us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(c) => current_max = c,
            }
        }

        // Update min latency
        let mut current_min = self.min_latency_us.load(Ordering::Relaxed);
        while latency_us < current_min {
            match self.min_latency_us.compare_exchange_weak(
                current_min,
                latency_us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(c) => current_min = c,
            }
        }
    }

    fn record_failure(&self) {
        self.messages_failed.fetch_add(1, Ordering::Relaxed);
    }

    fn avg_latency_us(&self) -> f64 {
        let sent = self.messages_sent.load(Ordering::Relaxed);
        if sent == 0 {
            return 0.0;
        }
        self.total_latency_us.load(Ordering::Relaxed) as f64 / sent as f64
    }
}

/// Creates test dependencies with realistic quotas.
fn test_deps_realistic() -> (
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
        // High rate limit to avoid artificial bottlenecks in load testing
        rate_limiter: Arc::new(RateLimiter::new(10_000)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(1000)),
        registry: registry.clone(),
        blob_sender_map: handler::new_blob_sender_map(),
        max_message_size: 1_048_576,
        idle_timeout: Duration::from_secs(300),
        quota: QuotaLimits {
            // Allow up to 200k blobs per recipient (enough for 30 days)
            max_blobs: 200_000,
            max_bytes: 0,
        },
        hint_store: None,
        noise_static_key: None,
        require_noise_encryption: false,
        nonce_tracker: Arc::new(handler::NonceTracker::new()),
    };
    (deps, storage, registry)
}

/// Starts a multi-connection test server. Returns the URL.
async fn start_load_test_server(deps: ConnectionDeps) -> String {
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

/// Perform handshake, return success status.
async fn do_handshake(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    client_id: &str,
) -> bool {
    let frame = encode_envelope(&make_handshake(client_id));
    if ws.send(Message::Binary(frame)).await.is_err() {
        return false;
    }

    match timeout(Duration::from_secs(5), ws.next()).await {
        Ok(Some(Ok(Message::Binary(data)))) => {
            let resp = decode_envelope(&data);
            resp["payload"]["type"] == "HandshakeAck"
        }
        _ => false,
    }
}

/// Send a message and receive the response, measuring latency.
/// Handles interleaved EncryptedUpdate pushes by skipping them.
async fn send_recv_timed(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    msg: &Value,
) -> Result<(Value, Duration), ()> {
    let start = Instant::now();
    let frame = encode_envelope(msg);

    if ws.send(Message::Binary(frame)).await.is_err() {
        return Err(());
    }

    // Read responses, skipping any pushed EncryptedUpdate or Delivered messages
    // until we get a Stored acknowledgment
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(());
        }

        match timeout(remaining, ws.next()).await {
            Ok(Some(Ok(Message::Binary(data)))) => {
                let latency = start.elapsed();
                let response = decode_envelope(&data);

                // Skip pushed EncryptedUpdate messages (deliveries to us)
                // and Delivered acks (for blobs we sent earlier)
                let msg_type = response["payload"]["type"].as_str().unwrap_or("");
                if msg_type == "EncryptedUpdate" {
                    continue;
                }
                if msg_type == "Acknowledgment" && response["payload"]["status"] == "Delivered" {
                    continue;
                }

                return Ok((response, latency));
            }
            Ok(Some(Ok(Message::Ping(_)))) => continue,
            Ok(Some(Ok(Message::Pong(_)))) => continue,
            _ => return Err(()),
        }
    }
}

/// Generate deterministic contact ID for a user's contact.
fn contact_id_for(user: usize, contact_index: usize) -> String {
    // Each user has 50 unique contacts
    // Use modular arithmetic to create a deterministic but varied contact network
    let contact_user = (user + contact_index + 1) % NUM_USERS;
    common::generate_test_client_id_wide(contact_user as u16)
}

/// Generate realistic ciphertext payload.
fn generate_realistic_payload(day: usize, user: usize, contact: usize) -> Vec<u8> {
    // Create a deterministic but varied payload
    let seed = ((day as u32) << 16) | ((user as u32) << 8) | (contact as u32);
    (0..BLOB_SIZE_BYTES)
        .map(|i| (seed.wrapping_add(i as u32) & 0xFF) as u8)
        .collect()
}

// ============================================================================
// Storage Snapshot
// ============================================================================

/// Captures storage state at a point in time.
#[derive(Debug, Clone)]
struct StorageSnapshot {
    blob_count: usize,
    recipient_count: usize,
    storage_bytes: usize,
}

impl StorageSnapshot {
    fn capture(storage: &SqliteBlobStore) -> Self {
        Self {
            blob_count: storage.blob_count(),
            recipient_count: storage.recipient_count(),
            storage_bytes: storage.storage_size_bytes(),
        }
    }
}

// ============================================================================
// Main Load Test
// ============================================================================

/// Realistic load test simulating 100 users with 50 contacts each,
/// sending 1 update per day for 30 simulated days.
///
/// Compressed into ~5 minutes of real time.
///
/// Measurements:
/// - Relay memory usage (via storage metrics)
/// - Blob storage growth over time
/// - Sync latency (round-trip time for store operations)
///
/// Success criteria:
/// - >99% message success rate
/// - Average latency < 50ms
/// - Storage grows linearly (no memory leaks)
#[tokio::test]
async fn test_realistic_usage_pattern_30_days() {
    // Check file descriptor limit — skip on constrained environments
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
        } else if rlim.rlim_cur < 1024 {
            eprintln!(
                "Skipping test: fd limit {} < 1024 (run `ulimit -n 1024` to enable)",
                rlim.rlim_cur
            );
            return;
        }
    }

    println!("\n=== Realistic Load Test Configuration ===");
    println!("Users: {}", NUM_USERS);
    println!("Contacts per user: {}", CONTACTS_PER_USER);
    println!("Simulated days: {}", SIMULATED_DAYS);
    println!("Updates per day: {}", updates_per_day());
    println!("Total updates: {}", total_updates());
    println!("Blob size: {} bytes", BLOB_SIZE_BYTES);
    println!(
        "Expected storage: ~{} MB",
        (total_updates() * BLOB_SIZE_BYTES) / (1024 * 1024)
    );
    println!(
        "Target duration: {} seconds (~{:.1} minutes)",
        TARGET_DURATION_SECS,
        TARGET_DURATION_SECS as f64 / 60.0
    );
    println!(
        "Time compression: ~{:.0}x",
        (SIMULATED_DAYS as f64 * 86400.0) / TARGET_DURATION_SECS as f64
    );
    println!();

    let (deps, storage, _registry) = test_deps_realistic();
    let url = start_load_test_server(deps).await;

    let metrics = Arc::new(LoadTestMetrics::new());
    let mut daily_snapshots: Vec<StorageSnapshot> = Vec::with_capacity(SIMULATED_DAYS + 1);

    // Initial snapshot
    daily_snapshots.push(StorageSnapshot::capture(&storage));

    let test_start = Instant::now();

    // Run simulation day by day
    for day in 0..SIMULATED_DAYS {
        let day_start = Instant::now();
        println!("Day {}/{} starting...", day + 1, SIMULATED_DAYS);

        // Process all users in parallel batches
        // Use smaller batches to avoid overwhelming connections
        let batch_size = 10;
        for batch_start in (0..NUM_USERS).step_by(batch_size) {
            let batch_end = (batch_start + batch_size).min(NUM_USERS);
            let barrier = Arc::new(Barrier::new(batch_end - batch_start));
            let mut handles = Vec::new();

            for user in batch_start..batch_end {
                let url = url.clone();
                let metrics = metrics.clone();
                let barrier = barrier.clone();

                handles.push(tokio::spawn(async move {
                    // Wait for all batch members to be ready
                    barrier.wait().await;

                    let client_id = common::generate_test_client_id_wide(user as u16);

                    // Connect and handshake
                    let connect_result =
                        timeout(Duration::from_secs(10), connect_async(&url)).await;
                    let (mut ws, _) = match connect_result {
                        Ok(Ok((ws, _))) => (ws, ()),
                        _ => {
                            for _ in 0..CONTACTS_PER_USER {
                                metrics.record_failure();
                            }
                            return;
                        }
                    };

                    if !do_handshake(&mut ws, &client_id).await {
                        for _ in 0..CONTACTS_PER_USER {
                            metrics.record_failure();
                        }
                        return;
                    }

                    // Send update to each contact
                    for contact_idx in 0..CONTACTS_PER_USER {
                        let recipient_id = contact_id_for(user, contact_idx);
                        let payload = generate_realistic_payload(day, user, contact_idx);
                        let update = make_encrypted_update(&recipient_id, &payload);

                        match send_recv_timed(&mut ws, &update).await {
                            Ok((response, latency)) => {
                                if response["payload"]["status"] == "Stored" {
                                    metrics.record_success(latency);
                                } else {
                                    metrics.record_failure();
                                }
                            }
                            Err(_) => {
                                metrics.record_failure();
                            }
                        }
                    }

                    // Close connection gracefully
                    ws.close(None).await.ok();
                }));
            }

            // Wait for batch to complete
            for handle in handles {
                handle.await.ok();
            }

            // Small delay between batches to prevent connection storms
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Capture daily snapshot
        let snapshot = StorageSnapshot::capture(&storage);
        let day_elapsed = day_start.elapsed();

        println!(
            "  Day {} complete: {} blobs, {} bytes, {:.2}s",
            day + 1,
            snapshot.blob_count,
            snapshot.storage_bytes,
            day_elapsed.as_secs_f64()
        );

        daily_snapshots.push(snapshot);

        // Calculate delay needed to hit target duration
        let elapsed = test_start.elapsed().as_secs_f64();
        let target_elapsed = (day + 1) as f64 * seconds_per_simulated_day();
        let needed_delay = target_elapsed - elapsed;

        if needed_delay > 0.1 {
            tokio::time::sleep(Duration::from_secs_f64(needed_delay)).await;
        }
    }

    let total_elapsed = test_start.elapsed();

    // ========================================================================
    // Results and Assertions
    // ========================================================================

    println!("\n=== Load Test Results ===");

    let sent = metrics.messages_sent.load(Ordering::Relaxed);
    let failed = metrics.messages_failed.load(Ordering::Relaxed);
    let total = sent + failed;
    let success_rate = sent as f64 / total as f64 * 100.0;

    println!("Messages sent: {}/{}", sent, total);
    println!("Success rate: {:.2}%", success_rate);
    println!("Total duration: {:.2}s", total_elapsed.as_secs_f64());
    println!(
        "Throughput: {:.0} msgs/sec",
        sent as f64 / total_elapsed.as_secs_f64()
    );

    println!("\n--- Latency ---");
    let avg_latency_ms = metrics.avg_latency_us() / 1000.0;
    let min_latency_us = metrics.min_latency_us.load(Ordering::Relaxed);
    let max_latency_us = metrics.max_latency_us.load(Ordering::Relaxed);
    println!("Average: {:.2} ms", avg_latency_ms);
    println!(
        "Min: {:.2} ms",
        if min_latency_us == u64::MAX {
            0.0
        } else {
            min_latency_us as f64 / 1000.0
        }
    );
    println!("Max: {:.2} ms", max_latency_us as f64 / 1000.0);

    println!("\n--- Storage Growth ---");
    let final_snapshot = daily_snapshots.last().unwrap();
    println!("Final blob count: {}", final_snapshot.blob_count);
    println!("Final recipient count: {}", final_snapshot.recipient_count);
    println!(
        "Final storage: {} bytes ({:.2} MB)",
        final_snapshot.storage_bytes,
        final_snapshot.storage_bytes as f64 / (1024.0 * 1024.0)
    );

    // Calculate storage growth rate
    if daily_snapshots.len() >= 2 {
        println!("\n--- Daily Storage Progression ---");
        for (i, snapshot) in daily_snapshots.iter().enumerate() {
            if i == 0 {
                println!(
                    "  Initial: {} blobs, {} bytes",
                    snapshot.blob_count, snapshot.storage_bytes
                );
            } else {
                let prev = &daily_snapshots[i - 1];
                let blob_delta = snapshot.blob_count - prev.blob_count;
                let bytes_delta = snapshot.storage_bytes.saturating_sub(prev.storage_bytes);
                println!(
                    "  Day {:2}: {} blobs (+{}), {} bytes (+{})",
                    i, snapshot.blob_count, blob_delta, snapshot.storage_bytes, bytes_delta
                );
            }
        }
    }

    // ========================================================================
    // Assertions
    // ========================================================================

    // Success rate should be > 99%
    assert!(
        success_rate > 99.0,
        "Success rate {:.2}% should be > 99%",
        success_rate
    );

    // Average latency should be < 50ms
    assert!(
        avg_latency_ms < 50.0,
        "Average latency {:.2}ms should be < 50ms",
        avg_latency_ms
    );

    // Storage should have grown (sanity check)
    assert!(
        final_snapshot.blob_count > 0,
        "Should have stored some blobs"
    );

    // Storage growth should be roughly linear (check variance)
    // Each day should add approximately the same number of blobs
    if daily_snapshots.len() >= 5 {
        let mut daily_deltas: Vec<usize> = Vec::new();
        for i in 1..daily_snapshots.len() {
            daily_deltas.push(daily_snapshots[i].blob_count - daily_snapshots[i - 1].blob_count);
        }

        let expected_per_day = updates_per_day();
        let avg_delta: f64 = daily_deltas.iter().sum::<usize>() as f64 / daily_deltas.len() as f64;

        // Allow 20% variance from expected (due to timing and batching effects)
        let min_acceptable = expected_per_day as f64 * 0.8;
        let max_acceptable = expected_per_day as f64 * 1.2;

        assert!(
            avg_delta >= min_acceptable && avg_delta <= max_acceptable,
            "Average daily growth {:.0} should be within 20% of expected {}",
            avg_delta,
            expected_per_day
        );
    }

    println!("\n=== All assertions passed ===");
}

// ============================================================================
// Smaller Quick Test (for CI)
// ============================================================================

/// Quick realistic load test for CI environments.
///
/// Simulates 10 users with 10 contacts each for 5 simulated days.
/// Completes in ~30 seconds.
#[tokio::test]
async fn test_realistic_usage_pattern_quick() {
    const QUICK_USERS: usize = 10;
    const QUICK_CONTACTS: usize = 10;
    const QUICK_DAYS: usize = 5;

    println!("\n=== Quick Load Test ===");
    println!(
        "Config: {} users, {} contacts, {} days",
        QUICK_USERS, QUICK_CONTACTS, QUICK_DAYS
    );

    let (deps, storage, _) = test_deps_realistic();
    let url = start_load_test_server(deps).await;

    let metrics = Arc::new(LoadTestMetrics::new());
    let test_start = Instant::now();

    for day in 0..QUICK_DAYS {
        let mut handles = Vec::new();

        for user in 0..QUICK_USERS {
            let url = url.clone();
            let metrics = metrics.clone();

            handles.push(tokio::spawn(async move {
                let client_id = common::generate_test_client_id_wide(user as u16);

                let (mut ws, _) = match timeout(Duration::from_secs(5), connect_async(&url)).await {
                    Ok(Ok((ws, _))) => (ws, ()),
                    _ => {
                        for _ in 0..QUICK_CONTACTS {
                            metrics.record_failure();
                        }
                        return;
                    }
                };

                if !do_handshake(&mut ws, &client_id).await {
                    for _ in 0..QUICK_CONTACTS {
                        metrics.record_failure();
                    }
                    return;
                }

                for contact_idx in 0..QUICK_CONTACTS {
                    let recipient_id = common::generate_test_client_id_wide(
                        ((user + contact_idx + 1) % QUICK_USERS) as u16,
                    );
                    let payload: Vec<u8> = (0..BLOB_SIZE_BYTES).map(|i| i as u8).collect();
                    let update = make_encrypted_update(&recipient_id, &payload);

                    match send_recv_timed(&mut ws, &update).await {
                        Ok((response, latency)) => {
                            if response["payload"]["status"] == "Stored" {
                                metrics.record_success(latency);
                            } else {
                                metrics.record_failure();
                            }
                        }
                        Err(_) => {
                            metrics.record_failure();
                        }
                    }
                }

                ws.close(None).await.ok();
            }));
        }

        for handle in handles {
            handle.await.ok();
        }

        println!("Day {}/{} complete", day + 1, QUICK_DAYS);
    }

    let elapsed = test_start.elapsed();
    let sent = metrics.messages_sent.load(Ordering::Relaxed);
    let failed = metrics.messages_failed.load(Ordering::Relaxed);
    let total = sent + failed;

    println!("\nResults:");
    println!("  Messages: {}/{}", sent, total);
    println!("  Duration: {:.2}s", elapsed.as_secs_f64());
    println!("  Blob count: {}", storage.blob_count());
    println!("  Storage: {} bytes", storage.storage_size_bytes());

    let success_rate = if total > 0 {
        sent as f64 / total as f64 * 100.0
    } else {
        0.0
    };
    assert!(
        success_rate > 95.0,
        "Success rate {:.2}% should be > 95%",
        success_rate
    );
}

// ============================================================================
// Storage Growth Test
// ============================================================================

/// Tests that storage growth is linear and predictable.
///
/// This is a focused test that doesn't require WebSocket connections,
/// directly testing the storage layer behavior.
#[test]
fn test_storage_growth_linear() {
    let store = SqliteBlobStore::in_memory().unwrap();

    let num_days = 10;
    let blobs_per_day = 1000;
    let mut snapshots = Vec::new();

    snapshots.push((0, store.blob_count(), store.storage_size_bytes()));

    for day in 1..=num_days {
        for i in 0..blobs_per_day {
            let recipient = format!("recipient-{}", i % 100);
            let data = vec![day as u8; BLOB_SIZE_BYTES];
            store.store(&recipient, vauchi_relay::storage::StoredBlob::new(data));
        }

        snapshots.push((day, store.blob_count(), store.storage_size_bytes()));
    }

    println!("\n=== Storage Growth Analysis ===");
    let mut growth_rates: Vec<usize> = Vec::new();
    for i in 1..snapshots.len() {
        let (day, blobs, bytes) = snapshots[i];
        let (_, prev_blobs, _) = snapshots[i - 1];
        let delta = blobs - prev_blobs;
        growth_rates.push(delta);
        println!("Day {}: {} blobs (+{}), {} bytes", day, blobs, delta, bytes);
    }

    // All growth rates should be equal to blobs_per_day
    for rate in &growth_rates {
        assert_eq!(
            *rate, blobs_per_day,
            "Daily growth should be exactly {}",
            blobs_per_day
        );
    }

    // Final blob count should be num_days * blobs_per_day
    assert_eq!(
        store.blob_count(),
        num_days * blobs_per_day,
        "Total blobs should match expected"
    );

    println!("Storage growth is linear: OK");
}

// ============================================================================
// Memory Stability Test
// ============================================================================

/// Tests that storage remains stable after cleanup cycles.
///
/// Simulates the pattern of blobs being stored, then cleaned up
/// (simulating delivery or expiry).
#[test]
fn test_storage_stability_with_cleanup() {
    use std::time::Duration;

    let store = SqliteBlobStore::in_memory().unwrap();

    let cycles = 5;
    let blobs_per_cycle = 500;

    for cycle in 0..cycles {
        // Store blobs
        for i in 0..blobs_per_cycle {
            let recipient = format!("recipient-{}", i % 50);
            let data = vec![cycle as u8; BLOB_SIZE_BYTES];
            store.store(&recipient, vauchi_relay::storage::StoredBlob::new(data));
        }

        let after_store = store.blob_count();

        // Clean up all (with zero TTL)
        let removed = store.cleanup_expired(Duration::ZERO);

        let after_cleanup = store.blob_count();

        println!(
            "Cycle {}: stored {} -> {} blobs, cleaned {} -> {} blobs",
            cycle + 1,
            blobs_per_cycle,
            after_store,
            removed,
            after_cleanup
        );

        // After cleanup, all blobs should be removed
        assert_eq!(
            after_cleanup, 0,
            "All blobs should be removed after cleanup"
        );
    }

    // Final state should be empty
    assert_eq!(store.blob_count(), 0);
    println!("Storage stability with cleanup: OK");
}
