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

#[cfg(unix)]
extern crate libc;

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::accept_async;

use vauchi_relay::connection_registry::ConnectionRegistry;
use vauchi_relay::handler::{self, ConnectionDeps, QuotaLimits};
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::noise_key::generate_relay_keypair;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::recovery_storage::SqliteRecoveryProofStore;
use vauchi_relay::storage::{BlobStore, SqliteBlobStore};

use common::ws_helpers::{connect_noise, make_encrypted_update, make_handshake};

// ============================================================================
// Test infrastructure
// ============================================================================

/// Returns (deps, relay_pubkey, storage, registry)
fn test_deps() -> (
    ConnectionDeps,
    [u8; 32],
    Arc<SqliteBlobStore>,
    Arc<ConnectionRegistry>,
) {
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let kp = generate_relay_keypair();
    let relay_pub = kp.public;
    let deps = ConnectionDeps {
        storage: storage.clone() as Arc<dyn BlobStore>,
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
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
        noise_static_key: Some(kp.private),
        nonce_tracker: Arc::new(handler::NonceTracker::new()),
        delivery_jitter_min_ms: 0,
        delivery_jitter_max_ms: 0,
        relay_signing_key: None,
        metrics: RelayMetrics::new(),
        mailbox_registry: std::sync::Arc::new(parking_lot::RwLock::new(
            vauchi_relay::mailbox_registry::MailboxRegistry::new(),
        )),
    };
    (deps, relay_pub, storage, registry)
}

/// Returns (deps, relay_pubkey, storage, registry)
fn test_deps_custom(
    rate_limit: u32,
    idle_timeout: Duration,
    quota: QuotaLimits,
) -> (
    ConnectionDeps,
    [u8; 32],
    Arc<SqliteBlobStore>,
    Arc<ConnectionRegistry>,
) {
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let kp = generate_relay_keypair();
    let relay_pub = kp.public;
    let deps = ConnectionDeps {
        storage: storage.clone() as Arc<dyn BlobStore>,
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(rate_limit)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(100)),
        registry: registry.clone(),
        blob_sender_map: handler::new_blob_sender_map(),
        max_message_size: 1_048_576,
        idle_timeout,
        quota,
        hint_store: None,
        noise_static_key: Some(kp.private),
        nonce_tracker: Arc::new(handler::NonceTracker::new()),
        delivery_jitter_min_ms: 0,
        delivery_jitter_max_ms: 0,
        relay_signing_key: None,
        metrics: RelayMetrics::new(),
        mailbox_registry: std::sync::Arc::new(parking_lot::RwLock::new(
            vauchi_relay::mailbox_registry::MailboxRegistry::new(),
        )),
    };
    (deps, relay_pub, storage, registry)
}

/// Starts a multi-connection test server. Returns the URL.
async fn start_multi_server(deps: ConnectionDeps) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://127.0.0.1:{}", addr.port());

    let storage = deps.storage;
    let recovery_storage = deps.recovery_storage;
    let rate_limiter = deps.rate_limiter;
    let recovery_rate_limiter = deps.recovery_rate_limiter;
    let registry = deps.registry;
    let blob_sender_map = deps.blob_sender_map;
    let max_message_size = deps.max_message_size;
    let idle_timeout = deps.idle_timeout;
    let quota = deps.quota;
    let noise_static_key = deps.noise_static_key;

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let per_conn = ConnectionDeps {
                storage: storage.clone(),
                recovery_storage: recovery_storage.clone(),
                rate_limiter: rate_limiter.clone(),
                recovery_rate_limiter: recovery_rate_limiter.clone(),
                registry: registry.clone(),
                blob_sender_map: blob_sender_map.clone(),
                max_message_size,
                idle_timeout,
                quota,
                hint_store: None,
                noise_static_key,
                nonce_tracker: Arc::new(handler::NonceTracker::new()),
                delivery_jitter_min_ms: 0,
                delivery_jitter_max_ms: 0,
                relay_signing_key: None,
                metrics: RelayMetrics::new(),
                mailbox_registry: std::sync::Arc::new(parking_lot::RwLock::new(
                    vauchi_relay::mailbox_registry::MailboxRegistry::new(),
                )),
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
// Test 1: Concurrent connections
// ============================================================================

/// 1000 concurrent WebSocket clients all do handshake + hold + close.
/// Assert >= 850 succeed (some may fail under OS resource pressure).
///
/// Connections are batched in waves of 200 to avoid exhausting file
/// descriptors all at once on resource-constrained CI runners.
///
/// NOTE: Requires sufficient file descriptor limits (ulimit -n >= 4096).
/// Each connection uses ~2 fds (client + server side).
/// The test is skipped if the fd limit is too low.
#[tokio::test]
async fn test_1000_concurrent_websocket_connections() {
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
        } else if rlim.rlim_cur < 4096 {
            eprintln!(
                "Skipping test: fd limit {} < 4096 (run `ulimit -n 4096` to enable)",
                rlim.rlim_cur
            );
            return;
        }
    }

    let (deps, relay_pub, _, registry) = test_deps();
    let url = start_multi_server(deps).await;

    let num_clients = 1000u16;
    let wave_size = 200u16;
    let mut total_successes = 0u16;

    // Batch connections in waves to reduce fd pressure
    for wave_start in (0..num_clients).step_by(wave_size as usize) {
        let wave_end = (wave_start + wave_size).min(num_clients);
        let mut handles = vec![];

        for i in wave_start..wave_end {
            let url = url.clone();
            handles.push(tokio::spawn(async move {
                let client_id = common::generate_test_client_id_wide(i);
                match timeout(Duration::from_secs(15), connect_noise(&url, &relay_pub)).await {
                    Ok(mut client) => {
                        let hs = make_handshake(&client_id);
                        client.send_envelope(&hs).await;
                        // Wait for HandshakeAck
                        match timeout(Duration::from_secs(10), client.recv()).await {
                            Ok(resp) => {
                                let ok = resp["payload"]["type"] == "HandshakeAck";
                                // Hold connection briefly
                                tokio::time::sleep(Duration::from_millis(50)).await;
                                client.close().await;
                                ok
                            }
                            _ => false,
                        }
                    }
                    _ => false,
                }
            }));
        }

        for handle in handles {
            if handle.await.unwrap_or(false) {
                total_successes += 1;
            }
        }

        // Brief pause between waves to let fds reclaim
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        total_successes >= 850,
        "Expected >= 850 successful connections, got {}",
        total_successes
    );

    // Poll until registry is empty (bounded to avoid infinite wait)
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while registry.connected_count() > 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "Registry still has {} connections after 5s deadline",
            registry.connected_count()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
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
    let (deps, relay_pub, storage, _) = test_deps();
    let url = start_multi_server(deps).await;

    let mut client = connect_noise(&url, &relay_pub).await;
    let sender_id = common::generate_test_client_id(1);
    let _ack = client.do_handshake(&sender_id).await;

    let start = Instant::now();
    let msg_count = 1000;

    for i in 0..msg_count {
        let recipient_id = common::generate_test_client_id((i % 200 + 2) as u8);
        let update = make_encrypted_update(&recipient_id, &[i as u8; 32]);
        let response = client.send_recv(&update).await;
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

    client.close().await;
}

// ============================================================================
// Test 3: Multi-client message throughput
// ============================================================================

/// 10 concurrent clients each sending 100 messages.
/// Assert all messages stored. Measure aggregate throughput.
#[tokio::test]
async fn test_multi_client_throughput() {
    let (deps, relay_pub, storage, _) = test_deps();
    let url = start_multi_server(deps).await;

    let num_clients = 10;
    let msgs_per_client = 100;
    let start = Instant::now();

    let mut handles = vec![];
    for c in 0..num_clients {
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let client_id = common::generate_test_client_id(c as u8);
            let mut client = connect_noise(&url, &relay_pub).await;
            let _ack = client.do_handshake(&client_id).await;

            let mut stored = 0usize;
            for i in 0..msgs_per_client {
                // Each client sends to a unique set of recipients
                let recipient_id =
                    common::generate_test_client_id(((c * msgs_per_client + i) % 200 + 50) as u8);
                let update = make_encrypted_update(&recipient_id, &[i as u8; 16]);
                let response = client.send_recv(&update).await;
                if response["payload"]["status"] == "Stored" {
                    stored += 1;
                }
            }

            client.close().await;
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
    let (deps, relay_pub, storage, _) = test_deps_custom(
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
            let mut client = connect_noise(&url, &relay_pub).await;
            let _ack = client.do_handshake(&client_id).await;

            let mut stored = 0usize;
            let recipient_id = common::generate_test_client_id(200 + c as u8);
            for i in 0..msgs_per_client {
                let update = make_encrypted_update(&recipient_id, &[i as u8]);
                client.send_envelope(&update).await;

                // Rate-limited messages get no response — use try_recv with timeout
                match timeout(Duration::from_millis(500), async {
                    client.try_recv().await
                })
                .await
                {
                    Ok(Some(resp)) if resp["payload"]["status"] == "Stored" => {
                        stored += 1;
                    }
                    _ => {
                        // No response or rate-limited — continue
                    }
                }
            }

            client.close().await;
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
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let blob_sender_map = handler::new_blob_sender_map();
    let kp = generate_relay_keypair();
    let relay_pub = kp.public;

    let make_local_deps = |s: Arc<SqliteBlobStore>,
                           r: Arc<ConnectionRegistry>,
                           bsm: handler::BlobSenderMap,
                           noise_priv: [u8; 32]|
     -> ConnectionDeps {
        ConnectionDeps {
            storage: s as Arc<dyn BlobStore>,
            recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
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
            noise_static_key: Some(noise_priv),
            nonce_tracker: Arc::new(handler::NonceTracker::new()),
            delivery_jitter_min_ms: 0,
            delivery_jitter_max_ms: 0,
            relay_signing_key: None,
            metrics: RelayMetrics::new(),
            mailbox_registry: std::sync::Arc::new(parking_lot::RwLock::new(
                vauchi_relay::mailbox_registry::MailboxRegistry::new(),
            )),
        }
    };

    let deps = make_local_deps(
        storage.clone(),
        registry.clone(),
        blob_sender_map.clone(),
        kp.private,
    );
    let url = start_multi_server(deps).await;

    let sender_id = common::generate_test_client_id(1);
    let recipient_id = common::generate_test_client_id(2);

    // Connect sender
    let mut sender = connect_noise(&url, &relay_pub).await;
    let _ack = sender.do_handshake(&sender_id).await;

    // Sender stores a blob
    let update = make_encrypted_update(&recipient_id, &[1, 2, 3, 4, 5]);
    let stored_ack = sender.send_recv(&update).await;
    assert_eq!(stored_ack["payload"]["status"], "Stored");

    let start = Instant::now();

    // Recipient connects — triggers delivery + Delivered ack to sender
    let mut recipient = connect_noise(&url, &relay_pub).await;
    let hs = make_handshake(&recipient_id);
    recipient.send_envelope(&hs).await;

    // Recipient: HandshakeAck
    let _ack = recipient.recv().await;
    // Recipient: blob delivery
    let blob = recipient.recv().await;
    assert_eq!(blob["payload"]["type"], "EncryptedUpdate");

    // Sender: wait for Delivered ack
    let delivered = timeout(Duration::from_secs(2), async {
        loop {
            if let Some(msg) = sender.try_recv().await
                && msg["payload"]["type"] == "Acknowledgment"
                && msg["payload"]["status"] == "Delivered"
            {
                return msg;
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

    sender.close().await;
    recipient.close().await;
}

// ============================================================================
// Test 6: Connection lifecycle (idle timeout + reconnect)
// ============================================================================

/// Connect with short idle timeout, wait for timeout, reconnect.
/// Assert second connection works.
#[tokio::test]
async fn test_idle_timeout_and_reconnect() {
    let (deps, relay_pub, _, _) = test_deps_custom(
        1000,
        Duration::from_millis(500), // 500ms idle timeout
        QuotaLimits {
            max_blobs: 1000,
            max_bytes: 0,
        },
    );
    let url = start_multi_server(deps).await;

    let client_id = common::generate_test_client_id(1);

    // First connection — use Noise; after handshake we hold and wait for idle close
    let mut client1 = connect_noise(&url, &relay_pub).await;
    let ack = client1.do_handshake(&client_id).await;
    assert_eq!(ack["payload"]["type"], "HandshakeAck");

    // Wait for idle timeout — server will close the WS stream
    // Poll until we get a close or an error (CC-06: bounded wait, no bare sleep)
    let timed_out = timeout(Duration::from_secs(3), async {
        loop {
            match client1.try_recv().await {
                None => {
                    // No message yet — keep waiting
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Some(_) => {
                    // Any message (incl. Close frame decoded as JSON error) means server sent something
                    return;
                }
            }
        }
    })
    .await;
    // Whether we timed out or got a close, the connection is dead — that's fine

    drop(client1);
    // Give server a moment to clean up
    let _ = timed_out;

    // Reconnect — should work
    let mut client2 = connect_noise(&url, &relay_pub).await;
    let ack2 = client2.do_handshake(&client_id).await;
    assert_eq!(ack2["payload"]["type"], "HandshakeAck");

    // Verify the reconnected session works
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[42u8]);
    let response = client2.send_recv(&update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    client2.close().await;
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
