// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Federation Load Tests
//!
//! Performance and stress tests for the relay federation subsystem.
//! Simulates realistic multi-relay scenarios to verify federation
//! behavior under load.
//!
//! ## Test Scenarios
//!
//! 1. **Multi-Relay Federation**: 3 federated relays with 1000 users
//! 2. **Offload Under Load**: Verify offload behavior when storage exceeds threshold
//! 3. **Gossip Convergence**: Measure time for peer advertisements to propagate
//! 4. **Network Partition Recovery**: Test reconnection after simulated partition
//!
//! ## Federation Topology
//!
//! ```text
//!     ┌─────────────┐
//!     │   Relay A   │ ◄── 334 users
//!     └──────┬──────┘
//!            │
//!     ┌──────┼──────┐
//!     ▼      ▼      ▼
//! ┌───────┐ ┌───────┐ ┌───────┐
//! │Relay B│ │Relay C│ │Relay D│ (for partition tests)
//! └───────┘ └───────┘ └───────┘
//!  333 users 333 users
//! ```

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_async, connect_async};

use vauchi_relay::config::RelayConfig;
use vauchi_relay::connection_registry::ConnectionRegistry;
use vauchi_relay::device_sync_storage::SqliteDeviceSyncStore;
use vauchi_relay::federation_connector::OffloadManager;
use vauchi_relay::federation_handler::{self, FederationDeps};
use vauchi_relay::federation_protocol::{
    self, AdvertisedPeer, FederationEnvelope, FederationPayload, FEDERATION_PROTOCOL_VERSION,
};
use vauchi_relay::forwarding_hints::{ForwardingHintStore, SqliteForwardingHintStore};
use vauchi_relay::handler::{self, ConnectionDeps, QuotaLimits};
use vauchi_relay::integrity;
use vauchi_relay::peer_registry::{gossip, PeerInfo, PeerOrigin, PeerRegistry, PeerStatus};
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::recovery_storage::SqliteRecoveryProofStore;
use vauchi_relay::storage::{BlobStore, SqliteBlobStore, StoredBlob};

// ============================================================================
// Protocol helpers
// ============================================================================

const FRAME_HEADER_SIZE: usize = 4;

/// Encodes a FederationEnvelope to wire format.
fn encode_fed(envelope: &FederationEnvelope) -> Vec<u8> {
    federation_protocol::encode_federation_message(envelope).unwrap()
}

/// Decodes wire bytes to FederationEnvelope.
fn decode_fed(data: &[u8]) -> FederationEnvelope {
    federation_protocol::decode_federation_message(data).unwrap()
}

/// Encodes a client protocol JSON value to wire format.
fn encode_client(envelope: &serde_json::Value) -> Vec<u8> {
    let json = serde_json::to_vec(envelope).unwrap();
    let len = json.len() as u32;
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + json.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&json);
    frame
}

/// Decodes client protocol wire bytes to JSON.
fn decode_client(data: &[u8]) -> serde_json::Value {
    assert!(data.len() >= FRAME_HEADER_SIZE, "Frame too short");
    serde_json::from_slice(&data[FRAME_HEADER_SIZE..]).unwrap()
}

/// Creates a PeerHandshake message.
fn make_peer_handshake(relay_id: &str, listen_addr: &str) -> FederationEnvelope {
    federation_protocol::create_federation_envelope(FederationPayload::PeerHandshake {
        relay_id: relay_id.to_string(),
        version: FEDERATION_PROTOCOL_VERSION,
        listen_addr: listen_addr.to_string(),
    })
}

/// Creates an OffloadBlob message with correct integrity hash.
#[allow(dead_code)]
fn make_offload_blob(
    blob_id: &str,
    routing_id: &str,
    data: &[u8],
    hop_count: u8,
) -> FederationEnvelope {
    let hash = integrity::compute_integrity_hash(data);
    federation_protocol::create_federation_envelope(FederationPayload::OffloadBlob {
        blob_id: blob_id.to_string(),
        routing_id: routing_id.to_string(),
        data: data.to_vec(),
        created_at_secs: now_secs(),
        integrity_hash: hash,
        hop_count,
    })
}

/// Creates a CapacityReport message.
#[allow(dead_code)]
fn make_capacity_report(used: usize, max: usize, count: usize) -> FederationEnvelope {
    federation_protocol::create_federation_envelope(FederationPayload::CapacityReport {
        used_bytes: used,
        max_bytes: max,
        blob_count: count,
    })
}

/// Creates a PeerAdvertisement message.
#[allow(dead_code)]
fn make_peer_advertisement(peers: Vec<AdvertisedPeer>) -> FederationEnvelope {
    federation_protocol::create_federation_envelope(FederationPayload::PeerAdvertisement { peers })
}

/// Creates a client Handshake message.
fn make_client_handshake(client_id: &str) -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": now_secs(),
        "payload": {
            "type": "Handshake",
            "client_id": client_id
        }
    })
}

/// Creates a client EncryptedUpdate message.
fn make_encrypted_update(recipient_id: &str, ciphertext: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": now_secs(),
        "payload": {
            "type": "EncryptedUpdate",
            "recipient_id": recipient_id,
            "ciphertext": ciphertext.to_vec()
        }
    })
}

/// Returns current unix timestamp in seconds.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ============================================================================
// Test infrastructure
// ============================================================================

/// Configuration for a simulated relay.
struct SimulatedRelay {
    relay_id: String,
    storage: Arc<SqliteBlobStore>,
    hint_store: Arc<SqliteForwardingHintStore>,
    peer_registry: Arc<PeerRegistry>,
    config: Arc<RelayConfig>,
    federation_url: String,
    client_url: String,
}

/// Creates a test RelayConfig for federation.
fn make_fed_config(relay_id: &str, max_storage: usize, offload_threshold: f64) -> Arc<RelayConfig> {
    Arc::new(RelayConfig {
        max_storage_bytes: max_storage,
        federation_enabled: true,
        federation_relay_id: relay_id.to_string(),
        federation_offload_threshold: offload_threshold,
        federation_offload_refuse: 0.95,
        federation_peer_timeout_secs: 5,
        federation_capacity_interval_secs: 1,
        federation_gossip_interval_secs: 1,
        federation_peer_ttl_secs: 60,
        ..Default::default()
    })
}

/// Creates client ConnectionDeps.
fn make_client_deps(
    storage: Arc<dyn BlobStore>,
    registry: Arc<ConnectionRegistry>,
    hint_store: Option<Arc<dyn ForwardingHintStore>>,
) -> ConnectionDeps {
    ConnectionDeps {
        storage,
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        device_sync_storage: Arc::new(SqliteDeviceSyncStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(1000)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(100)),
        registry,
        blob_sender_map: handler::new_blob_sender_map(),
        max_message_size: 1_048_576,
        idle_timeout: Duration::from_secs(30),
        quota: QuotaLimits {
            max_blobs: 100_000,
            max_bytes: 100_000_000,
        },
        hint_store,
        noise_static_key: None,
        require_noise_encryption: false,
        nonce_tracker: Arc::new(handler::NonceTracker::new()),
    }
}

/// Starts a federation server that accepts multiple connections.
async fn start_federation_server(deps: FederationDeps) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://127.0.0.1:{}", addr.port());

    let storage = deps.storage;
    let hint_store = deps.hint_store;
    let peer_registry = deps.peer_registry;
    let config = deps.config;

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let fed_deps = FederationDeps {
                storage: storage.clone(),
                hint_store: hint_store.clone(),
                peer_registry: peer_registry.clone(),
                config: config.clone(),
            };
            tokio::spawn(async move {
                if let Ok(ws) = accept_async(stream).await {
                    federation_handler::handle_federation_connection(ws, fed_deps).await;
                }
            });
        }
    });

    url
}

/// Starts a client server that accepts multiple connections.
async fn start_client_server(deps: ConnectionDeps) -> String {
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
    let hint_store = deps.hint_store;

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
                hint_store: hint_store.clone(),
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

/// Creates and starts a simulated relay with both federation and client endpoints.
async fn create_relay(
    relay_id: &str,
    max_storage: usize,
    offload_threshold: f64,
) -> SimulatedRelay {
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let hint_store = Arc::new(SqliteForwardingHintStore::in_memory().unwrap());
    let peer_registry = Arc::new(PeerRegistry::new(0.95));
    let config = make_fed_config(relay_id, max_storage, offload_threshold);
    let connection_registry = Arc::new(ConnectionRegistry::new());

    let federation_url = start_federation_server(FederationDeps {
        storage: storage.clone() as Arc<dyn BlobStore>,
        hint_store: hint_store.clone() as Arc<dyn ForwardingHintStore>,
        peer_registry: peer_registry.clone(),
        config: config.clone(),
    })
    .await;

    let client_url = start_client_server(make_client_deps(
        storage.clone() as Arc<dyn BlobStore>,
        connection_registry,
        Some(hint_store.clone() as Arc<dyn ForwardingHintStore>),
    ))
    .await;

    SimulatedRelay {
        relay_id: relay_id.to_string(),
        storage,
        hint_store,
        peer_registry,
        config,
        federation_url,
        client_url,
    }
}

/// Performs a federation handshake as a peer connecting to the server.
async fn do_federation_handshake(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    our_relay_id: &str,
    listen_addr: &str,
) -> Result<FederationPayload, String> {
    let hs = make_peer_handshake(our_relay_id, listen_addr);
    ws.send(Message::Binary(encode_fed(&hs)))
        .await
        .map_err(|e| e.to_string())?;

    let msg = timeout(Duration::from_secs(5), ws.next())
        .await
        .map_err(|_| "Timeout waiting for handshake ack")?
        .ok_or("Stream ended")?
        .map_err(|e| e.to_string())?;

    match msg {
        Message::Binary(data) => Ok(decode_fed(&data).payload),
        other => Err(format!("Expected Binary message, got {:?}", other)),
    }
}

/// Establishes federation connections between relays.
async fn connect_relays(
    source: &SimulatedRelay,
    target: &SimulatedRelay,
) -> Result<mpsc::Sender<Vec<u8>>, String> {
    let (mut ws, _) = connect_async(&target.federation_url)
        .await
        .map_err(|e| e.to_string())?;

    let ack = do_federation_handshake(&mut ws, &source.relay_id, &source.federation_url).await?;

    match ack {
        FederationPayload::PeerHandshakeAck {
            accepted,
            relay_id,
            capacity_used_bytes,
            capacity_max_bytes,
            ..
        } => {
            if !accepted {
                return Err("Handshake rejected".to_string());
            }

            let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);

            // Register peer in source's registry
            source.peer_registry.register_peer(PeerInfo {
                relay_id: relay_id.clone(),
                url: target.federation_url.clone(),
                capacity_used_bytes,
                capacity_max_bytes,
                status: PeerStatus::Connected,
                sender: Some(tx.clone()),
                origin: PeerOrigin::Configured,
                last_seen_secs: now_secs(),
            });

            // Spawn task to forward messages from channel to WebSocket
            let (mut write, mut read) = ws.split();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        Some(data) = rx.recv() => {
                            if write.send(Message::Binary(data)).await.is_err() {
                                break;
                            }
                        }
                        msg = read.next() => {
                            match msg {
                                Some(Ok(Message::Binary(_))) => {
                                    // Process incoming messages (acks, capacity reports, etc.)
                                }
                                Some(Ok(Message::Close(_))) | None => break,
                                _ => {}
                            }
                        }
                    }
                }
            });

            Ok(tx)
        }
        other => Err(format!("Expected PeerHandshakeAck, got {:?}", other)),
    }
}

// ============================================================================
// Test 1: Multi-Relay Federation with 1000 Users
// ============================================================================

/// Simulates a 3-relay federation with 1000 users distributed across relays.
/// Each user connects, sends messages, and receives messages.
///
/// User distribution:
/// - Relay A: users 0-333 (334 users)
/// - Relay B: users 334-666 (333 users)
/// - Relay C: users 667-999 (333 users)
///
/// Message flow: Each user sends a message to a random user on a different relay.
#[tokio::test]
async fn test_federation_1000_users_across_3_relays() {
    let relay_a = create_relay("relay-A", 10_000_000, 0.80).await;
    let relay_b = create_relay("relay-B", 10_000_000, 0.80).await;
    let relay_c = create_relay("relay-C", 10_000_000, 0.80).await;

    // Establish federation connections between all relays
    let _ab = connect_relays(&relay_a, &relay_b).await.unwrap();
    let _ac = connect_relays(&relay_a, &relay_c).await.unwrap();
    let _ba = connect_relays(&relay_b, &relay_a).await.unwrap();
    let _bc = connect_relays(&relay_b, &relay_c).await.unwrap();
    let _ca = connect_relays(&relay_c, &relay_a).await.unwrap();
    let _cb = connect_relays(&relay_c, &relay_b).await.unwrap();

    // Wait for connections to establish
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify peer registrations
    assert_eq!(relay_a.peer_registry.connected_peers().len(), 2);
    assert_eq!(relay_b.peer_registry.connected_peers().len(), 2);
    assert_eq!(relay_c.peer_registry.connected_peers().len(), 2);

    let total_users = 1000u16;
    let users_per_batch = 50u16;
    let successful_connections = Arc::new(AtomicUsize::new(0));
    let successful_sends = Arc::new(AtomicUsize::new(0));

    let start = Instant::now();

    // Process users in batches to avoid fd exhaustion
    for batch_start in (0..total_users).step_by(users_per_batch as usize) {
        let batch_end = (batch_start + users_per_batch).min(total_users);
        let mut handles = vec![];

        for user_id in batch_start..batch_end {
            // Determine which relay this user connects to
            let relay_url = if user_id < 334 {
                relay_a.client_url.clone()
            } else if user_id < 667 {
                relay_b.client_url.clone()
            } else {
                relay_c.client_url.clone()
            };

            let conn_counter = successful_connections.clone();
            let send_counter = successful_sends.clone();

            handles.push(tokio::spawn(async move {
                let client_id = common::generate_test_client_id_wide(user_id);

                if let Ok(Ok((mut ws, _))) =
                    timeout(Duration::from_secs(10), connect_async(&relay_url)).await
                {
                    // Handshake
                    let hs = make_client_handshake(&client_id);
                    if ws.send(Message::Binary(encode_client(&hs))).await.is_err() {
                        return;
                    }

                    // Wait for HandshakeAck
                    let Ok(Some(Ok(Message::Binary(data)))) =
                        timeout(Duration::from_secs(5), ws.next()).await
                    else {
                        return;
                    };
                    let resp = decode_client(&data);
                    if resp["payload"]["type"] != "HandshakeAck" {
                        return;
                    }
                    conn_counter.fetch_add(1, Ordering::Relaxed);

                    // Send a message to a user on a different relay
                    let target_user = (user_id + 400) % 1000;
                    let recipient_id = common::generate_test_client_id_wide(target_user);
                    let update = make_encrypted_update(&recipient_id, &[user_id as u8; 32]);

                    if ws
                        .send(Message::Binary(encode_client(&update)))
                        .await
                        .is_ok()
                    {
                        // Wait for Stored ack
                        if let Ok(Some(Ok(Message::Binary(data)))) =
                            timeout(Duration::from_secs(5), ws.next()).await
                        {
                            let resp = decode_client(&data);
                            if resp["payload"]["status"] == "Stored" {
                                send_counter.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }

                    ws.close(None).await.ok();
                }
            }));
        }

        // Wait for batch to complete
        for handle in handles {
            let _ = handle.await;
        }

        // Brief pause between batches
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let elapsed = start.elapsed();
    let connected = successful_connections.load(Ordering::Relaxed);
    let sent = successful_sends.load(Ordering::Relaxed);

    eprintln!(
        "Federation load test: {} connections, {} messages in {:?}",
        connected, sent, elapsed
    );
    eprintln!(
        "Connection rate: {:.0}/s, Message rate: {:.0}/s",
        connected as f64 / elapsed.as_secs_f64(),
        sent as f64 / elapsed.as_secs_f64()
    );

    // Assert high success rate (allow some failures under load)
    assert!(
        connected >= 900,
        "Expected >= 900 connections, got {}",
        connected
    );
    assert!(sent >= 850, "Expected >= 850 messages sent, got {}", sent);

    // Verify blobs were stored across all relays
    let total_blobs =
        relay_a.storage.blob_count() + relay_b.storage.blob_count() + relay_c.storage.blob_count();
    assert!(
        total_blobs >= 850,
        "Expected >= 850 blobs across all relays, got {}",
        total_blobs
    );
}

// ============================================================================
// Test 2: Offload Under Load
// ============================================================================

/// Tests that blobs are correctly offloaded when a relay's storage exceeds
/// the configured threshold while under load.
#[tokio::test]
async fn test_offload_under_load() {
    // Create relay A with very small storage to trigger offload quickly
    let relay_a = create_relay("relay-A", 10_000, 0.50).await; // 50% threshold
    let relay_b = create_relay("relay-B", 1_000_000, 0.80).await;

    // Connect A -> B
    let _ab = connect_relays(&relay_a, &relay_b).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Store blobs on relay A until we exceed threshold
    let num_blobs = 50;
    for i in 0..num_blobs {
        let routing_id = format!("user-{}", i);
        let blob = StoredBlob::new(vec![i as u8; 200]); // 200 bytes each
        relay_a.storage.store(&routing_id, blob);
    }

    // Verify blobs stored
    assert_eq!(relay_a.storage.blob_count(), num_blobs);
    let initial_size = relay_a.storage.storage_size_bytes();
    eprintln!(
        "Initial storage: {} bytes ({} blobs)",
        initial_size, num_blobs
    );

    // Run offload manager
    let manager = OffloadManager {
        storage: relay_a.storage.clone() as Arc<dyn BlobStore>,
        hint_store: relay_a.hint_store.clone() as Arc<dyn ForwardingHintStore>,
        peer_registry: relay_a.peer_registry.clone(),
        config: relay_a.config.clone(),
    };

    let mut total_offloaded = 0;
    for _ in 0..10 {
        let offloaded = manager.check_and_offload().await;
        total_offloaded += offloaded;
        if offloaded == 0 {
            break;
        }
        // Give time for messages to propagate
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let final_blob_count = relay_a.storage.blob_count();
    eprintln!(
        "Offloaded {} blobs, {} remaining",
        total_offloaded, final_blob_count
    );

    // Verify offload occurred
    assert!(total_offloaded > 0, "Expected some blobs to be offloaded");

    // Verify forwarding hints were created
    assert!(
        relay_a.hint_store.hint_count() > 0,
        "Expected forwarding hints to be created"
    );

    // Verify blob count decreased
    // Note: SQLite doesn't immediately reclaim storage space after DELETE,
    // but blob_count accurately reflects the number of stored blobs.
    assert!(
        final_blob_count < num_blobs,
        "Blob count should have decreased after offload: {} -> {}",
        num_blobs,
        final_blob_count
    );
}

// ============================================================================
// Test 3: Gossip Convergence Time
// ============================================================================

/// Measures how quickly peer information propagates through gossip.
/// Creates a chain of relays and measures convergence time.
#[tokio::test]
async fn test_gossip_convergence_time() {
    // Create 3 relays in a chain: A <-> B <-> C
    let relay_a = create_relay("relay-A", 1_000_000, 0.80).await;
    let relay_b = create_relay("relay-B", 1_000_000, 0.80).await;
    let relay_c = create_relay("relay-C", 1_000_000, 0.80).await;

    // Connect A <-> B and B <-> C (but NOT A <-> C directly)
    let _ab = connect_relays(&relay_a, &relay_b).await.unwrap();
    let _ba = connect_relays(&relay_b, &relay_a).await.unwrap();
    let _bc = connect_relays(&relay_b, &relay_c).await.unwrap();
    let _cb = connect_relays(&relay_c, &relay_b).await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Initially, relay A only knows B, and relay C only knows B
    assert_eq!(relay_a.peer_registry.connected_peers().len(), 1);
    assert_eq!(relay_c.peer_registry.connected_peers().len(), 1);

    let start = Instant::now();

    // Simulate gossip: B advertises its peers (A and C) to A
    let peers_to_advertise = vec![AdvertisedPeer {
        relay_id: "relay-C".to_string(),
        url: relay_c.federation_url.clone(),
        capacity_pct: 50,
        last_seen_secs: now_secs(),
    }];

    // Process advertisement on relay A
    let new_peers = gossip::process_peer_advertisement(
        &relay_a.relay_id,
        &relay_a.peer_registry,
        &peers_to_advertise,
    );

    let convergence_time = start.elapsed();

    eprintln!(
        "Gossip convergence: {} new peers discovered in {:?}",
        new_peers, convergence_time
    );

    // Verify relay A now knows about relay C
    assert_eq!(new_peers, 1, "Should have discovered 1 new peer");
    assert_eq!(
        relay_a.peer_registry.all_peers().len(),
        2,
        "Relay A should know about 2 peers (B and C)"
    );

    // Convergence should be nearly instant (< 10ms)
    assert!(
        convergence_time < Duration::from_millis(10),
        "Gossip processing should be < 10ms, took {:?}",
        convergence_time
    );
}

/// Tests gossip with many peers and measures processing time.
#[tokio::test]
async fn test_gossip_many_peers_convergence() {
    let relay = create_relay("relay-main", 1_000_000, 0.80).await;

    // Simulate receiving advertisement with 100 peers
    let mut advertised_peers = Vec::with_capacity(100);
    for i in 0..100 {
        advertised_peers.push(AdvertisedPeer {
            relay_id: format!("peer-{}", i),
            url: format!("ws://peer-{}:8080", i),
            capacity_pct: (i % 100) as u8,
            last_seen_secs: now_secs(),
        });
    }

    let start = Instant::now();
    let new_count = gossip::process_peer_advertisement(
        &relay.relay_id,
        &relay.peer_registry,
        &advertised_peers,
    );
    let elapsed = start.elapsed();

    eprintln!(
        "Processed {} peer advertisements in {:?} ({:.0}/s)",
        new_count,
        elapsed,
        new_count as f64 / elapsed.as_secs_f64()
    );

    assert_eq!(new_count, 100);
    assert_eq!(relay.peer_registry.all_peers().len(), 100);

    // Should process 100 peers in < 50ms
    assert!(
        elapsed < Duration::from_millis(50),
        "Processing 100 peers should be < 50ms, took {:?}",
        elapsed
    );
}

// ============================================================================
// Test 4: Federation Reconnection After Network Partition
// ============================================================================

/// Simulates a network partition where one relay loses connection to its peers,
/// then verifies the system can recover when the partition heals.
#[tokio::test]
async fn test_federation_reconnection_after_partition() {
    let relay_a = create_relay("relay-A", 1_000_000, 0.80).await;
    let relay_b = create_relay("relay-B", 1_000_000, 0.80).await;

    // Establish initial connection
    let sender = connect_relays(&relay_a, &relay_b).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify connection established
    assert_eq!(relay_a.peer_registry.connected_peers().len(), 1);
    assert_eq!(relay_b.peer_registry.peer_count(), 1);

    // Store some blobs on relay A
    for i in 0..5 {
        relay_a
            .storage
            .store(&format!("user-{}", i), StoredBlob::new(vec![i as u8; 100]));
    }
    assert_eq!(relay_a.storage.blob_count(), 5);

    // Simulate partition: mark peer as disconnected
    relay_a
        .peer_registry
        .set_status("relay-B", PeerStatus::Disconnected);

    // Verify partition state
    assert_eq!(relay_a.peer_registry.connected_peers().len(), 0);

    // Try to offload - should fail (no connected peers)
    let manager = OffloadManager {
        storage: relay_a.storage.clone() as Arc<dyn BlobStore>,
        hint_store: relay_a.hint_store.clone() as Arc<dyn ForwardingHintStore>,
        peer_registry: relay_a.peer_registry.clone(),
        config: Arc::new(RelayConfig {
            max_storage_bytes: 100, // Tiny to force offload attempt
            federation_offload_threshold: 0.01,
            ..Default::default()
        }),
    };

    let offloaded = manager.check_and_offload().await;
    assert_eq!(offloaded, 0, "Should not offload during partition");

    // Simulate partition heal: reconnect
    let _new_sender = connect_relays(&relay_a, &relay_b).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify reconnection
    assert_eq!(
        relay_a.peer_registry.connected_peers().len(),
        1,
        "Should have 1 connected peer after reconnection"
    );

    // Now offload should work
    // (Update peer registry sender)
    relay_a.peer_registry.register_peer(PeerInfo {
        relay_id: "relay-B".to_string(),
        url: relay_b.federation_url.clone(),
        capacity_used_bytes: 0,
        capacity_max_bytes: 1_000_000,
        status: PeerStatus::Connected,
        sender: Some(sender.clone()),
        origin: PeerOrigin::Configured,
        last_seen_secs: now_secs(),
    });

    let offloaded_after = manager.check_and_offload().await;
    eprintln!("Offloaded {} blobs after partition heal", offloaded_after);

    // Should be able to offload now
    // (May not offload all due to batch size, but should offload some)
    assert!(
        offloaded_after > 0 || relay_a.storage.blob_count() < 5,
        "Should be able to offload after partition heals"
    );
}

// ============================================================================
// Test 5: Capacity Report Updates Under Load
// ============================================================================

/// Tests that capacity reports are correctly processed under load with
/// many concurrent updates.
#[tokio::test]
async fn test_capacity_report_updates_under_load() {
    let relay_a = create_relay("relay-A", 1_000_000, 0.80).await;

    // Register multiple peers
    let num_peers = 20;
    for i in 0..num_peers {
        let (tx, _rx) = mpsc::channel(64);
        relay_a.peer_registry.register_peer(PeerInfo {
            relay_id: format!("peer-{}", i),
            url: format!("ws://peer-{}:8080", i),
            capacity_used_bytes: 0,
            capacity_max_bytes: 1_000_000,
            status: PeerStatus::Connected,
            sender: Some(tx),
            origin: PeerOrigin::Configured,
            last_seen_secs: now_secs(),
        });
    }

    assert_eq!(relay_a.peer_registry.peer_count(), num_peers);

    let start = Instant::now();

    // Simulate rapid capacity updates
    let num_updates = 1000;
    for i in 0..num_updates {
        let peer_id = format!("peer-{}", i % num_peers);
        let used = (i * 1000) % 900_000; // Vary usage
        relay_a
            .peer_registry
            .update_capacity(&peer_id, used, 1_000_000);
    }

    let elapsed = start.elapsed();

    eprintln!(
        "Processed {} capacity updates in {:?} ({:.0}/s)",
        num_updates,
        elapsed,
        num_updates as f64 / elapsed.as_secs_f64()
    );

    // Verify final state
    let peers = relay_a.peer_registry.connected_peers();
    assert_eq!(peers.len(), num_peers);

    // Should process 1000 updates in < 100ms
    assert!(
        elapsed < Duration::from_millis(100),
        "1000 capacity updates should be < 100ms, took {:?}",
        elapsed
    );
}

// ============================================================================
// Test 6: High Volume Offload Batch Processing
// ============================================================================

/// Tests offloading many blobs in batches under simulated load.
#[tokio::test]
async fn test_high_volume_offload_batch() {
    let relay_a = create_relay("relay-A", 100_000, 0.10).await; // Very low threshold
    let relay_b = create_relay("relay-B", 10_000_000, 0.80).await;

    // Connect A -> B
    let _ab = connect_relays(&relay_a, &relay_b).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Store many small blobs
    let num_blobs = 500;
    for i in 0..num_blobs {
        relay_a
            .storage
            .store(&format!("route-{}", i), StoredBlob::new(vec![i as u8; 100]));
    }

    assert_eq!(relay_a.storage.blob_count(), num_blobs);

    let manager = OffloadManager {
        storage: relay_a.storage.clone() as Arc<dyn BlobStore>,
        hint_store: relay_a.hint_store.clone() as Arc<dyn ForwardingHintStore>,
        peer_registry: relay_a.peer_registry.clone(),
        config: relay_a.config.clone(),
    };

    let start = Instant::now();
    let mut total_offloaded = 0;

    // Run offload multiple times to process all blobs
    for _ in 0..100 {
        let offloaded = manager.check_and_offload().await;
        total_offloaded += offloaded;
        if offloaded == 0 && relay_a.storage.storage_size_bytes() < 10_000 {
            break;
        }
    }

    let elapsed = start.elapsed();

    eprintln!(
        "Offloaded {} blobs in {:?} ({:.0}/s)",
        total_offloaded,
        elapsed,
        total_offloaded as f64 / elapsed.as_secs_f64()
    );

    // Verify significant offload occurred
    assert!(total_offloaded > 0, "Should have offloaded some blobs");

    // Verify hints created
    let hint_count = relay_a.hint_store.hint_count();
    assert_eq!(
        hint_count, total_offloaded,
        "Should have {} hints, got {}",
        total_offloaded, hint_count
    );
}

// ============================================================================
// Test 7: Concurrent Federation Connections Stress
// ============================================================================

/// Tests the federation handler with many concurrent peer connections.
#[tokio::test]
async fn test_concurrent_federation_connections() {
    let relay = create_relay("relay-main", 1_000_000, 0.80).await;

    let num_connections = 50;
    let successful = Arc::new(AtomicUsize::new(0));
    let mut handles = vec![];

    let start = Instant::now();

    for i in 0..num_connections {
        let url = relay.federation_url.clone();
        let counter = successful.clone();

        handles.push(tokio::spawn(async move {
            if let Ok(Ok((mut ws, _))) = timeout(Duration::from_secs(10), connect_async(&url)).await
            {
                let hs =
                    make_peer_handshake(&format!("peer-{}", i), &format!("127.0.0.1:{}", 9000 + i));
                if ws.send(Message::Binary(encode_fed(&hs))).await.is_err() {
                    return;
                }

                if let Ok(Some(Ok(Message::Binary(data)))) =
                    timeout(Duration::from_secs(5), ws.next()).await
                {
                    let resp = decode_fed(&data);
                    if let FederationPayload::PeerHandshakeAck { accepted, .. } = resp.payload {
                        if accepted {
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }

                // Hold connection briefly
                tokio::time::sleep(Duration::from_millis(50)).await;
                ws.close(None).await.ok();
            }
        }));
    }

    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = start.elapsed();
    let success_count = successful.load(Ordering::Relaxed);

    eprintln!(
        "Federation connections: {}/{} successful in {:?}",
        success_count, num_connections, elapsed
    );

    // Allow some failures under stress
    assert!(
        success_count >= 40,
        "Expected >= 40 successful connections, got {}",
        success_count
    );

    // Verify peers registered
    assert!(
        relay.peer_registry.peer_count() >= 40,
        "Expected >= 40 registered peers"
    );
}

// ============================================================================
// Test 8: Stale Peer Cleanup Under Load
// ============================================================================

/// Tests cleanup of stale discovered peers while new peers are being added.
#[tokio::test]
async fn test_stale_peer_cleanup_under_load() {
    let registry = PeerRegistry::new(0.95);

    // Add old discovered peers
    let old_time = now_secs() - 7200; // 2 hours ago
    for i in 0..100 {
        registry.add_discovered_peer(
            &format!("old-peer-{}", i),
            &format!("ws://old-{}:8080", i),
            50,
            old_time,
        );
    }

    // Add recent discovered peers
    let recent_time = now_secs() - 60; // 1 minute ago
    for i in 0..50 {
        registry.add_discovered_peer(
            &format!("new-peer-{}", i),
            &format!("ws://new-{}:8080", i),
            30,
            recent_time,
        );
    }

    // Add configured peers (should never be removed)
    for i in 0..10 {
        let (tx, _rx) = mpsc::channel(64);
        registry.register_peer(PeerInfo {
            relay_id: format!("configured-{}", i),
            url: format!("ws://configured-{}:8080", i),
            capacity_used_bytes: 0,
            capacity_max_bytes: 1_000_000,
            status: PeerStatus::Connected,
            sender: Some(tx),
            origin: PeerOrigin::Configured,
            last_seen_secs: old_time, // Old, but should not be removed
        });
    }

    assert_eq!(registry.peer_count(), 160);

    let start = Instant::now();

    // Remove peers older than 1 hour
    let removed = registry.remove_stale_peers(now_secs(), 3600);

    let elapsed = start.elapsed();

    eprintln!("Removed {} stale peers in {:?}", removed, elapsed);

    // Should have removed only old discovered peers
    assert_eq!(removed, 100, "Should remove 100 old discovered peers");
    assert_eq!(
        registry.peer_count(),
        60,
        "Should have 60 peers remaining (50 new + 10 configured)"
    );

    // Cleanup should be fast
    assert!(
        elapsed < Duration::from_millis(50),
        "Cleanup should be < 50ms, took {:?}",
        elapsed
    );
}
