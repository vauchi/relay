// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Federation integration tests.
//!
//! Tests the federation handler (acceptor side) with a direct WebSocket
//! connection, verifying offload, integrity, hop_count, capacity, drain,
//! and purge flows. Also tests the OffloadManager end-to-end.

mod common;

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_async, connect_async};

use vauchi_relay::config::RelayConfig;
use vauchi_relay::connection_registry::ConnectionRegistry;
use vauchi_relay::device_sync_storage::MemoryDeviceSyncStore;
use vauchi_relay::federation_connector::OffloadManager;
use vauchi_relay::federation_handler::{self, FederationDeps};
use vauchi_relay::federation_protocol::{
    self, FederationEnvelope, FederationPayload, FEDERATION_PROTOCOL_VERSION,
};
use vauchi_relay::forwarding_hints::{ForwardingHintStore, MemoryForwardingHintStore};
use vauchi_relay::handler::{self, ConnectionDeps, QuotaLimits};
use vauchi_relay::integrity;
use vauchi_relay::peer_registry::{PeerInfo, PeerOrigin, PeerRegistry, PeerStatus};
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::recovery_storage::MemoryRecoveryProofStore;
use vauchi_relay::storage::{BlobStore, MemoryBlobStore, StoredBlob};

// ============================================================================
// Protocol helpers
// ============================================================================

const FRAME_HEADER_SIZE: usize = 4;

/// Encodes a FederationEnvelope to wire format (4-byte BE length prefix + JSON).
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
fn make_peer_handshake(relay_id: &str) -> FederationEnvelope {
    federation_protocol::create_federation_envelope(FederationPayload::PeerHandshake {
        relay_id: relay_id.to_string(),
        version: FEDERATION_PROTOCOL_VERSION,
        listen_addr: "127.0.0.1:9999".to_string(),
    })
}

/// Creates an OffloadBlob message with correct integrity hash.
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
        created_at_secs: 1000,
        integrity_hash: hash,
        hop_count,
    })
}

/// Creates an OffloadBlob with a specific created_at_secs.
fn make_offload_blob_with_ts(
    blob_id: &str,
    routing_id: &str,
    data: &[u8],
    created_at_secs: u64,
    hop_count: u8,
) -> FederationEnvelope {
    let hash = integrity::compute_integrity_hash(data);
    federation_protocol::create_federation_envelope(FederationPayload::OffloadBlob {
        blob_id: blob_id.to_string(),
        routing_id: routing_id.to_string(),
        data: data.to_vec(),
        created_at_secs,
        integrity_hash: hash,
        hop_count,
    })
}

/// Creates an OffloadBlob with a wrong integrity hash.
fn make_offload_blob_bad_hash(blob_id: &str, routing_id: &str, data: &[u8]) -> FederationEnvelope {
    federation_protocol::create_federation_envelope(FederationPayload::OffloadBlob {
        blob_id: blob_id.to_string(),
        routing_id: routing_id.to_string(),
        data: data.to_vec(),
        created_at_secs: 1000,
        integrity_hash: "badhash".to_string(),
        hop_count: 0,
    })
}

/// Creates a CapacityReport message.
fn make_capacity_report(used: usize, max: usize, count: usize) -> FederationEnvelope {
    federation_protocol::create_federation_envelope(FederationPayload::CapacityReport {
        used_bytes: used,
        max_bytes: max,
        blob_count: count,
    })
}

/// Creates a DrainNotice message.
fn make_drain_notice(timeout_secs: u64) -> FederationEnvelope {
    federation_protocol::create_federation_envelope(FederationPayload::DrainNotice {
        drain_timeout_secs: timeout_secs,
    })
}

/// Creates a client Handshake message.
fn make_client_handshake(client_id: &str) -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "Handshake",
            "client_id": client_id
        }
    })
}

/// Creates a client PurgeRequest message.
fn make_client_purge() -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "PurgeRequest",
            "include_device_sync": false
        }
    })
}

// ============================================================================
// Test infrastructure
// ============================================================================

/// Creates a test RelayConfig for federation.
fn make_fed_config(max_storage: usize, offload_threshold: f64) -> Arc<RelayConfig> {
    Arc::new(RelayConfig {
        max_storage_bytes: max_storage,
        federation_enabled: true,
        federation_relay_id: "test-relay".to_string(),
        federation_offload_threshold: offload_threshold,
        federation_offload_refuse: 0.95,
        federation_peer_timeout_secs: 5,
        federation_capacity_interval_secs: 1,
        ..Default::default()
    })
}

/// Starts a federation acceptor server that handles one connection.
/// Returns the WebSocket URL.
async fn start_federation_server(deps: FederationDeps) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://127.0.0.1:{}", addr.port());

    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            if let Ok(ws) = accept_async(stream).await {
                federation_handler::handle_federation_connection(ws, deps).await;
            }
        }
    });

    url
}

/// Starts a client handler server that handles one connection.
/// Returns the WebSocket URL.
async fn start_client_server(deps: ConnectionDeps) -> String {
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

/// Performs a federation handshake as a peer connecting to the server.
/// Returns the PeerHandshakeAck payload.
async fn do_federation_handshake(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    our_relay_id: &str,
) -> FederationPayload {
    let hs = make_peer_handshake(our_relay_id);
    ws.send(Message::Binary(encode_fed(&hs))).await.unwrap();

    let msg = timeout(Duration::from_secs(3), ws.next())
        .await
        .expect("Timeout waiting for handshake ack")
        .expect("Stream ended")
        .expect("WebSocket error");

    match msg {
        Message::Binary(data) => decode_fed(&data).payload,
        other => panic!("Expected Binary message, got {:?}", other),
    }
}

/// Sends a federation message and receives the response.
async fn fed_send_recv(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    msg: &FederationEnvelope,
) -> FederationPayload {
    ws.send(Message::Binary(encode_fed(msg))).await.unwrap();

    let resp = timeout(Duration::from_secs(3), ws.next())
        .await
        .expect("Timeout waiting for response")
        .expect("Stream ended")
        .expect("WebSocket error");

    match resp {
        Message::Binary(data) => decode_fed(&data).payload,
        other => panic!("Expected Binary, got {:?}", other),
    }
}

/// Receives the next client protocol message.
async fn recv_client(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> serde_json::Value {
    let msg = timeout(Duration::from_secs(3), ws.next())
        .await
        .expect("Timeout")
        .expect("Stream ended")
        .expect("WS error");

    match msg {
        Message::Binary(data) => decode_client(&data),
        other => panic!("Expected Binary, got {:?}", other),
    }
}

/// Try to receive a client message with short timeout.
async fn try_recv_client(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Option<serde_json::Value> {
    match timeout(Duration::from_millis(300), ws.next()).await {
        Ok(Some(Ok(Message::Binary(data)))) => Some(decode_client(&data)),
        _ => None,
    }
}

/// Creates client ConnectionDeps with an optional hint store.
fn make_client_deps(
    storage: Arc<dyn BlobStore>,
    hint_store: Option<Arc<dyn ForwardingHintStore>>,
) -> ConnectionDeps {
    ConnectionDeps {
        storage,
        recovery_storage: Arc::new(MemoryRecoveryProofStore::new()),
        device_sync_storage: Arc::new(MemoryDeviceSyncStore::new()),
        rate_limiter: Arc::new(RateLimiter::new(60)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(10)),
        registry: Arc::new(ConnectionRegistry::new()),
        blob_sender_map: handler::new_blob_sender_map(),
        max_message_size: 1_048_576,
        idle_timeout: Duration::from_secs(5),
        quota: QuotaLimits {
            max_blobs: 100,
            max_bytes: 10_000_000,
        },
        hint_store,
        noise_static_key: None,
        require_noise_encryption: false,
    }
}

// ============================================================================
// Tests: Federation Handshake
// ============================================================================

#[tokio::test]
async fn test_federation_handshake_accepted() {
    let storage = Arc::new(MemoryBlobStore::new());
    let hint_store = Arc::new(MemoryForwardingHintStore::new());
    let peer_registry = Arc::new(PeerRegistry::new(0.95));
    let config = make_fed_config(1_000_000, 0.80);

    let url = start_federation_server(FederationDeps {
        storage,
        hint_store,
        peer_registry: peer_registry.clone(),
        config,
    })
    .await;

    let (mut ws, _) = connect_async(&url).await.unwrap();
    let ack = do_federation_handshake(&mut ws, "peer-A").await;

    match ack {
        FederationPayload::PeerHandshakeAck {
            relay_id,
            version,
            accepted,
            ..
        } => {
            assert_eq!(relay_id, "test-relay");
            assert_eq!(version, FEDERATION_PROTOCOL_VERSION);
            assert!(accepted);
        }
        other => panic!("Expected PeerHandshakeAck, got {:?}", other),
    }

    // Peer should be registered
    assert_eq!(peer_registry.peer_count(), 1);

    ws.close(None).await.ok();
}

#[tokio::test]
async fn test_federation_handshake_version_mismatch_rejected() {
    let storage = Arc::new(MemoryBlobStore::new());
    let hint_store = Arc::new(MemoryForwardingHintStore::new());
    let peer_registry = Arc::new(PeerRegistry::new(0.95));
    let config = make_fed_config(1_000_000, 0.80);

    let url = start_federation_server(FederationDeps {
        storage,
        hint_store,
        peer_registry,
        config,
    })
    .await;

    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Send handshake with wrong version
    let hs = federation_protocol::create_federation_envelope(FederationPayload::PeerHandshake {
        relay_id: "peer-A".to_string(),
        version: 99,
        listen_addr: "127.0.0.1:9999".to_string(),
    });
    ws.send(Message::Binary(encode_fed(&hs))).await.unwrap();

    let msg = timeout(Duration::from_secs(3), ws.next())
        .await
        .expect("Timeout")
        .expect("Stream ended")
        .expect("WS error");

    match msg {
        Message::Binary(data) => {
            let envelope = decode_fed(&data);
            match envelope.payload {
                FederationPayload::PeerHandshakeAck { accepted, .. } => {
                    assert!(!accepted);
                }
                other => panic!("Expected PeerHandshakeAck, got {:?}", other),
            }
        }
        other => panic!("Expected Binary, got {:?}", other),
    }

    ws.close(None).await.ok();
}

// ============================================================================
// Tests: OffloadBlob Acceptance & Rejection
// ============================================================================

#[tokio::test]
async fn test_offload_blob_accepted_under_capacity() {
    let storage: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
    let hint_store = Arc::new(MemoryForwardingHintStore::new());
    let peer_registry = Arc::new(PeerRegistry::new(0.95));
    let config = make_fed_config(1_000_000, 0.80);

    let url = start_federation_server(FederationDeps {
        storage: storage.clone(),
        hint_store,
        peer_registry,
        config,
    })
    .await;

    let (mut ws, _) = connect_async(&url).await.unwrap();
    do_federation_handshake(&mut ws, "peer-A").await;

    // Send an offload blob
    let blob_data = vec![42u8; 100];
    let offload = make_offload_blob("blob-1", "route-abc", &blob_data, 0);
    let ack = fed_send_recv(&mut ws, &offload).await;

    match ack {
        FederationPayload::OffloadAck {
            blob_id,
            accepted,
            reason,
        } => {
            assert_eq!(blob_id, "blob-1");
            assert!(accepted);
            assert!(reason.is_none());
        }
        other => panic!("Expected OffloadAck, got {:?}", other),
    }

    // Blob should be stored on the receiving relay
    assert_eq!(storage.blob_count(), 1);
    let blobs = storage.peek("route-abc");
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].data, blob_data);

    ws.close(None).await.ok();
}

#[tokio::test]
async fn test_offload_blob_rejected_integrity_mismatch() {
    let storage: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
    let hint_store = Arc::new(MemoryForwardingHintStore::new());
    let peer_registry = Arc::new(PeerRegistry::new(0.95));
    let config = make_fed_config(1_000_000, 0.80);

    let url = start_federation_server(FederationDeps {
        storage: storage.clone(),
        hint_store,
        peer_registry,
        config,
    })
    .await;

    let (mut ws, _) = connect_async(&url).await.unwrap();
    do_federation_handshake(&mut ws, "peer-A").await;

    // Send blob with wrong hash
    let offload = make_offload_blob_bad_hash("blob-bad", "route-abc", &[1, 2, 3]);
    let ack = fed_send_recv(&mut ws, &offload).await;

    match ack {
        FederationPayload::OffloadAck {
            accepted, reason, ..
        } => {
            assert!(!accepted);
            assert!(reason.unwrap().contains("integrity"));
        }
        other => panic!("Expected OffloadAck, got {:?}", other),
    }

    // Blob should NOT be stored
    assert_eq!(storage.blob_count(), 0);

    ws.close(None).await.ok();
}

#[tokio::test]
async fn test_offload_blob_rejected_hop_count_too_high() {
    let storage: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
    let hint_store = Arc::new(MemoryForwardingHintStore::new());
    let peer_registry = Arc::new(PeerRegistry::new(0.95));
    let config = make_fed_config(1_000_000, 0.80);

    let url = start_federation_server(FederationDeps {
        storage: storage.clone(),
        hint_store,
        peer_registry,
        config,
    })
    .await;

    let (mut ws, _) = connect_async(&url).await.unwrap();
    do_federation_handshake(&mut ws, "peer-A").await;

    // Send blob with hop_count=1 (already offloaded once)
    let offload = make_offload_blob("blob-hop", "route-abc", &[10, 20, 30], 1);
    let ack = fed_send_recv(&mut ws, &offload).await;

    match ack {
        FederationPayload::OffloadAck {
            accepted, reason, ..
        } => {
            assert!(!accepted);
            assert!(reason.unwrap().contains("hop_count"));
        }
        other => panic!("Expected OffloadAck, got {:?}", other),
    }

    // Blob should NOT be stored
    assert_eq!(storage.blob_count(), 0);

    ws.close(None).await.ok();
}

#[tokio::test]
async fn test_offload_blob_rejected_at_capacity() {
    let storage = Arc::new(MemoryBlobStore::new());
    // Fill storage near capacity (>= 95% of 1000 bytes)
    // Each StoredBlob has overhead, so store enough data
    for i in 0..100 {
        storage.store(&format!("fill-{}", i), StoredBlob::new(vec![0u8; 50]));
    }

    let hint_store = Arc::new(MemoryForwardingHintStore::new());
    let peer_registry = Arc::new(PeerRegistry::new(0.95));
    // Use a max_storage of 100 bytes so even a small amount triggers capacity refusal
    let config = make_fed_config(100, 0.80);

    // Pre-fill to exceed 95% of 100 bytes
    let full_storage = Arc::new(MemoryBlobStore::new());
    // Store enough to exceed capacity
    full_storage.store("fill", StoredBlob::new(vec![0u8; 96]));

    let url = start_federation_server(FederationDeps {
        storage: full_storage.clone() as Arc<dyn BlobStore>,
        hint_store,
        peer_registry,
        config,
    })
    .await;

    let (mut ws, _) = connect_async(&url).await.unwrap();
    do_federation_handshake(&mut ws, "peer-A").await;

    let offload = make_offload_blob("blob-full", "route-abc", &[1, 2, 3], 0);
    let ack = fed_send_recv(&mut ws, &offload).await;

    match ack {
        FederationPayload::OffloadAck {
            accepted, reason, ..
        } => {
            assert!(!accepted);
            assert!(reason.unwrap().contains("capacity"));
        }
        other => panic!("Expected OffloadAck, got {:?}", other),
    }

    ws.close(None).await.ok();
}

// ============================================================================
// Tests: TTL Preservation
// ============================================================================

#[tokio::test]
async fn test_offload_preserves_created_at_secs() {
    let storage: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
    let hint_store = Arc::new(MemoryForwardingHintStore::new());
    let peer_registry = Arc::new(PeerRegistry::new(0.95));
    let config = make_fed_config(1_000_000, 0.80);

    let url = start_federation_server(FederationDeps {
        storage: storage.clone(),
        hint_store,
        peer_registry,
        config,
    })
    .await;

    let (mut ws, _) = connect_async(&url).await.unwrap();
    do_federation_handshake(&mut ws, "peer-A").await;

    // Send blob with specific created_at_secs (old timestamp)
    let original_created_at = 1700000000u64;
    let offload =
        make_offload_blob_with_ts("blob-ttl", "route-ttl", &[5, 6, 7], original_created_at, 0);
    let ack = fed_send_recv(&mut ws, &offload).await;

    match ack {
        FederationPayload::OffloadAck { accepted, .. } => assert!(accepted),
        other => panic!("Expected OffloadAck, got {:?}", other),
    }

    // Verify the stored blob preserves the original created_at_secs
    let blobs = storage.peek("route-ttl");
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].created_at_secs, original_created_at);
    // hop_count should be incremented
    assert_eq!(blobs[0].hop_count, 1);

    ws.close(None).await.ok();
}

// ============================================================================
// Tests: hop_count Enforcement
// ============================================================================

#[tokio::test]
async fn test_offload_increments_hop_count() {
    let storage: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
    let hint_store = Arc::new(MemoryForwardingHintStore::new());
    let peer_registry = Arc::new(PeerRegistry::new(0.95));
    let config = make_fed_config(1_000_000, 0.80);

    let url = start_federation_server(FederationDeps {
        storage: storage.clone(),
        hint_store,
        peer_registry,
        config,
    })
    .await;

    let (mut ws, _) = connect_async(&url).await.unwrap();
    do_federation_handshake(&mut ws, "peer-A").await;

    let offload = make_offload_blob("blob-hop0", "route-hop", &[1, 2], 0);
    let ack = fed_send_recv(&mut ws, &offload).await;

    match ack {
        FederationPayload::OffloadAck { accepted, .. } => assert!(accepted),
        other => panic!("Expected OffloadAck, got {:?}", other),
    }

    let blobs = storage.peek("route-hop");
    assert_eq!(blobs[0].hop_count, 1);

    // hop_count=1 blobs should NOT be offloaded again (get_oldest_blobs filters them)
    let oldest = storage.get_oldest_blobs(10);
    assert!(
        oldest.is_empty(),
        "hop_count=1 blobs should not be offload candidates"
    );

    ws.close(None).await.ok();
}

// ============================================================================
// Tests: CapacityReport & DrainNotice
// ============================================================================

#[tokio::test]
async fn test_capacity_report_updates_peer_registry() {
    let storage: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
    let hint_store = Arc::new(MemoryForwardingHintStore::new());
    let peer_registry = Arc::new(PeerRegistry::new(0.95));
    let config = make_fed_config(1_000_000, 0.80);

    let url = start_federation_server(FederationDeps {
        storage,
        hint_store,
        peer_registry: peer_registry.clone(),
        config,
    })
    .await;

    let (mut ws, _) = connect_async(&url).await.unwrap();
    do_federation_handshake(&mut ws, "peer-A").await;

    // Send capacity report
    let report = make_capacity_report(500_000, 1_000_000, 42);
    ws.send(Message::Binary(encode_fed(&report))).await.unwrap();

    // Give the server a moment to process
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify peer_registry was updated
    let peers = peer_registry.connected_peers();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].capacity_used_bytes, 500_000);
    assert_eq!(peers[0].capacity_max_bytes, 1_000_000);

    ws.close(None).await.ok();
}

#[tokio::test]
async fn test_drain_notice_marks_peer_as_draining() {
    let storage: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
    let hint_store = Arc::new(MemoryForwardingHintStore::new());
    let peer_registry = Arc::new(PeerRegistry::new(0.95));
    let config = make_fed_config(1_000_000, 0.80);

    let url = start_federation_server(FederationDeps {
        storage,
        hint_store,
        peer_registry: peer_registry.clone(),
        config,
    })
    .await;

    let (mut ws, _) = connect_async(&url).await.unwrap();
    do_federation_handshake(&mut ws, "peer-A").await;

    // Send drain notice
    let drain = make_drain_notice(300);
    let ack = fed_send_recv(&mut ws, &drain).await;

    // Should receive DrainAck
    match ack {
        FederationPayload::DrainAck => {}
        other => panic!("Expected DrainAck, got {:?}", other),
    }

    // Peer should be marked as Draining (not in connected_peers)
    let connected = peer_registry.connected_peers();
    assert!(connected.is_empty());

    ws.close(None).await.ok();
}

// ============================================================================
// Tests: OffloadManager
// ============================================================================

#[tokio::test]
async fn test_offload_manager_below_threshold_does_nothing() {
    let storage = Arc::new(MemoryBlobStore::new());
    let hint_store = Arc::new(MemoryForwardingHintStore::new());
    let peer_registry = Arc::new(PeerRegistry::new(0.95));
    let config = make_fed_config(1_000_000, 0.80);

    // Small amount of data, well below 80%
    storage.store("r1", StoredBlob::new(vec![1; 100]));

    let manager = OffloadManager {
        storage: storage.clone() as Arc<dyn BlobStore>,
        hint_store: hint_store.clone() as Arc<dyn ForwardingHintStore>,
        peer_registry,
        config,
    };

    let offloaded = manager.check_and_offload().await;
    assert_eq!(offloaded, 0);
    assert_eq!(hint_store.hint_count(), 0);
}

#[tokio::test]
async fn test_offload_manager_no_peers_available() {
    let storage = Arc::new(MemoryBlobStore::new());
    let hint_store = Arc::new(MemoryForwardingHintStore::new());
    let peer_registry = Arc::new(PeerRegistry::new(0.95));
    // Tiny storage so any blob triggers offload
    let config = make_fed_config(100, 0.01);

    storage.store("r1", StoredBlob::new(vec![1; 50]));

    let manager = OffloadManager {
        storage: storage.clone() as Arc<dyn BlobStore>,
        hint_store: hint_store.clone() as Arc<dyn ForwardingHintStore>,
        peer_registry,
        config,
    };

    let offloaded = manager.check_and_offload().await;
    assert_eq!(offloaded, 0);
    // Blob should still be on source
    assert_eq!(storage.blob_count(), 1);
}

#[tokio::test]
async fn test_offload_manager_successful_offload_with_hints() {
    let storage = Arc::new(MemoryBlobStore::new());
    let hint_store = Arc::new(MemoryForwardingHintStore::new());
    let peer_registry = Arc::new(PeerRegistry::new(0.95));
    // Tiny storage to trigger offload
    let config = make_fed_config(100, 0.01);

    let blob = StoredBlob::new(vec![42; 50]);
    let blob_id = blob.id.clone();
    storage.store("route-1", blob);

    // Register a peer with capacity and sender
    let (tx, mut rx) = mpsc::channel(64);
    peer_registry.register_peer(PeerInfo {
        relay_id: "peer-1".to_string(),
        url: "ws://peer-1:8080".to_string(),
        capacity_used_bytes: 10,
        capacity_max_bytes: 1000,
        status: PeerStatus::Connected,
        sender: Some(tx),
        origin: PeerOrigin::Configured,
        last_seen_secs: 1000,
    });

    let manager = OffloadManager {
        storage: storage.clone() as Arc<dyn BlobStore>,
        hint_store: hint_store.clone() as Arc<dyn ForwardingHintStore>,
        peer_registry,
        config,
    };

    let offloaded = manager.check_and_offload().await;
    assert_eq!(offloaded, 1);

    // Blob removed from local storage
    assert_eq!(storage.blob_count(), 0);

    // Forwarding hint created
    assert_eq!(hint_store.hint_count(), 1);
    let hints = hint_store.get_hints("route-1");
    assert_eq!(hints.len(), 1);
    assert_eq!(hints[0].blob_id, blob_id);
    assert_eq!(hints[0].target_relay, "ws://peer-1:8080");

    // Message sent to peer via channel
    let sent_data = rx.try_recv().unwrap();
    let envelope = federation_protocol::decode_federation_message(&sent_data).unwrap();
    match envelope.payload {
        FederationPayload::OffloadBlob {
            blob_id: sent_id,
            routing_id,
            hop_count,
            ..
        } => {
            assert_eq!(sent_id, blob_id);
            assert_eq!(routing_id, "route-1");
            assert_eq!(hop_count, 0);
        }
        other => panic!("Expected OffloadBlob, got {:?}", other),
    }
}

// ============================================================================
// Tests: Client-Facing Forwarding Hints Delivery
// ============================================================================

#[tokio::test]
async fn test_client_receives_forwarding_hints_on_connect() {
    let storage = Arc::new(MemoryBlobStore::new());
    let hint_store = Arc::new(MemoryForwardingHintStore::new());

    // Without routing_token, routing_id == client_id
    let client_id = common::generate_test_client_id(1);
    let routing_id = &client_id;

    // Store a forwarding hint for this routing_id
    hint_store.store_hint(vauchi_relay::forwarding_hints::ForwardingHint {
        routing_id: routing_id.to_string(),
        blob_id: "offloaded-blob-1".to_string(),
        target_relay: "ws://peer-relay:8080".to_string(),
        created_at_secs: 1000,
        expires_at_secs: 9999999999,
    });

    let deps = make_client_deps(
        storage as Arc<dyn BlobStore>,
        Some(hint_store as Arc<dyn ForwardingHintStore>),
    );

    let url = start_client_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Send handshake
    let hs = make_client_handshake(&client_id);
    ws.send(Message::Binary(encode_client(&hs))).await.unwrap();

    // Receive HandshakeAck
    let ack = recv_client(&mut ws).await;
    assert_eq!(ack["payload"]["type"], "HandshakeAck");
    let features = ack["payload"]["features"].as_array().unwrap();
    assert!(
        features.iter().any(|f| f == "forwarding_hints"),
        "forwarding_hints should be in features"
    );

    // Receive ForwardingHints message
    let hints_msg = recv_client(&mut ws).await;
    assert_eq!(hints_msg["payload"]["type"], "ForwardingHints");
    let hints = hints_msg["payload"]["hints"].as_array().unwrap();
    assert_eq!(hints.len(), 1);
    assert_eq!(hints[0]["blob_id"], "offloaded-blob-1");
    assert_eq!(hints[0]["relay_url"], "ws://peer-relay:8080");

    ws.close(None).await.ok();
}

#[tokio::test]
async fn test_client_no_hints_no_forwarding_message() {
    let storage = Arc::new(MemoryBlobStore::new());
    let hint_store = Arc::new(MemoryForwardingHintStore::new());

    let client_id = common::generate_test_client_id(2);

    // No hints stored for this client

    let deps = make_client_deps(
        storage as Arc<dyn BlobStore>,
        Some(hint_store as Arc<dyn ForwardingHintStore>),
    );

    let url = start_client_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let hs = make_client_handshake(&client_id);
    ws.send(Message::Binary(encode_client(&hs))).await.unwrap();

    // Receive HandshakeAck
    let ack = recv_client(&mut ws).await;
    assert_eq!(ack["payload"]["type"], "HandshakeAck");

    // Should NOT receive a ForwardingHints message
    let next = try_recv_client(&mut ws).await;
    if let Some(msg) = next {
        // If we do receive a message, it shouldn't be ForwardingHints
        assert_ne!(
            msg["payload"]["type"], "ForwardingHints",
            "Should not receive ForwardingHints when no hints exist"
        );
    }

    ws.close(None).await.ok();
}

#[tokio::test]
async fn test_hint_store_none_no_hints_sent() {
    // With hint_store=None (federation disabled), no hints are sent
    let storage = Arc::new(MemoryBlobStore::new());
    let deps = make_client_deps(storage as Arc<dyn BlobStore>, None);

    let url = start_client_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(3);
    let hs = make_client_handshake(&client_id);
    ws.send(Message::Binary(encode_client(&hs))).await.unwrap();

    let ack = recv_client(&mut ws).await;
    assert_eq!(ack["payload"]["type"], "HandshakeAck");

    // No ForwardingHints message expected
    let next = try_recv_client(&mut ws).await;
    if let Some(msg) = next {
        assert_ne!(msg["payload"]["type"], "ForwardingHints");
    }

    ws.close(None).await.ok();
}

// ============================================================================
// Tests: Purge Cleans Forwarding Hints
// ============================================================================

#[tokio::test]
async fn test_purge_request_deletes_forwarding_hints() {
    let storage = Arc::new(MemoryBlobStore::new());
    let hint_store = Arc::new(MemoryForwardingHintStore::new());

    let client_id = common::generate_test_client_id(4);
    let routing_id = &client_id;

    // Store a forwarding hint
    hint_store.store_hint(vauchi_relay::forwarding_hints::ForwardingHint {
        routing_id: routing_id.to_string(),
        blob_id: "blob-to-purge".to_string(),
        target_relay: "ws://peer:8080".to_string(),
        created_at_secs: 1000,
        expires_at_secs: 9999999999,
    });
    assert_eq!(hint_store.hint_count(), 1);

    // Also store a blob so there's something to purge
    storage.store(routing_id, StoredBlob::new(vec![1, 2, 3]));

    let deps = make_client_deps(
        storage.clone() as Arc<dyn BlobStore>,
        Some(hint_store.clone() as Arc<dyn ForwardingHintStore>),
    );

    let url = start_client_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Handshake
    let hs = make_client_handshake(&client_id);
    ws.send(Message::Binary(encode_client(&hs))).await.unwrap();

    // Receive HandshakeAck
    let ack = recv_client(&mut ws).await;
    assert_eq!(ack["payload"]["type"], "HandshakeAck");

    // Receive pending blobs (1 blob)
    let blob_msg = recv_client(&mut ws).await;
    assert_eq!(blob_msg["payload"]["type"], "EncryptedUpdate");

    // Receive ForwardingHints
    let hints_msg = recv_client(&mut ws).await;
    assert_eq!(hints_msg["payload"]["type"], "ForwardingHints");

    // Send PurgeRequest
    let purge = make_client_purge();
    ws.send(Message::Binary(encode_client(&purge)))
        .await
        .unwrap();

    // Receive PurgeResponse
    let purge_resp = recv_client(&mut ws).await;
    assert_eq!(purge_resp["payload"]["type"], "PurgeResponse");

    // Wait for processing
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Forwarding hints should be deleted
    assert_eq!(hint_store.hint_count(), 0);
    assert!(hint_store.get_hints(routing_id).is_empty());

    ws.close(None).await.ok();
}

// ============================================================================
// Tests: End-to-End Offload Flow (OffloadManager + Federation Handler)
// ============================================================================

#[tokio::test]
async fn test_end_to_end_offload_and_retrieval() {
    // This test simulates:
    // 1. Relay A has blobs that need offloading
    // 2. OffloadManager sends them to Relay B (via channel)
    // 3. Relay B (federation handler) receives and stores them
    // 4. Client connects to Relay B and retrieves the offloaded blob

    // --- Set up Relay B (acceptor) ---
    let relay_b_storage: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
    let relay_b_hints = Arc::new(MemoryForwardingHintStore::new());
    let relay_b_registry = Arc::new(PeerRegistry::new(0.95));
    let relay_b_config = make_fed_config(1_000_000, 0.80);

    let relay_b_url = start_federation_server(FederationDeps {
        storage: relay_b_storage.clone(),
        hint_store: relay_b_hints.clone(),
        peer_registry: relay_b_registry,
        config: relay_b_config,
    })
    .await;

    // --- Connect to Relay B as a federation peer ---
    let (mut fed_ws, _) = connect_async(&relay_b_url).await.unwrap();
    let ack = do_federation_handshake(&mut fed_ws, "relay-A").await;
    match ack {
        FederationPayload::PeerHandshakeAck { accepted, .. } => assert!(accepted),
        other => panic!("Expected accepted ack, got {:?}", other),
    }

    // --- Offload a blob to Relay B ---
    let blob_data = vec![100u8; 200];
    let client_id = common::generate_test_client_id(10);
    // Without routing_token in handshake, routing_id == client_id
    let routing_id = &client_id;
    let offload =
        make_offload_blob_with_ts("offloaded-blob-42", routing_id, &blob_data, 1700000000, 0);
    let offload_ack = fed_send_recv(&mut fed_ws, &offload).await;

    match offload_ack {
        FederationPayload::OffloadAck { accepted, .. } => assert!(accepted),
        other => panic!("Expected accepted ack, got {:?}", other),
    }

    // Verify blob is on Relay B
    assert_eq!(relay_b_storage.blob_count(), 1);
    let stored_blobs = relay_b_storage.peek(routing_id);
    assert_eq!(stored_blobs.len(), 1);
    assert_eq!(stored_blobs[0].data, blob_data);
    assert_eq!(stored_blobs[0].created_at_secs, 1700000000);
    assert_eq!(stored_blobs[0].hop_count, 1);

    // --- Client connects to Relay B and retrieves the blob ---
    let client_deps = make_client_deps(relay_b_storage.clone(), None);
    let client_url = start_client_server(client_deps).await;
    let (mut client_ws, _) = connect_async(&client_url).await.unwrap();

    // Client handshake (use client_id — routing_id will be the same since no routing_token)
    let hs = make_client_handshake(&client_id);
    client_ws
        .send(Message::Binary(encode_client(&hs)))
        .await
        .unwrap();

    // Receive HandshakeAck
    let client_ack = recv_client(&mut client_ws).await;
    assert_eq!(client_ack["payload"]["type"], "HandshakeAck");

    // Receive the offloaded blob
    let blob_msg = recv_client(&mut client_ws).await;
    assert_eq!(blob_msg["payload"]["type"], "EncryptedUpdate");
    let received_data: Vec<u8> = blob_msg["payload"]["ciphertext"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect();
    assert_eq!(received_data, blob_data);

    fed_ws.close(None).await.ok();
    client_ws.close(None).await.ok();
}

#[tokio::test]
async fn test_end_to_end_offload_with_forwarding_hints() {
    // This test simulates the complete flow:
    // 1. Relay A stores blobs for a client
    // 2. OffloadManager offloads them to a peer (via mpsc channel, not real network)
    // 3. Forwarding hints are created on Relay A
    // 4. Client connects to Relay A and receives forwarding hints

    let relay_a_storage = Arc::new(MemoryBlobStore::new());
    let relay_a_hints = Arc::new(MemoryForwardingHintStore::new());
    let relay_a_registry = Arc::new(PeerRegistry::new(0.95));
    // Tiny storage to trigger offload
    let relay_a_config = make_fed_config(100, 0.01);

    let client_id = common::generate_test_client_id(20);
    let routing_id = &client_id;

    // Store a blob on Relay A
    let blob = StoredBlob::new(vec![77; 50]);
    let _blob_id = blob.id.clone();
    relay_a_storage.store(routing_id, blob);

    // Register a peer with capacity
    let (tx, _rx) = mpsc::channel(64);
    relay_a_registry.register_peer(PeerInfo {
        relay_id: "peer-B".to_string(),
        url: "ws://relay-b:8080".to_string(),
        capacity_used_bytes: 10,
        capacity_max_bytes: 10_000,
        status: PeerStatus::Connected,
        sender: Some(tx),
        origin: PeerOrigin::Configured,
        last_seen_secs: 1000,
    });

    // Run OffloadManager
    let manager = OffloadManager {
        storage: relay_a_storage.clone() as Arc<dyn BlobStore>,
        hint_store: relay_a_hints.clone() as Arc<dyn ForwardingHintStore>,
        peer_registry: relay_a_registry,
        config: relay_a_config,
    };

    let offloaded = manager.check_and_offload().await;
    assert_eq!(offloaded, 1);

    // Verify: blob removed from Relay A, hint created
    assert_eq!(relay_a_storage.blob_count(), 0);
    assert_eq!(relay_a_hints.hint_count(), 1);
    let hints = relay_a_hints.get_hints(routing_id);
    assert_eq!(hints[0].target_relay, "ws://relay-b:8080");

    // Client connects to Relay A and should receive forwarding hints
    let client_deps = make_client_deps(
        relay_a_storage as Arc<dyn BlobStore>,
        Some(relay_a_hints as Arc<dyn ForwardingHintStore>),
    );
    let url = start_client_server(client_deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let hs = make_client_handshake(&client_id);
    ws.send(Message::Binary(encode_client(&hs))).await.unwrap();

    // HandshakeAck
    let ack = recv_client(&mut ws).await;
    assert_eq!(ack["payload"]["type"], "HandshakeAck");

    // ForwardingHints (no pending blobs since they were offloaded)
    let hints_msg = recv_client(&mut ws).await;
    assert_eq!(hints_msg["payload"]["type"], "ForwardingHints");
    let hint_array = hints_msg["payload"]["hints"].as_array().unwrap();
    assert_eq!(hint_array.len(), 1);
    assert_eq!(hint_array[0]["relay_url"], "ws://relay-b:8080");

    ws.close(None).await.ok();
}

// ============================================================================
// Tests: Multiple Blobs Offload
// ============================================================================

#[tokio::test]
async fn test_multiple_blobs_offloaded_to_peer() {
    let storage: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
    let hint_store = Arc::new(MemoryForwardingHintStore::new());
    let peer_registry = Arc::new(PeerRegistry::new(0.95));
    let config = make_fed_config(1_000_000, 0.80);

    let url = start_federation_server(FederationDeps {
        storage: storage.clone(),
        hint_store,
        peer_registry,
        config,
    })
    .await;

    let (mut ws, _) = connect_async(&url).await.unwrap();
    do_federation_handshake(&mut ws, "peer-A").await;

    // Send 3 offload blobs
    for i in 0..3 {
        let offload = make_offload_blob(
            &format!("blob-{}", i),
            &format!("route-{}", i),
            &[i as u8; 50],
            0,
        );
        let ack = fed_send_recv(&mut ws, &offload).await;
        match ack {
            FederationPayload::OffloadAck { accepted, .. } => assert!(accepted),
            other => panic!("Expected OffloadAck, got {:?}", other),
        }
    }

    assert_eq!(storage.blob_count(), 3);

    ws.close(None).await.ok();
}

// ============================================================================
// Tests: Peer Disconnect Handling
// ============================================================================

#[tokio::test]
async fn test_peer_disconnect_marks_disconnected() {
    let storage: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
    let hint_store = Arc::new(MemoryForwardingHintStore::new());
    let peer_registry = Arc::new(PeerRegistry::new(0.95));
    let config = make_fed_config(1_000_000, 0.80);

    let url = start_federation_server(FederationDeps {
        storage,
        hint_store,
        peer_registry: peer_registry.clone(),
        config,
    })
    .await;

    let (mut ws, _) = connect_async(&url).await.unwrap();
    do_federation_handshake(&mut ws, "peer-A").await;

    // Verify peer is connected
    assert_eq!(peer_registry.connected_peers().len(), 1);

    // Close the connection
    ws.close(None).await.ok();

    // Give the server time to detect disconnection
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Peer should be disconnected (no longer in connected_peers)
    assert!(peer_registry.connected_peers().is_empty());
}
