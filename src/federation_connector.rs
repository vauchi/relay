// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Federation Connector (Initiator Side)
//!
//! Connects to peer relays and maintains persistent federation connections.
//! Handles outbound federation: sending offload blobs, receiving acks, and
//! reconnecting on failure with exponential backoff.

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::config::RelayConfig;
use crate::federation_protocol::{self, FEDERATION_PROTOCOL_VERSION, FederationPayload};

/// TCP connect timeout — prevents 75-second OS-level waits on unreachable hosts.
const TCP_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
use crate::forwarding_hints::{ForwardingHint, ForwardingHintStore};
use crate::integrity;
use crate::metrics::RelayMetrics;
use crate::padding;
use crate::peer_registry::{PeerInfo, PeerOrigin, PeerRegistry, PeerStatus};
use crate::storage::BlobStore;

/// Maintains a persistent connection to a peer relay.
/// Reconnects with exponential backoff on failure.
/// When `tls_client_config` is provided, connections use mTLS for authentication.
pub async fn maintain_peer_connection(
    peer_url: String,
    own_relay_id: String,
    peer_registry: Arc<PeerRegistry>,
    config: Arc<RelayConfig>,
    tls_client_config: Option<Arc<tokio_rustls::rustls::ClientConfig>>,
    offload_manager: Option<Arc<OffloadManager>>,
    metrics: RelayMetrics,
) {
    let mut backoff_secs = 1u64;
    let max_backoff_secs = 60u64;
    let session = &uuid::Uuid::new_v4().to_string()[..8];

    loop {
        info!("[fed-conn-{}] Connecting to peer {}", session, peer_url);
        metrics.federation_peer_connections_total.inc();

        match try_connect_to_peer(
            &peer_url,
            &own_relay_id,
            peer_registry.clone(),
            config.clone(),
            session,
            tls_client_config.clone(),
            offload_manager.clone(),
        )
        .await
        {
            Ok(()) => {
                backoff_secs = 1;
            }
            Err(e) => {
                warn!("[fed-conn-{}] Connection to peer failed: {}", session, e);
                metrics.federation_peer_connection_errors.inc();
            }
        }

        // Mark peer as disconnected
        // (The peer_relay_id might not be known yet if we never got a handshake ack)

        info!("[fed-conn-{}] Reconnecting in {}s", session, backoff_secs);
        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
        backoff_secs = (backoff_secs * 2).min(max_backoff_secs);
    }
}

/// Attempts a single connection to a peer relay.
/// Uses mTLS when `tls_client_config` is provided.
async fn try_connect_to_peer(
    peer_url: &str,
    own_relay_id: &str,
    peer_registry: Arc<PeerRegistry>,
    config: Arc<RelayConfig>,
    session: &str,
    tls_client_config: Option<Arc<tokio_rustls::rustls::ClientConfig>>,
    offload_manager: Option<Arc<OffloadManager>>,
) -> Result<(), String> {
    // Validate URL against SSRF blocklist (Tracker #133)
    crate::url_validation::validate_federation_url(peer_url)
        .map_err(|e| format!("SSRF validation failed for {}: {}", peer_url, e))?;

    let federation_url = format!("{}/federation", peer_url);

    if let Some(ref client_config) = tls_client_config {
        info!("[fed-conn-{}] Using mTLS for peer connection", session);
        let ws_stream = connect_with_tls(&federation_url, client_config).await?;
        handle_peer_session(
            ws_stream,
            own_relay_id,
            peer_url,
            peer_registry,
            config,
            session,
            offload_manager,
        )
        .await
    } else {
        // Non-TLS path: explicit DNS resolution + SSRF validation (prevents
        // DNS rebinding). S15: Connect to the validated SocketAddr, not the
        // URL string — avoids a second DNS resolution that could return a
        // different (private) IP.
        let stripped = federation_url
            .strip_prefix("ws://")
            .ok_or_else(|| "Non-TLS federation requires ws:// scheme".to_string())?;
        let authority = stripped.split('/').next().unwrap_or(stripped);
        let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
            let port: u16 = p.parse().map_err(|_| "Invalid port in URL".to_string())?;
            (h.to_string(), port)
        } else {
            (authority.to_string(), 80u16)
        };
        let validated_addr = crate::url_validation::resolve_and_validate(&host, port)
            .await
            .map_err(|e| format!("SSRF: {}", e))?;

        let tcp_stream = timeout(
            TCP_CONNECT_TIMEOUT,
            tokio::net::TcpStream::connect(validated_addr),
        )
        .await
        .map_err(|_| "TCP connect timed out".to_string())?
        .map_err(|e| format!("TCP connect failed: {}", e))?;

        let (ws_stream, _) = tokio_tungstenite::client_async(&federation_url, tcp_stream)
            .await
            .map_err(|e| format!("WebSocket upgrade failed: {}", e))?;
        handle_peer_session(
            ws_stream,
            own_relay_id,
            peer_url,
            peer_registry,
            config,
            session,
            offload_manager,
        )
        .await
    }
}

/// Connects to a peer relay using TLS, then upgrades to WebSocket.
async fn connect_with_tls(
    url: &str,
    client_config: &Arc<tokio_rustls::rustls::ClientConfig>,
) -> Result<WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>, String> {
    let stripped = url
        .strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))
        .ok_or_else(|| "Invalid WebSocket URL scheme".to_string())?;

    let authority = stripped.split('/').next().unwrap_or(stripped);
    let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
        let port: u16 = p.parse().map_err(|_| "Invalid port in URL".to_string())?;
        (h.to_string(), port)
    } else {
        (authority.to_string(), 443u16)
    };

    // Explicit DNS resolution + SSRF validation (prevents DNS rebinding)
    // Validates ALL resolved IPs before TCP connect — hostnames that resolve
    // to private IPs are blocked, not just IP literal URLs.
    let validated_addr = crate::url_validation::resolve_and_validate(&host, port)
        .await
        .map_err(|e| format!("SSRF: {}", e))?;

    let tcp_stream = timeout(
        TCP_CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(validated_addr),
    )
    .await
    .map_err(|_| "TCP connect timed out".to_string())?
    .map_err(|e| format!("TCP connect failed: {}", e))?;

    let connector = tokio_rustls::TlsConnector::from(client_config.clone());
    let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(host)
        .map_err(|e| format!("Invalid server name: {}", e))?;
    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| format!("TLS handshake failed: {}", e))?;

    let (ws_stream, _) = tokio_tungstenite::client_async(url, tls_stream)
        .await
        .map_err(|e| format!("WebSocket upgrade over TLS failed: {}", e))?;

    Ok(ws_stream)
}

/// Handles the federation protocol session after WebSocket connection is established.
/// Generic over the stream type to support both plain TCP and TLS connections.
async fn handle_peer_session<S>(
    ws_stream: WebSocketStream<S>,
    own_relay_id: &str,
    peer_url: &str,
    peer_registry: Arc<PeerRegistry>,
    config: Arc<RelayConfig>,
    session: &str,
    offload_manager: Option<Arc<OffloadManager>>,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut write, mut read) = ws_stream.split();

    let handshake =
        federation_protocol::create_federation_envelope(FederationPayload::PeerHandshake {
            relay_id: own_relay_id.to_string(),
            version: FEDERATION_PROTOCOL_VERSION,
            listen_addr: config.network.listen_addr.to_string(),
        });
    let hs_data = federation_protocol::encode_federation_message(&handshake)
        .map_err(|e| format!("Failed to encode handshake: {}", e))?;
    write
        .send(Message::Binary(hs_data))
        .await
        .map_err(|e| format!("Failed to send handshake: {}", e))?;

    let peer_timeout = std::time::Duration::from_secs(config.federation.peer_timeout_secs);
    let peer_relay_id = match timeout(peer_timeout, read.next()).await {
        Ok(Some(Ok(Message::Binary(data)))) => {
            match federation_protocol::decode_federation_message(&data) {
                Ok(envelope) => {
                    if let FederationPayload::PeerHandshakeAck {
                        relay_id,
                        accepted,
                        capacity_used_bytes,
                        capacity_max_bytes,
                        ..
                    } = envelope.payload
                    {
                        if !accepted {
                            return Err("Peer rejected handshake".to_string());
                        }

                        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);

                        let now_secs = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        peer_registry.register_peer(PeerInfo {
                            relay_id: relay_id.clone(),
                            url: peer_url.to_string(),
                            capacity_used_bytes,
                            capacity_max_bytes,
                            status: PeerStatus::Connected,
                            sender: Some(tx),
                            origin: PeerOrigin::Configured,
                            last_seen_secs: now_secs,
                        });

                        let write = Arc::new(tokio::sync::Mutex::new(write));
                        let write_clone = write.clone();
                        tokio::spawn(async move {
                            while let Some(data) = rx.recv().await {
                                let mut w = write_clone.lock().await;
                                if w.send(Message::Binary(data)).await.is_err() {
                                    break;
                                }
                            }
                        });

                        info!("[fed-conn-{}] Handshake accepted by peer", session);
                        relay_id
                    } else {
                        return Err("Expected PeerHandshakeAck".to_string());
                    }
                }
                Err(e) => return Err(format!("Failed to decode ack: {}", e)),
            }
        }
        Ok(Some(Ok(_))) => return Err("Expected binary message".to_string()),
        Ok(Some(Err(e))) => return Err(format!("WebSocket error: {}", e)),
        Ok(None) => return Err("Connection closed before ack".to_string()),
        Err(_) => return Err("Handshake ack timeout".to_string()),
    };

    loop {
        let msg = match timeout(
            std::time::Duration::from_secs(config.federation.peer_timeout_secs * 4),
            read.next(),
        )
        .await
        {
            Ok(Some(msg)) => msg,
            Ok(None) => {
                debug!("[fed-conn-{}] Peer disconnected", session);
                break;
            }
            Err(_) => {
                debug!("[fed-conn-{}] Peer read timeout", session);
                break;
            }
        };

        match msg {
            Ok(Message::Binary(data)) => {
                let envelope = match federation_protocol::decode_federation_message(&data) {
                    Ok(e) => e,
                    Err(e) => {
                        warn!("[fed-conn-{}] Failed to decode: {}", session, e);
                        continue;
                    }
                };

                match envelope.payload {
                    FederationPayload::OffloadAck {
                        blob_id,
                        accepted,
                        reason,
                    } => {
                        if accepted {
                            debug!(
                                "[fed-conn-{}] Offload ack: blob {} accepted",
                                session, blob_id
                            );
                        } else {
                            warn!(
                                "[fed-conn-{}] Offload ack: blob {} rejected: {:?}",
                                session, blob_id, reason
                            );
                        }
                        if let Some(ref offload_mgr) = offload_manager {
                            offload_mgr.handle_offload_ack(&blob_id, accepted);
                        }
                    }
                    FederationPayload::CapacityReport {
                        used_bytes,
                        max_bytes,
                        ..
                    } => {
                        peer_registry.update_capacity(&peer_relay_id, used_bytes, max_bytes);
                    }
                    FederationPayload::DrainNotice { .. } => {
                        peer_registry.set_status(&peer_relay_id, PeerStatus::Draining);
                        let ack = federation_protocol::create_federation_envelope(
                            FederationPayload::DrainAck,
                        );
                        if let Ok(data) = federation_protocol::encode_federation_message(&ack) {
                            let peers = peer_registry.connected_peers();
                            if let Some(peer) = peers.iter().find(|p| p.relay_id == peer_relay_id)
                                && let Some(ref sender) = peer.sender
                            {
                                let _ = sender.send(data).await;
                            }
                        }
                    }
                    _ => {
                        debug!("[fed-conn-{}] Unhandled message from peer", session);
                    }
                }
            }
            Ok(Message::Ping(_data)) => {
                // Pong is handled automatically by tungstenite for outgoing connections
                debug!("[fed-conn-{}] Received ping", session);
            }
            Ok(Message::Close(_)) => {
                debug!("[fed-conn-{}] Peer sent close", session);
                break;
            }
            Ok(_) => {}
            Err(e) => {
                warn!("[fed-conn-{}] Connection error: {}", session, e);
                break;
            }
        }
    }

    peer_registry.set_status(&peer_relay_id, PeerStatus::Disconnected);
    Ok(())
}

/// Metadata for a blob pending offload acknowledgment.
#[derive(Debug, Clone)]
pub struct PendingOffload {
    pub routing_id: String,
    pub created_at_secs: u64,
    pub target_relay: String,
}

/// Manages offloading blobs to federation peers when storage exceeds threshold.
///
/// Blobs are only deleted from local storage after the peer confirms receipt
/// via an `OffloadAck { accepted: true }` message. This prevents data loss
/// if the peer fails to store the blob.
pub struct OffloadManager {
    pub storage: Arc<dyn BlobStore>,
    pub hint_store: Arc<dyn ForwardingHintStore>,
    pub peer_registry: Arc<PeerRegistry>,
    pub config: Arc<RelayConfig>,
    pub metrics: RelayMetrics,
    /// Blobs sent to peers awaiting acknowledgment. Keyed by blob_id.
    pub pending_offloads:
        Arc<parking_lot::Mutex<std::collections::HashMap<String, PendingOffload>>>,
}

impl OffloadManager {
    /// Checks storage usage and offloads blobs if above threshold.
    /// Returns the number of blobs sent (not yet confirmed).
    pub async fn check_and_offload(&self) -> usize {
        let used = self.storage.storage_size_bytes();
        let ratio = used as f64 / self.config.storage.max_storage_bytes as f64;

        if ratio < self.config.federation.offload_threshold {
            return 0;
        }

        let peer = match self.peer_registry.get_peer_with_capacity() {
            Some(p) => p,
            None => {
                debug!("No federation peers with capacity available for offload");
                return 0;
            }
        };

        let sender = match peer.sender {
            Some(ref s) => s.clone(),
            None => return 0,
        };

        let batch_size = 10;
        let candidates = self.storage.get_oldest_blobs(batch_size);

        let pending_ids: std::collections::HashSet<String> = {
            let pending = self.pending_offloads.lock();
            pending.keys().cloned().collect()
        };
        let candidates: Vec<_> = candidates
            .into_iter()
            .filter(|(_, blob)| !pending_ids.contains(&blob.id))
            .collect();

        let mut sent = 0;
        for (routing_id, blob) in candidates {
            // Pad blob data to fixed bucket size to prevent traffic analysis
            let padded_data = padding::pad(&blob.data);
            let hash = integrity::compute_integrity_hash(&padded_data);

            let offload_msg =
                federation_protocol::create_federation_envelope(FederationPayload::OffloadBlob {
                    blob_id: blob.id.clone(),
                    routing_id: routing_id.clone(),
                    data: padded_data,
                    created_at_secs: blob.created_at_secs,
                    integrity_hash: hash,
                    hop_count: blob.hop_count,
                });

            let encoded = match federation_protocol::encode_federation_message(&offload_msg) {
                Ok(data) => data,
                Err(_) => continue,
            };

            if sender.send(encoded).await.is_err() {
                warn!("Failed to send offload to peer");
                break;
            }

            // Track as pending — only delete when ack received
            {
                let mut pending = self.pending_offloads.lock();
                pending.insert(
                    blob.id.clone(),
                    PendingOffload {
                        routing_id,
                        created_at_secs: blob.created_at_secs,
                        target_relay: peer.url.clone(),
                    },
                );
            }
            self.metrics.federation_offloads_sent.inc();
            sent += 1;
        }

        if sent > 0 {
            info!("Sent {} blobs to peer relay (awaiting ack)", sent);
        }

        sent
    }

    /// Called when an `OffloadAck` is received from a peer.
    ///
    /// If accepted, removes the blob from local storage and creates a forwarding hint.
    /// If rejected, removes from pending so it can be retried later.
    pub fn handle_offload_ack(&self, blob_id: &str, accepted: bool) {
        let pending_info = {
            let mut pending = self.pending_offloads.lock();
            pending.remove(blob_id)
        };

        if let Some(info) = pending_info {
            if accepted {
                if self.storage.remove_blob(blob_id) {
                    let hint = ForwardingHint {
                        routing_id: info.routing_id,
                        blob_id: blob_id.to_string(),
                        target_relay: info.target_relay,
                        created_at_secs: info.created_at_secs,
                        expires_at_secs: info.created_at_secs + self.config.storage.blob_ttl_secs,
                    };
                    self.hint_store.store_hint(hint);
                    self.metrics.federation_hints_stored.inc();
                    self.metrics.federation_hints_active.inc();
                    debug!("Offload confirmed: blob {} deleted locally", blob_id);
                }
            } else {
                warn!("Offload rejected for blob {}, will retry later", blob_id);
            }
        }
    }
}

// INLINE_TEST_REQUIRED: Tests need access to private federation internals and mock types
#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarding_hints::SqliteForwardingHintStore;
    use crate::storage::SqliteBlobStore;
    use crate::storage::StoredBlob;

    fn make_test_config(max_storage: usize, threshold: f64) -> Arc<RelayConfig> {
        use crate::config::{FederationConfig, StorageConfig};
        Arc::new(RelayConfig {
            storage: StorageConfig {
                max_storage_bytes: max_storage,
                ..Default::default()
            },
            federation: FederationConfig {
                offload_threshold: threshold,
                offload_refuse: 0.95,
                peer_timeout_secs: 5,
                ..Default::default()
            },
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn test_offload_manager_below_threshold() {
        let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
        let hint_store = Arc::new(SqliteForwardingHintStore::in_memory().unwrap());
        let registry = Arc::new(PeerRegistry::new(0.95));
        let config = make_test_config(1_000_000, 0.80);

        // Store a small amount (well below 80% of 1MB)
        storage.store("r1", StoredBlob::new(vec![1; 100]));

        let manager = OffloadManager {
            storage,
            hint_store: hint_store.clone(),
            peer_registry: registry,
            config,
            metrics: RelayMetrics::new(),
            pending_offloads: Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
        };

        let offloaded = manager.check_and_offload().await;
        assert_eq!(offloaded, 0);
        assert_eq!(hint_store.hint_count(), 0);
    }

    #[tokio::test]
    async fn test_offload_manager_no_peers() {
        let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
        let hint_store = Arc::new(SqliteForwardingHintStore::in_memory().unwrap());
        let registry = Arc::new(PeerRegistry::new(0.95));
        // Use tiny max_storage so even a small blob triggers offload
        let config = make_test_config(100, 0.01);

        storage.store("r1", StoredBlob::new(vec![1; 50]));

        let manager = OffloadManager {
            storage,
            hint_store,
            peer_registry: registry,
            config,
            metrics: RelayMetrics::new(),
            pending_offloads: Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
        };

        let offloaded = manager.check_and_offload().await;
        assert_eq!(offloaded, 0);
    }

    #[tokio::test]
    async fn test_offload_manager_sends_to_peer() {
        let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
        let hint_store = Arc::new(SqliteForwardingHintStore::in_memory().unwrap());
        let registry = Arc::new(PeerRegistry::new(0.95));
        // Very small max storage to trigger offload
        let config = make_test_config(100, 0.01);

        // Store a blob
        let blob = StoredBlob::new(vec![1; 50]);
        let blob_id = blob.id.clone();
        storage.store("r1", blob);

        // Register a peer with capacity
        let (tx, mut rx) = mpsc::channel(64);
        registry.register_peer(PeerInfo {
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
            storage: storage.clone(),
            hint_store: hint_store.clone(),
            peer_registry: registry,
            config,
            metrics: RelayMetrics::new(),
            pending_offloads: Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
        };

        let sent = manager.check_and_offload().await;
        assert_eq!(sent, 1);

        // Blob still in local storage (awaiting ack)
        assert_eq!(storage.blob_count(), 1);

        // No hint yet (awaiting ack)
        assert_eq!(hint_store.hint_count(), 0);

        // Blob is in pending_offloads
        assert_eq!(manager.pending_offloads.lock().len(), 1);

        // Message was sent via the channel
        let sent_data = rx.try_recv().unwrap();
        let envelope = federation_protocol::decode_federation_message(&sent_data).unwrap();
        if let FederationPayload::OffloadBlob {
            blob_id: sent_id, ..
        } = envelope.payload
        {
            assert_eq!(sent_id, blob_id);
        } else {
            panic!("Expected OffloadBlob message");
        }

        // Simulate ack: blob accepted
        manager.handle_offload_ack(&blob_id, true);

        // Now blob is deleted and hint created
        assert_eq!(storage.blob_count(), 0);
        assert_eq!(hint_store.hint_count(), 1);
        let hints = hint_store.get_hints("r1");
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].target_relay, "ws://peer-1:8080");
        assert!(manager.pending_offloads.lock().is_empty());
    }

    #[tokio::test]
    async fn test_offload_ack_rejected_keeps_blob() {
        let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
        let hint_store = Arc::new(SqliteForwardingHintStore::in_memory().unwrap());
        let registry = Arc::new(PeerRegistry::new(0.95));
        let config = make_test_config(100, 0.01);

        let blob = StoredBlob::new(vec![1; 50]);
        let blob_id = blob.id.clone();
        storage.store("r1", blob);

        let (tx, _rx) = mpsc::channel(64);
        registry.register_peer(PeerInfo {
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
            storage: storage.clone(),
            hint_store: hint_store.clone(),
            peer_registry: registry,
            config,
            metrics: RelayMetrics::new(),
            pending_offloads: Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
        };

        manager.check_and_offload().await;
        assert_eq!(manager.pending_offloads.lock().len(), 1);

        // Simulate ack: blob rejected
        manager.handle_offload_ack(&blob_id, false);

        // Blob still in local storage (not deleted)
        assert_eq!(storage.blob_count(), 1);
        // No hint created
        assert_eq!(hint_store.hint_count(), 0);
        // Pending cleared
        assert!(manager.pending_offloads.lock().is_empty());
    }

    // Trace: codebase-review-tracker item #131
    #[tokio::test]
    async fn test_connect_with_tls_invalid_host() {
        // Build a minimal client config (no real certs needed for this test)
        let root_store = tokio_rustls::rustls::RootCertStore::empty();
        let client_config = Arc::new(
            tokio_rustls::rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        );

        // Loopback should now be blocked by SSRF validation (#133)
        let result = connect_with_tls("wss://127.0.0.1:1/federation", &client_config).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("SSRF") || err.contains("loopback"),
            "Expected SSRF block, got: {}",
            err
        );

        // Non-routable public IP should fail at TCP connect
        let result2 = connect_with_tls("wss://198.51.100.1:1/federation", &client_config).await;
        assert!(result2.is_err());
        let err2 = result2.unwrap_err();
        assert!(
            err2.contains("TCP connect failed") || err2.contains("connect"),
            "Expected TCP connect failure, got: {}",
            err2
        );
    }

    // Trace: codebase-review-tracker item #131
    #[tokio::test]
    async fn test_connect_with_tls_invalid_url() {
        let root_store = tokio_rustls::rustls::RootCertStore::empty();
        let client_config = Arc::new(
            tokio_rustls::rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        );

        let result = connect_with_tls("http://not-websocket/federation", &client_config).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid WebSocket URL scheme"));
    }

    /// handle_offload_ack with an unknown blob_id is a no-op (no panic).
    #[test]
    fn test_offload_ack_unknown_blob_noop() {
        let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
        let hint_store = Arc::new(SqliteForwardingHintStore::in_memory().unwrap());
        let registry = Arc::new(PeerRegistry::new(0.95));
        let config = make_test_config(100, 0.01);

        let manager = OffloadManager {
            storage: storage.clone(),
            hint_store: hint_store.clone(),
            peer_registry: registry,
            config,
            metrics: RelayMetrics::new(),
            pending_offloads: Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
        };

        // Ack for a blob that was never pending — should not panic
        manager.handle_offload_ack("nonexistent-blob", true);

        assert_eq!(storage.blob_count(), 0);
        assert_eq!(hint_store.hint_count(), 0);
    }

    /// Already-pending blobs are skipped in check_and_offload (dedup filter).
    #[tokio::test]
    async fn test_offload_skips_already_pending_blobs() {
        let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
        let hint_store = Arc::new(SqliteForwardingHintStore::in_memory().unwrap());
        let registry = Arc::new(PeerRegistry::new(0.95));
        let config = make_test_config(100, 0.01);

        let blob = StoredBlob::new(vec![1; 50]);
        let blob_id = blob.id.clone();
        storage.store("r1", blob);

        let (tx, _rx) = mpsc::channel(64);
        registry.register_peer(PeerInfo {
            relay_id: "peer-1".to_string(),
            url: "ws://peer-1:8080".to_string(),
            capacity_used_bytes: 10,
            capacity_max_bytes: 1000,
            status: PeerStatus::Connected,
            sender: Some(tx),
            origin: PeerOrigin::Configured,
            last_seen_secs: 1000,
        });

        // Pre-insert blob into pending
        let pending = Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
        pending.lock().insert(
            blob_id.clone(),
            PendingOffload {
                routing_id: "r1".to_string(),
                created_at_secs: 0,
                target_relay: "ws://peer-1:8080".to_string(),
            },
        );

        let manager = OffloadManager {
            storage,
            hint_store,
            peer_registry: registry,
            config,
            metrics: RelayMetrics::new(),
            pending_offloads: pending,
        };

        // Should send 0 because the only blob is already pending
        let sent = manager.check_and_offload().await;
        assert_eq!(sent, 0, "Already-pending blobs should be skipped");
    }

    /// Peer with no sender channel returns 0 offloads.
    #[tokio::test]
    async fn test_offload_peer_no_sender() {
        let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
        let hint_store = Arc::new(SqliteForwardingHintStore::in_memory().unwrap());
        let registry = Arc::new(PeerRegistry::new(0.95));
        let config = make_test_config(100, 0.01);

        storage.store("r1", StoredBlob::new(vec![1; 50]));

        // Register peer with NO sender channel
        registry.register_peer(PeerInfo {
            relay_id: "peer-1".to_string(),
            url: "ws://peer-1:8080".to_string(),
            capacity_used_bytes: 10,
            capacity_max_bytes: 1000,
            status: PeerStatus::Connected,
            sender: None,
            origin: PeerOrigin::Configured,
            last_seen_secs: 1000,
        });

        let manager = OffloadManager {
            storage,
            hint_store,
            peer_registry: registry,
            config,
            metrics: RelayMetrics::new(),
            pending_offloads: Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
        };

        let sent = manager.check_and_offload().await;
        assert_eq!(sent, 0, "Peer without sender should return 0");
    }

    /// PendingOffload struct can be constructed and cloned.
    #[test]
    fn test_pending_offload_construction() {
        let offload = PendingOffload {
            routing_id: "route-1".to_string(),
            created_at_secs: 1000,
            target_relay: "ws://relay-a:8080".to_string(),
        };
        let cloned = offload.clone();
        assert_eq!(cloned.routing_id, "route-1");
        assert_eq!(cloned.created_at_secs, 1000);
        assert_eq!(cloned.target_relay, "ws://relay-a:8080");
    }

    // Trace: codebase-review-tracker item #131
    #[test]
    #[allow(clippy::type_complexity)]
    fn test_maintain_peer_connection_accepts_tls_config() {
        // allow(zero_assertions): compile-time signature check
        // Verify the function signature accepts None (backward compatible)
        // This is a compile-time check — we don't actually connect
        let fn_ref: fn(
            String,
            String,
            Arc<PeerRegistry>,
            Arc<RelayConfig>,
            Option<Arc<tokio_rustls::rustls::ClientConfig>>,
            Option<Arc<OffloadManager>>,
            RelayMetrics,
        ) -> _ = |a, b, c, d, e, f, g| maintain_peer_connection(a, b, c, d, e, f, g);
        // Verify the function reference is valid (compile-time signature check)
        assert!(std::mem::size_of_val(&fn_ref) > 0);
    }
}
