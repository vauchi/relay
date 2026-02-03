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
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::config::RelayConfig;
use crate::federation_protocol::{
    self, FederationPayload, FEDERATION_PROTOCOL_VERSION,
};
use crate::forwarding_hints::{ForwardingHint, ForwardingHintStore};
use crate::integrity;
use crate::peer_registry::{PeerInfo, PeerRegistry, PeerStatus};
use crate::storage::BlobStore;

/// Maintains a persistent connection to a peer relay.
/// Reconnects with exponential backoff on failure.
pub async fn maintain_peer_connection(
    peer_url: String,
    own_relay_id: String,
    storage: Arc<dyn BlobStore>,
    _hint_store: Arc<dyn ForwardingHintStore>,
    peer_registry: Arc<PeerRegistry>,
    config: Arc<RelayConfig>,
) {
    let mut backoff_secs = 1u64;
    let max_backoff_secs = 60u64;
    let session = &uuid::Uuid::new_v4().to_string()[..8];

    loop {
        info!(
            "[fed-conn-{}] Connecting to peer {}",
            session, peer_url
        );

        match try_connect_to_peer(
            &peer_url,
            &own_relay_id,
            storage.clone(),
            peer_registry.clone(),
            config.clone(),
            session,
        )
        .await
        {
            Ok(()) => {
                // Connection ended normally, reset backoff
                backoff_secs = 1;
            }
            Err(e) => {
                warn!(
                    "[fed-conn-{}] Connection to peer failed: {}",
                    session, e
                );
            }
        }

        // Mark peer as disconnected
        // (The peer_relay_id might not be known yet if we never got a handshake ack)

        info!(
            "[fed-conn-{}] Reconnecting in {}s",
            session, backoff_secs
        );
        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
        backoff_secs = (backoff_secs * 2).min(max_backoff_secs);
    }
}

/// Attempts a single connection to a peer relay.
async fn try_connect_to_peer(
    peer_url: &str,
    own_relay_id: &str,
    _storage: Arc<dyn BlobStore>,
    peer_registry: Arc<PeerRegistry>,
    config: Arc<RelayConfig>,
    session: &str,
) -> Result<(), String> {
    let federation_url = format!("{}/federation", peer_url);
    let (ws_stream, _) = tokio_tungstenite::connect_async(&federation_url)
        .await
        .map_err(|e| format!("WebSocket connect failed: {}", e))?;

    let (mut write, mut read) = ws_stream.split();

    // Send PeerHandshake
    let handshake = federation_protocol::create_federation_envelope(
        FederationPayload::PeerHandshake {
            relay_id: own_relay_id.to_string(),
            version: FEDERATION_PROTOCOL_VERSION,
            listen_addr: config.listen_addr.to_string(),
        },
    );
    let hs_data = federation_protocol::encode_federation_message(&handshake)
        .map_err(|e| format!("Failed to encode handshake: {}", e))?;
    write
        .send(Message::Binary(hs_data))
        .await
        .map_err(|e| format!("Failed to send handshake: {}", e))?;

    // Wait for PeerHandshakeAck
    let peer_timeout = std::time::Duration::from_secs(config.federation_peer_timeout_secs);
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

                        // Create sender channel for sending messages to this peer
                        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);

                        // Register peer
                        peer_registry.register_peer(PeerInfo {
                            relay_id: relay_id.clone(),
                            url: peer_url.to_string(),
                            capacity_used_bytes,
                            capacity_max_bytes,
                            status: PeerStatus::Connected,
                            sender: Some(tx),
                        });

                        // Spawn a task to forward outgoing messages from the channel to the WS
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

    // Read loop for incoming messages from peer
    loop {
        let msg = match timeout(
            std::time::Duration::from_secs(config.federation_peer_timeout_secs * 4),
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
                    FederationPayload::OffloadAck { blob_id: _, accepted, reason } => {
                        if accepted {
                            debug!("[fed-conn-{}] Offload ack: blob accepted", session);
                        } else {
                            warn!(
                                "[fed-conn-{}] Offload ack: blob rejected: {:?}",
                                session, reason
                            );
                        }
                        // OffloadManager handles the ack via a separate mechanism
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
                        // Send DrainAck via the sender channel
                        let ack = federation_protocol::create_federation_envelope(
                            FederationPayload::DrainAck,
                        );
                        if let Ok(data) = federation_protocol::encode_federation_message(&ack) {
                            // Use the sender channel
                            let peers = peer_registry.connected_peers();
                            if let Some(peer) = peers.iter().find(|p| p.relay_id == peer_relay_id) {
                                if let Some(ref sender) = peer.sender {
                                    let _ = sender.send(data).await;
                                }
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

/// Manages offloading blobs to federation peers when storage exceeds threshold.
pub struct OffloadManager {
    pub storage: Arc<dyn BlobStore>,
    pub hint_store: Arc<dyn ForwardingHintStore>,
    pub peer_registry: Arc<PeerRegistry>,
    pub config: Arc<RelayConfig>,
}

impl OffloadManager {
    /// Checks storage usage and offloads blobs if above threshold.
    /// Returns the number of blobs successfully offloaded.
    pub async fn check_and_offload(&self) -> usize {
        let used = self.storage.storage_size_bytes();
        let ratio = used as f64 / self.config.max_storage_bytes as f64;

        if ratio < self.config.federation_offload_threshold {
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

        let mut offloaded = 0;
        for (routing_id, blob) in candidates {
            let hash = integrity::compute_integrity_hash(&blob.data);

            let offload_msg = federation_protocol::create_federation_envelope(
                FederationPayload::OffloadBlob {
                    blob_id: blob.id.clone(),
                    routing_id: routing_id.clone(),
                    data: blob.data.clone(),
                    created_at_secs: blob.created_at_secs,
                    integrity_hash: hash,
                    hop_count: blob.hop_count,
                },
            );

            let encoded = match federation_protocol::encode_federation_message(&offload_msg) {
                Ok(data) => data,
                Err(_) => continue,
            };

            if sender.send(encoded).await.is_err() {
                warn!("Failed to send offload to peer");
                break;
            }

            // Remove from local storage and create forwarding hint
            if self.storage.remove_blob(&blob.id) {
                let hint = ForwardingHint {
                    routing_id,
                    blob_id: blob.id,
                    target_relay: peer.url.clone(),
                    created_at_secs: blob.created_at_secs,
                    expires_at_secs: blob.created_at_secs + self.config.blob_ttl_secs,
                };
                self.hint_store.store_hint(hint);
                offloaded += 1;
            }
        }

        if offloaded > 0 {
            info!("Offloaded {} blobs to peer relay", offloaded);
        }

        offloaded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarding_hints::MemoryForwardingHintStore;
    use crate::storage::MemoryBlobStore;
    use crate::storage::StoredBlob;

    fn make_test_config(max_storage: usize, threshold: f64) -> Arc<RelayConfig> {
        let mut config = RelayConfig::default();
        config.max_storage_bytes = max_storage;
        config.federation_offload_threshold = threshold;
        config.federation_offload_refuse = 0.95;
        config.federation_peer_timeout_secs = 5;
        Arc::new(config)
    }

    #[tokio::test]
    async fn test_offload_manager_below_threshold() {
        let storage = Arc::new(MemoryBlobStore::new());
        let hint_store = Arc::new(MemoryForwardingHintStore::new());
        let registry = Arc::new(PeerRegistry::new(0.95));
        let config = make_test_config(1_000_000, 0.80);

        // Store a small amount (well below 80% of 1MB)
        storage.store("r1", StoredBlob::new(vec![1; 100]));

        let manager = OffloadManager {
            storage,
            hint_store: hint_store.clone(),
            peer_registry: registry,
            config,
        };

        let offloaded = manager.check_and_offload().await;
        assert_eq!(offloaded, 0);
        assert_eq!(hint_store.hint_count(), 0);
    }

    #[tokio::test]
    async fn test_offload_manager_no_peers() {
        let storage = Arc::new(MemoryBlobStore::new());
        let hint_store = Arc::new(MemoryForwardingHintStore::new());
        let registry = Arc::new(PeerRegistry::new(0.95));
        // Use tiny max_storage so even a small blob triggers offload
        let config = make_test_config(100, 0.01);

        storage.store("r1", StoredBlob::new(vec![1; 50]));

        let manager = OffloadManager {
            storage,
            hint_store,
            peer_registry: registry,
            config,
        };

        let offloaded = manager.check_and_offload().await;
        assert_eq!(offloaded, 0);
    }

    #[tokio::test]
    async fn test_offload_manager_successful_offload() {
        let storage = Arc::new(MemoryBlobStore::new());
        let hint_store = Arc::new(MemoryForwardingHintStore::new());
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
        });

        let manager = OffloadManager {
            storage: storage.clone(),
            hint_store: hint_store.clone(),
            peer_registry: registry,
            config,
        };

        let offloaded = manager.check_and_offload().await;
        assert_eq!(offloaded, 1);

        // Blob removed from local storage
        assert_eq!(storage.blob_count(), 0);

        // Hint created
        assert_eq!(hint_store.hint_count(), 1);
        let hints = hint_store.get_hints("r1");
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].target_relay, "ws://peer-1:8080");

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
    }
}
