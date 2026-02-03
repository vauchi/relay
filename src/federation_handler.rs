// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Federation Connection Handler
//!
//! Handles incoming federation WebSocket connections from peer relays.
//! Processes offloaded blobs, capacity reports, and drain notices.
//! Follows zero-knowledge logging rules: never log routing_id, only aggregate
//! counts with random session labels.

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, info, warn};

use crate::config::RelayConfig;
use crate::federation_protocol::{self, FederationPayload, FEDERATION_PROTOCOL_VERSION};
use crate::forwarding_hints::ForwardingHintStore;
use crate::integrity;
use crate::peer_registry::{PeerInfo, PeerRegistry, PeerStatus};
use crate::storage::{BlobStore, StoredBlob};

/// Dependencies for handling a federation connection.
pub struct FederationDeps {
    pub storage: Arc<dyn BlobStore>,
    pub hint_store: Arc<dyn ForwardingHintStore>,
    pub peer_registry: Arc<PeerRegistry>,
    pub config: Arc<RelayConfig>,
}

/// Handles an incoming federation WebSocket connection from a peer relay.
pub async fn handle_federation_connection(
    ws_stream: WebSocketStream<TcpStream>,
    deps: FederationDeps,
) {
    let FederationDeps {
        storage,
        hint_store: _hint_store,
        peer_registry,
        config,
    } = deps;

    // Random session label for logging (never log routing_id)
    let session = &uuid::Uuid::new_v4().to_string()[..8];

    let (mut write, mut read) = ws_stream.split();

    // Wait for PeerHandshake with timeout
    let peer_timeout = std::time::Duration::from_secs(config.federation_peer_timeout_secs);
    let (peer_relay_id, _peer_version) = match timeout(peer_timeout, read.next()).await {
        Ok(Some(Ok(Message::Binary(data)))) => {
            match federation_protocol::decode_federation_message(&data) {
                Ok(envelope) => {
                    if let FederationPayload::PeerHandshake {
                        relay_id,
                        version,
                        listen_addr: _,
                    } = envelope.payload
                    {
                        if version != FEDERATION_PROTOCOL_VERSION {
                            warn!(
                                "[fed-{}] Version mismatch: got {}, expected {}",
                                session, version, FEDERATION_PROTOCOL_VERSION
                            );
                            // Send rejection
                            let ack = federation_protocol::create_federation_envelope(
                                FederationPayload::PeerHandshakeAck {
                                    relay_id: config.federation_relay_id.clone(),
                                    version: FEDERATION_PROTOCOL_VERSION,
                                    accepted: false,
                                    capacity_used_bytes: 0,
                                    capacity_max_bytes: 0,
                                },
                            );
                            if let Ok(data) = federation_protocol::encode_federation_message(&ack) {
                                let _ = write.send(Message::Binary(data)).await;
                            }
                            return;
                        }
                        (relay_id, version)
                    } else {
                        warn!(
                            "[fed-{}] Expected PeerHandshake, got other message",
                            session
                        );
                        return;
                    }
                }
                Err(e) => {
                    warn!("[fed-{}] Failed to decode handshake: {}", session, e);
                    return;
                }
            }
        }
        Ok(Some(Ok(_))) => {
            warn!("[fed-{}] Expected binary message for handshake", session);
            return;
        }
        Ok(Some(Err(e))) => {
            warn!("[fed-{}] Error reading handshake: {}", session, e);
            return;
        }
        Ok(None) => {
            debug!("[fed-{}] Connection closed before handshake", session);
            return;
        }
        Err(_) => {
            warn!("[fed-{}] Handshake timeout", session);
            return;
        }
    };

    info!("[fed-{}] Peer connected", session);

    // Register peer in PeerRegistry
    let used_bytes = storage.storage_size_bytes();
    peer_registry.register_peer(PeerInfo {
        relay_id: peer_relay_id.clone(),
        url: String::new(), // Acceptor doesn't know the URL
        capacity_used_bytes: used_bytes,
        capacity_max_bytes: config.max_storage_bytes,
        status: PeerStatus::Connected,
        sender: None,
    });

    // Send PeerHandshakeAck
    let ack =
        federation_protocol::create_federation_envelope(FederationPayload::PeerHandshakeAck {
            relay_id: config.federation_relay_id.clone(),
            version: FEDERATION_PROTOCOL_VERSION,
            accepted: true,
            capacity_used_bytes: used_bytes,
            capacity_max_bytes: config.max_storage_bytes,
        });
    if let Ok(data) = federation_protocol::encode_federation_message(&ack) {
        if write.send(Message::Binary(data)).await.is_err() {
            warn!("[fed-{}] Failed to send PeerHandshakeAck", session);
            peer_registry.set_status(&peer_relay_id, PeerStatus::Disconnected);
            return;
        }
    }

    let mut offload_count: usize = 0;

    // Main message loop
    loop {
        let msg = match timeout(
            std::time::Duration::from_secs(config.federation_peer_timeout_secs * 2),
            read.next(),
        )
        .await
        {
            Ok(Some(msg)) => msg,
            Ok(None) => {
                debug!("[fed-{}] Peer disconnected", session);
                break;
            }
            Err(_) => {
                warn!("[fed-{}] Peer idle timeout", session);
                break;
            }
        };

        match msg {
            Ok(Message::Binary(data)) => {
                let envelope = match federation_protocol::decode_federation_message(&data) {
                    Ok(e) => e,
                    Err(e) => {
                        warn!("[fed-{}] Failed to decode message: {}", session, e);
                        continue;
                    }
                };

                match envelope.payload {
                    FederationPayload::OffloadBlob {
                        blob_id,
                        routing_id: blob_routing_id,
                        data: blob_data,
                        created_at_secs,
                        integrity_hash,
                        hop_count,
                    } => {
                        // Reject if hop_count >= 1 (prevent re-offloading)
                        if hop_count >= 1 {
                            let ack = federation_protocol::create_federation_envelope(
                                FederationPayload::OffloadAck {
                                    blob_id,
                                    accepted: false,
                                    reason: Some("hop_count too high".to_string()),
                                },
                            );
                            if let Ok(data) = federation_protocol::encode_federation_message(&ack) {
                                let _ = write.send(Message::Binary(data)).await;
                            }
                            continue;
                        }

                        // Verify integrity
                        if !integrity::verify_integrity_hash(&blob_data, &integrity_hash) {
                            let ack = federation_protocol::create_federation_envelope(
                                FederationPayload::OffloadAck {
                                    blob_id,
                                    accepted: false,
                                    reason: Some("integrity check failed".to_string()),
                                },
                            );
                            if let Ok(data) = federation_protocol::encode_federation_message(&ack) {
                                let _ = write.send(Message::Binary(data)).await;
                            }
                            continue;
                        }

                        // Check capacity
                        let current_usage = storage.storage_size_bytes();
                        let usage_ratio = current_usage as f64 / config.max_storage_bytes as f64;
                        if usage_ratio >= config.federation_offload_refuse {
                            let ack = federation_protocol::create_federation_envelope(
                                FederationPayload::OffloadAck {
                                    blob_id,
                                    accepted: false,
                                    reason: Some("at capacity".to_string()),
                                },
                            );
                            if let Ok(data) = federation_protocol::encode_federation_message(&ack) {
                                let _ = write.send(Message::Binary(data)).await;
                            }
                            continue;
                        }

                        // Store blob with incremented hop_count
                        let blob =
                            StoredBlob::with_metadata(blob_data, created_at_secs, hop_count + 1);
                        storage.store(&blob_routing_id, blob);
                        offload_count += 1;

                        // Send acceptance ack
                        let ack = federation_protocol::create_federation_envelope(
                            FederationPayload::OffloadAck {
                                blob_id,
                                accepted: true,
                                reason: None,
                            },
                        );
                        if let Ok(data) = federation_protocol::encode_federation_message(&ack) {
                            let _ = write.send(Message::Binary(data)).await;
                        }
                    }
                    FederationPayload::CapacityReport {
                        used_bytes,
                        max_bytes,
                        blob_count: _,
                    } => {
                        peer_registry.update_capacity(&peer_relay_id, used_bytes, max_bytes);
                        debug!("[fed-{}] Updated peer capacity", session);
                    }
                    FederationPayload::DrainNotice {
                        drain_timeout_secs: _,
                    } => {
                        peer_registry.set_status(&peer_relay_id, PeerStatus::Draining);
                        info!("[fed-{}] Peer is draining", session);
                        // Send DrainAck
                        let ack = federation_protocol::create_federation_envelope(
                            FederationPayload::DrainAck,
                        );
                        if let Ok(data) = federation_protocol::encode_federation_message(&ack) {
                            let _ = write.send(Message::Binary(data)).await;
                        }
                    }
                    FederationPayload::Unknown => {
                        debug!("[fed-{}] Unknown federation message type", session);
                    }
                    _ => {
                        debug!("[fed-{}] Unexpected federation message", session);
                    }
                }
            }
            Ok(Message::Ping(data)) => {
                let _ = write.send(Message::Pong(data)).await;
            }
            Ok(Message::Close(_)) => {
                debug!("[fed-{}] Peer sent close", session);
                break;
            }
            Ok(_) => {}
            Err(e) => {
                warn!("[fed-{}] Connection error: {}", session, e);
                break;
            }
        }
    }

    // Log aggregate only (zero-knowledge: no routing_ids)
    if offload_count > 0 {
        info!(
            "[fed-{}] Accepted {} offloaded blobs from peer",
            session, offload_count
        );
    }

    peer_registry.set_status(&peer_relay_id, PeerStatus::Disconnected);
}
