// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Federation Connection Handler
//!
//! Handles incoming federation WebSocket connections from peer relays.
//! Processes offloaded blobs, capacity reports, and drain notices.
//! Follows privacy-preserving logging rules: never log routing_id, only aggregate
//! counts with random session labels.

use std::sync::Arc;

use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::config::RelayConfig;
use crate::federation_core;
use crate::federation_protocol::{
    self, FEDERATION_PROTOCOL_VERSION, FederationPayload, create_federation_envelope,
    encode_federation_message,
};
use crate::forwarding_hints::ForwardingHintStore;
use crate::metrics::RelayMetrics;
use crate::peer_registry::gossip;
use crate::peer_registry::{PeerInfo, PeerOrigin, PeerRegistry, PeerStatus};
use crate::rate_limit::RateLimiter;
use crate::storage::BlobStore;

/// Helper to send a federation message over WebSocket.
/// Encodes the payload and sends as binary. Errors are silently ignored
/// (fire-and-forget pattern for acks).
async fn send_federation_msg<S>(
    write: &mut SplitSink<WebSocketStream<S>, Message>,
    payload: FederationPayload,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let envelope = create_federation_envelope(payload);
    if let Ok(data) = encode_federation_message(&envelope) {
        let _ = write.send(Message::Binary(data)).await;
    }
}

/// Dependencies for handling a federation connection.
pub struct FederationDeps {
    pub storage: Arc<dyn BlobStore>,
    pub hint_store: Arc<dyn ForwardingHintStore>,
    pub peer_registry: Arc<PeerRegistry>,
    pub config: Arc<RelayConfig>,
    /// Per-peer rate limiter for incoming federation messages.
    /// Prevents a compromised or misbehaving peer from flooding the relay.
    pub federation_rate_limiter: Arc<RateLimiter>,
    pub metrics: RelayMetrics,
}

/// Handles an incoming federation WebSocket connection from a peer relay.
/// Generic over the stream type to support both plain TCP and mTLS connections.
pub async fn handle_federation_connection<S>(ws_stream: WebSocketStream<S>, deps: FederationDeps)
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let FederationDeps {
        storage,
        hint_store: _hint_store,
        peer_registry,
        config,
        federation_rate_limiter,
        metrics,
    } = deps;

    // Random session label for logging (never log routing_id)
    let session = &uuid::Uuid::new_v4().to_string()[..8];

    let (mut write, mut read) = ws_stream.split();

    let peer_timeout = std::time::Duration::from_secs(config.federation.peer_timeout_secs);
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
                            send_federation_msg(
                                &mut write,
                                FederationPayload::PeerHandshakeAck {
                                    relay_id: config.federation.relay_id.clone(),
                                    version: FEDERATION_PROTOCOL_VERSION,
                                    accepted: false,
                                    capacity_used_bytes: 0,
                                    capacity_max_bytes: 0,
                                },
                            )
                            .await;
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
    metrics.federation_peers_connected.inc();

    let used_bytes = storage.storage_size_bytes();
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    peer_registry.register_peer(PeerInfo {
        relay_id: peer_relay_id.clone(),
        url: String::new(), // Acceptor doesn't know the URL
        capacity_used_bytes: used_bytes,
        capacity_max_bytes: config.storage.max_storage_bytes,
        status: PeerStatus::Connected,
        sender: None,
        origin: PeerOrigin::Configured,
        last_seen_secs: now_secs,
    });

    let ack =
        federation_protocol::create_federation_envelope(FederationPayload::PeerHandshakeAck {
            relay_id: config.federation.relay_id.clone(),
            version: FEDERATION_PROTOCOL_VERSION,
            accepted: true,
            capacity_used_bytes: used_bytes,
            capacity_max_bytes: config.storage.max_storage_bytes,
        });
    if let Ok(data) = federation_protocol::encode_federation_message(&ack)
        && write.send(Message::Binary(data)).await.is_err()
    {
        warn!("[fed-{}] Failed to send PeerHandshakeAck", session);
        peer_registry.set_status(&peer_relay_id, PeerStatus::Disconnected);
        return;
    }

    let mut offload_count: usize = 0;

    loop {
        let msg = match timeout(
            std::time::Duration::from_secs(config.federation.peer_timeout_secs * 2),
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
                if !federation_rate_limiter.consume(&peer_relay_id) {
                    warn!("[fed-{}] Federation peer rate limited", session);
                    metrics.federation_rate_limited.inc();
                    continue;
                }

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
                        // Transport-agnostic offload decision (ADR-052):
                        // both this WebSocket arm and the HTTP handler route
                        // through the same `apply_offload` core.
                        let outcome = federation_core::apply_offload(
                            storage.as_ref(),
                            config.storage.max_storage_bytes,
                            config.federation.offload_refuse,
                            blob_id,
                            &blob_routing_id,
                            blob_data,
                            created_at_secs,
                            &integrity_hash,
                            hop_count,
                        );
                        if outcome.accepted {
                            offload_count += 1;
                            metrics.federation_offloads_received.inc();
                        } else {
                            metrics.federation_offloads_rejected.inc();
                        }
                        send_federation_msg(&mut write, outcome.ack).await;
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
                        metrics.federation_drain_notices.inc();
                        info!("[fed-{}] Peer is draining", session);
                        send_federation_msg(&mut write, FederationPayload::DrainAck).await;
                    }
                    FederationPayload::PeerAdvertisement { peers } => {
                        if config.federation.gossip_enabled {
                            let new_count = gossip::process_peer_advertisement(
                                &config.federation.relay_id,
                                &peer_registry,
                                &peers,
                            );
                            debug!(
                                "[fed-{}] Processed gossip: {} advertised, {} new",
                                session,
                                peers.len(),
                                new_count
                            );
                            send_federation_msg(
                                &mut write,
                                FederationPayload::PeerAdvertisementAck {
                                    new_peers_count: new_count,
                                },
                            )
                            .await;
                            // Touch the sender peer so it doesn't expire
                            peer_registry.touch_peer(
                                &peer_relay_id,
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                            );
                        } else {
                            debug!(
                                "[fed-{}] Gossip disabled, ignoring PeerAdvertisement",
                                session
                            );
                        }
                    }
                    FederationPayload::PeerAdvertisementAck { .. } => {
                        debug!("[fed-{}] Received PeerAdvertisementAck", session);
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

    // Log aggregate only (privacy-preserving: no routing_ids)
    if offload_count > 0 {
        info!(
            "[fed-{}] Accepted {} offloaded blobs from peer",
            session, offload_count
        );
    }

    metrics.federation_peers_connected.dec();
    peer_registry.set_status(&peer_relay_id, PeerStatus::Disconnected);
}
