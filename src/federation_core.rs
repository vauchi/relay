// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Transport-agnostic federation message handling.
//!
//! The offload decision (single-hop guard, integrity verification,
//! unpadding, capacity refusal, store) lives here so both the legacy
//! WebSocket handler and the HTTP handler share one decision path while
//! federation migrates from WebSocket to mTLS-HTTP (ADR-052). Metrics and
//! transport framing stay with the caller; this layer is pure decision +
//! the store side-effect.

use crate::config::RelayConfig;
use crate::federation_protocol::FederationPayload;
use crate::integrity;
use crate::metrics::RelayMetrics;
use crate::padding;
use crate::peer_registry::{PeerRegistry, PeerStatus, gossip};
use crate::storage::{BlobStore, StoredBlob};

/// Outcome of applying an inbound offload blob.
pub struct OffloadOutcome {
    /// The `OffloadAck` payload to return to the peer.
    pub ack: FederationPayload,
    /// Whether the blob was accepted and stored (the caller increments the
    /// received/rejected metric off this).
    pub accepted: bool,
}

/// Applies an inbound federation offload blob.
///
/// Enforces the single-hop limit (an offloaded blob must not be
/// re-offloaded), verifies the integrity hash over the padded bytes as
/// sent, unpads (accepting pre-padding blobs as-is for backward
/// compatibility), refuses at/above the `offload_refuse` usage ratio, and
/// stores with an incremented hop count on acceptance.
#[allow(clippy::too_many_arguments)]
pub fn apply_offload(
    storage: &dyn BlobStore,
    max_storage_bytes: usize,
    offload_refuse: f64,
    blob_id: String,
    routing_id: &str,
    data: Vec<u8>,
    created_at_secs: u64,
    integrity_hash: &str,
    hop_count: u8,
) -> OffloadOutcome {
    let reject = |blob_id: String, reason: &str| OffloadOutcome {
        ack: FederationPayload::OffloadAck {
            blob_id,
            accepted: false,
            reason: Some(reason.to_string()),
        },
        accepted: false,
    };

    if hop_count >= 1 {
        return reject(blob_id, "hop_count too high");
    }
    if !integrity::verify_integrity_hash(&data, integrity_hash) {
        return reject(blob_id, "integrity check failed");
    }
    let unpadded = padding::unpad(&data).unwrap_or(data);

    let usage_ratio = storage.storage_size_bytes() as f64 / max_storage_bytes as f64;
    if usage_ratio >= offload_refuse {
        return reject(blob_id, "at capacity");
    }

    storage.store(
        routing_id,
        StoredBlob::with_metadata(unpadded, created_at_secs, hop_count + 1),
    );
    OffloadOutcome {
        ack: FederationPayload::OffloadAck {
            blob_id,
            accepted: true,
            reason: None,
        },
        accepted: true,
    }
}

/// Result of applying an inbound federation message.
pub struct MessageResult {
    /// Response payload to send back to the peer, if any.
    pub response: Option<FederationPayload>,
    /// True when the message was an offload blob that was accepted and
    /// stored — the transport increments its aggregate counter off this.
    pub offload_stored: bool,
}

/// Applies an inbound federation message: dispatches on the payload
/// variant, performs the registry/storage side-effects and metric
/// increments, and returns the optional response payload.
///
/// Transport-agnostic (ADR-052): `peer_relay_id` is supplied by the
/// caller — the WebSocket handshake today, the mTLS client identity once
/// federation is HTTP. Rate limiting stays at the transport layer.
pub fn apply_message(
    payload: FederationPayload,
    storage: &dyn BlobStore,
    config: &RelayConfig,
    peer_registry: &PeerRegistry,
    metrics: &RelayMetrics,
    peer_relay_id: &str,
) -> MessageResult {
    match payload {
        FederationPayload::OffloadBlob {
            blob_id,
            routing_id,
            data,
            created_at_secs,
            integrity_hash,
            hop_count,
        } => {
            let outcome = apply_offload(
                storage,
                config.storage.max_storage_bytes,
                config.federation.offload_refuse,
                blob_id,
                &routing_id,
                data,
                created_at_secs,
                &integrity_hash,
                hop_count,
            );
            if outcome.accepted {
                metrics.federation_offloads_received.inc();
            } else {
                metrics.federation_offloads_rejected.inc();
            }
            MessageResult {
                response: Some(outcome.ack),
                offload_stored: outcome.accepted,
            }
        }
        FederationPayload::CapacityReport {
            used_bytes,
            max_bytes,
            blob_count: _,
        } => {
            peer_registry.update_capacity(peer_relay_id, used_bytes, max_bytes);
            MessageResult {
                response: None,
                offload_stored: false,
            }
        }
        FederationPayload::DrainNotice {
            drain_timeout_secs: _,
        } => {
            peer_registry.set_status(peer_relay_id, PeerStatus::Draining);
            metrics.federation_drain_notices.inc();
            MessageResult {
                response: Some(FederationPayload::DrainAck),
                offload_stored: false,
            }
        }
        // TODO(PFC): gossip handling reads SystemTime::now() — see 2026-07-06-relay-pfc-violations R16
        FederationPayload::PeerAdvertisement { peers } => {
            if config.federation.gossip_enabled {
                let new_peers_count = gossip::process_peer_advertisement(
                    &config.federation.relay_id,
                    peer_registry,
                    &peers,
                );
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                peer_registry.touch_peer(peer_relay_id, now_secs);
                MessageResult {
                    response: Some(FederationPayload::PeerAdvertisementAck { new_peers_count }),
                    offload_stored: false,
                }
            } else {
                MessageResult {
                    response: None,
                    offload_stored: false,
                }
            }
        }
        _ => MessageResult {
            response: None,
            offload_stored: false,
        },
    }
}
