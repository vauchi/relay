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

use crate::federation_protocol::FederationPayload;
use crate::integrity;
use crate::padding;
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
