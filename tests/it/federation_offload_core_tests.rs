// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the transport-agnostic federation offload decision
//! (`federation_core::apply_offload`). This is the shared decision path
//! both the WebSocket handler and the HTTP handler route through during
//! the WS→mTLS-HTTP migration (ADR-052), so it is tested independently of
//! either transport.

use vauchi_relay::federation_core::{OffloadOutcome, apply_offload};
use vauchi_relay::federation_protocol::FederationPayload;
use vauchi_relay::storage::{BlobStore, SqliteBlobStore};
use vauchi_relay::{integrity, padding};

const MAX_BYTES: usize = 1_073_741_824; // 1 GiB
const REFUSE: f64 = 0.95;

fn unwrap_ack(outcome: &OffloadOutcome) -> (&str, bool, Option<&str>) {
    match &outcome.ack {
        FederationPayload::OffloadAck {
            blob_id,
            accepted,
            reason,
        } => (blob_id.as_str(), *accepted, reason.as_deref()),
        other => panic!("expected OffloadAck, got {other:?}"),
    }
}

// @internal
#[test]
fn apply_offload_accepts_valid_blob_and_stores_it_unpadded() {
    let store = SqliteBlobStore::in_memory().expect("in-memory store");
    let payload = b"federation-offload-payload";
    let padded = padding::pad(payload);
    let hash = integrity::compute_integrity_hash(&padded);

    let outcome = apply_offload(
        &store,
        MAX_BYTES,
        REFUSE,
        "blob-1".to_string(),
        "routing-abc",
        padded,
        1_700_000_000,
        &hash,
        0,
    );

    assert!(outcome.accepted, "valid single-hop blob must be accepted");
    assert_eq!(unwrap_ack(&outcome), ("blob-1", true, None));

    let stored = store.take("routing-abc");
    assert_eq!(stored.len(), 1, "blob must be stored at its routing id");
    assert_eq!(
        stored[0].data, payload,
        "stored blob must be the unpadded payload"
    );
    assert_eq!(stored[0].hop_count, 1, "hop count must increment to 1");
}

// @internal
#[test]
fn apply_offload_rejects_already_hopped_blob() {
    let store = SqliteBlobStore::in_memory().expect("in-memory store");
    let padded = padding::pad(b"x");
    let hash = integrity::compute_integrity_hash(&padded);

    let outcome = apply_offload(
        &store,
        MAX_BYTES,
        REFUSE,
        "blob-2".to_string(),
        "routing-def",
        padded,
        1_700_000_000,
        &hash,
        1, // already offloaded once
    );

    assert!(!outcome.accepted);
    assert_eq!(
        unwrap_ack(&outcome),
        ("blob-2", false, Some("hop_count too high"))
    );
    assert_eq!(
        store.take("routing-def").len(),
        0,
        "rejected blob not stored"
    );
}

// @internal
#[test]
fn apply_offload_rejects_integrity_mismatch() {
    let store = SqliteBlobStore::in_memory().expect("in-memory store");
    let padded = padding::pad(b"tampered");
    let wrong_hash = "00".repeat(32);

    let outcome = apply_offload(
        &store,
        MAX_BYTES,
        REFUSE,
        "blob-3".to_string(),
        "routing-ghi",
        padded,
        1_700_000_000,
        &wrong_hash,
        0,
    );

    assert!(!outcome.accepted);
    assert_eq!(
        unwrap_ack(&outcome),
        ("blob-3", false, Some("integrity check failed"))
    );
    assert_eq!(
        store.take("routing-ghi").len(),
        0,
        "rejected blob not stored"
    );
}

// @internal
#[test]
fn apply_offload_rejects_at_capacity() {
    let store = SqliteBlobStore::in_memory().expect("in-memory store");
    let padded = padding::pad(b"y");
    let hash = integrity::compute_integrity_hash(&padded);

    // refuse ratio 0.0 means any usage (including empty) is "at capacity".
    let outcome = apply_offload(
        &store,
        MAX_BYTES,
        0.0,
        "blob-4".to_string(),
        "routing-jkl",
        padded,
        1_700_000_000,
        &hash,
        0,
    );

    assert!(!outcome.accepted);
    assert_eq!(unwrap_ack(&outcome), ("blob-4", false, Some("at capacity")));
    assert_eq!(
        store.take("routing-jkl").len(),
        0,
        "rejected blob not stored"
    );
}
