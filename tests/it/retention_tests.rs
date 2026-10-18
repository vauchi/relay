// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Storage-level evidence for private#691; not a complete client catch-up test.

use std::time::Duration;

use vauchi_relay::federation_core::apply_offload;
use vauchi_relay::storage::{BlobStore, SqliteBlobStore, StoredBlob};
use vauchi_relay::{integrity, padding};

const DAY: u64 = 24 * 60 * 60;
const CREATED: u64 = 1_700_000_000;
const RETENTION: Duration = Duration::from_secs(120 * DAY);

// @scenario: message_delivery:Message stored with TTL
#[test]
fn retention_keeps_day_100_data_across_restart_and_ack_removes_only_that_blob() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("retention.db");
    let stored = StoredBlob::with_metadata(b"opaque-queued-update".to_vec(), CREATED, 0);
    let id = stored.id.clone();
    {
        let store = SqliteBlobStore::open(&path).unwrap();
        store.store("recipient", stored).unwrap();
        store
            .store("other", StoredBlob::with_metadata(vec![2], CREATED, 0))
            .unwrap();
        assert_eq!(store.cleanup_expired_at(RETENTION, CREATED + 100 * DAY), 0);
        assert_eq!(store.peek("recipient")[0].data, b"opaque-queued-update");
        store.shutdown();
    }
    {
        let store = SqliteBlobStore::open(&path).unwrap();
        let pending = store.peek("recipient");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, id);
        assert_eq!(pending[0].created_at_secs, CREATED);
        assert!(store.acknowledge("recipient", &id));
        assert!(!store.acknowledge("recipient", &id));
        assert_eq!(store.peek("recipient").len(), 0);
        assert_eq!(store.peek("other")[0].data, vec![2]);
        store.shutdown();
    }
    let store = SqliteBlobStore::open(&path).unwrap();
    assert_eq!(store.peek("recipient").len(), 0);
    assert_eq!(store.blob_count(), 1);
}

// @scenario: message_delivery:Message expires after TTL
#[test]
fn retention_expires_at_the_exact_boundary_and_preserves_a_later_envelope() {
    for elapsed in [120 * DAY - 1, 120 * DAY, 120 * DAY + 1] {
        let store = SqliteBlobStore::in_memory().unwrap();
        store
            .store("old", StoredBlob::with_metadata(vec![1], CREATED, 0))
            .unwrap();
        store
            .store(
                "later",
                StoredBlob::with_metadata(vec![2], CREATED + DAY, 0),
            )
            .unwrap();
        let expected = usize::from(elapsed >= 120 * DAY);
        assert_eq!(
            store.cleanup_expired_at(RETENTION, CREATED + elapsed),
            expected
        );
        assert_eq!(store.peek("old").len(), 1 - expected);
        assert_eq!(store.peek("later")[0].data, vec![2]);
    }
}

// @internal
#[test]
fn retention_does_not_restart_when_a_peer_accepts_an_old_envelope() {
    let store = SqliteBlobStore::in_memory().unwrap();
    let payload = padding::pad(b"opaque-federated-update");
    let hash = integrity::compute_integrity_hash(&payload);
    let outcome = apply_offload(
        &store,
        1_073_741_824,
        0.95,
        "original-id".into(),
        "recipient",
        payload,
        CREATED,
        &hash,
        0,
    );
    assert!(outcome.accepted);
    let stored = store.peek("recipient");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].data, b"opaque-federated-update");
    assert_eq!(stored[0].created_at_secs, CREATED);
    assert_eq!(stored[0].hop_count, 1);
    assert_eq!(store.cleanup_expired_at(RETENTION, CREATED + 100 * DAY), 0);
    assert_eq!(store.peek("recipient").len(), 1);
    assert_eq!(store.cleanup_expired_at(RETENTION, CREATED + 120 * DAY), 1);
    assert_eq!(store.peek("recipient").len(), 0);
}

// @internal
#[test]
fn retention_handles_a_clock_before_creation_or_before_one_full_ttl() {
    let store = SqliteBlobStore::in_memory().unwrap();
    store
        .store("epoch", StoredBlob::with_metadata(vec![1], 0, 0))
        .unwrap();
    store
        .store("future", StoredBlob::with_metadata(vec![2], CREATED, 0))
        .unwrap();
    assert_eq!(store.cleanup_expired_at(RETENTION, DAY), 0);
    assert_eq!(store.blob_count(), 2);
    assert_eq!(store.cleanup_expired_at(RETENTION, 120 * DAY), 1);
    assert_eq!(store.peek("epoch").len(), 0);
    assert_eq!(store.peek("future")[0].data, vec![2]);
}

proptest::proptest! {
    // @internal
    #[test]
    fn retention_matches_age_for_representable_timestamps(
        now in proptest::prelude::any::<u64>(),
        created in 0u64..=i64::MAX as u64,
        ttl_secs in proptest::prelude::any::<u64>(),
    ) {
        let store = SqliteBlobStore::in_memory().unwrap();
        store.store("recipient", StoredBlob::with_metadata(vec![1], created, 0)).unwrap();
        let expired = now >= created && now - created >= ttl_secs;
        let removed = store.cleanup_expired_at(Duration::from_secs(ttl_secs), now);
        proptest::prop_assert_eq!(removed, usize::from(expired));
        proptest::prop_assert_eq!(store.peek("recipient").len(), usize::from(!expired));
    }
}
