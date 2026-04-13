// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Security tests for relay resource exhaustion mitigations (SP-13₀).
//!
//! Tests cover: R-H4 (blob cleanup GC), R-H5 (take atomicity).
//!
//! R-H2 (recovery query batch limit) and R-H3 (proof_data size limit) were
//! enforced by the now-removed WebSocket handler. HTTP v2 enforces its own
//! limits in http_api.rs.

use std::sync::Arc;
use std::time::Duration;

use vauchi_relay::storage::{BlobStore, SqliteBlobStore, StoredBlob};

// ── R-H4: blob cleanup GC ──

/// R-H4: After blob cleanup, blob_sender_map entries for expired blobs should be pruned.
#[test]
fn test_blob_sender_map_gc_prunes_expired_entries() {
    let storage = SqliteBlobStore::in_memory().unwrap();

    // Store a blob
    let blob = StoredBlob::new(vec![1, 2, 3]);
    let blob_id = blob.id.clone();
    storage.store("recipient1", blob);

    // Verify blob exists
    assert_eq!(storage.blob_count(), 1);

    // Get all blob IDs
    let ids = storage.all_blob_ids();
    assert!(ids.contains(&blob_id));

    // Clean up with zero TTL (expires everything)
    storage.cleanup_expired(Duration::ZERO);

    // After cleanup, all_blob_ids should be empty
    let ids = storage.all_blob_ids();
    assert!(ids.is_empty());
}

/// R-H4: all_blob_ids returns all unique blob IDs across recipients.
#[test]
fn test_all_blob_ids_returns_all_blobs() {
    let storage = SqliteBlobStore::in_memory().unwrap();

    let blob1 = StoredBlob::new(vec![1]);
    let blob2 = StoredBlob::new(vec![2]);
    let id1 = blob1.id.clone();
    let id2 = blob2.id.clone();

    storage.store("alice", blob1);
    storage.store("bob", blob2);

    let ids = storage.all_blob_ids();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&id1));
    assert!(ids.contains(&id2));
}

// ── R-H5: SqliteBlobStore::take() atomicity ──

/// R-H5: take() should select and delete within a single lock acquisition.
/// This test verifies that take() returns blobs and removes them atomically.
#[test]
fn test_blob_take_is_atomic() {
    let storage = SqliteBlobStore::in_memory().unwrap();

    let blob = StoredBlob::new(vec![42, 43, 44]);
    let blob_id = blob.id.clone();
    storage.store("recipient1", blob);

    // take() should return the blob and remove it
    let taken = storage.take("recipient1");
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].id, blob_id);
    assert_eq!(taken[0].data, vec![42, 43, 44]);

    // Subsequent peek should return nothing
    let remaining = storage.peek("recipient1");
    assert!(remaining.is_empty());

    // Blob count should be 0
    assert_eq!(storage.blob_count(), 0);
}

/// R-H5: Concurrent take calls should not return duplicate data.
#[test]
fn test_blob_take_no_duplicates_under_concurrency() {
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());

    // Store multiple blobs
    for i in 0..10 {
        storage.store("shared", StoredBlob::new(vec![i]));
    }

    let storage1 = storage.clone();
    let storage2 = storage.clone();

    let handle1 = std::thread::spawn(move || storage1.take("shared"));
    let handle2 = std::thread::spawn(move || storage2.take("shared"));

    let result1 = handle1.join().unwrap();
    let result2 = handle2.join().unwrap();

    // Total taken should be exactly 10 — no duplicates
    let total = result1.len() + result2.len();
    assert_eq!(
        total,
        10,
        "Expected 10 total blobs, got {} (thread1={}, thread2={})",
        total,
        result1.len(),
        result2.len()
    );

    // Storage should be empty
    assert_eq!(storage.blob_count(), 0);
}
