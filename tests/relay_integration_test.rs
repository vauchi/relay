//! Relay Integration Tests
//!
//! Tests the relay server's protocol handling, message routing,
//! and storage operations in an integrated manner.
//!
//! Based on: features/sync_updates.feature

use std::sync::Arc;
use std::time::Duration;
use vauchi_relay::storage::{BlobStore, MemoryBlobStore, StoredBlob};

mod common;

/// Test: Blob storage stores and retrieves correctly
/// Based on: Scenario: Updates are delivered when recipient connects
#[test]
fn test_blob_store_and_retrieve() {
    let store = MemoryBlobStore::new();

    let blob = StoredBlob::new("sender-abc".to_string(), vec![1, 2, 3, 4, 5]);
    let blob_id = blob.id.clone();

    store.store("recipient-xyz", blob);

    let pending = store.peek("recipient-xyz");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, blob_id);
    assert_eq!(pending[0].sender_id, "sender-abc");
    assert_eq!(pending[0].data, vec![1, 2, 3, 4, 5]);
}

/// Test: Multiple blobs for same recipient
/// Based on: Scenario: Offline recipient receives all pending updates
#[test]
fn test_multiple_blobs_for_recipient() {
    let store = MemoryBlobStore::new();

    store.store(
        "recipient-1",
        StoredBlob::new("sender-a".to_string(), vec![1]),
    );
    store.store(
        "recipient-1",
        StoredBlob::new("sender-b".to_string(), vec![2]),
    );
    store.store(
        "recipient-1",
        StoredBlob::new("sender-a".to_string(), vec![3]),
    );

    let pending = store.peek("recipient-1");
    assert_eq!(pending.len(), 3);
}

/// Test: Blobs are separate per recipient
/// Based on: Scenario: Updates are routed to correct recipient
#[test]
fn test_blobs_separate_per_recipient() {
    let store = MemoryBlobStore::new();

    store.store(
        "recipient-1",
        StoredBlob::new("sender".to_string(), vec![1]),
    );
    store.store(
        "recipient-2",
        StoredBlob::new("sender".to_string(), vec![2]),
    );
    store.store(
        "recipient-3",
        StoredBlob::new("sender".to_string(), vec![3]),
    );

    assert_eq!(store.peek("recipient-1").len(), 1);
    assert_eq!(store.peek("recipient-2").len(), 1);
    assert_eq!(store.peek("recipient-3").len(), 1);
    assert_eq!(store.peek("recipient-1")[0].data, vec![1]);
    assert_eq!(store.peek("recipient-2")[0].data, vec![2]);
    assert_eq!(store.peek("recipient-3")[0].data, vec![3]);
}

/// Test: Acknowledgment removes specific blob
/// Based on: Scenario: Client acknowledges receipt
#[test]
fn test_acknowledge_removes_blob() {
    let store = MemoryBlobStore::new();

    let blob1 = StoredBlob::new("sender".to_string(), vec![1]);
    let blob2 = StoredBlob::new("sender".to_string(), vec![2]);
    let blob1_id = blob1.id.clone();

    store.store("recipient", blob1);
    store.store("recipient", blob2);

    assert_eq!(store.blob_count(), 2);

    let ack_result = store.acknowledge("recipient", &blob1_id);
    assert!(
        ack_result,
        "Acknowledge should return true for existing blob"
    );
    assert_eq!(store.blob_count(), 1);

    // Remaining blob should be the second one
    let remaining = store.peek("recipient");
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].data, vec![2]);
}

/// Test: Acknowledge non-existent blob returns false
/// Based on: Scenario: Invalid acknowledgment is ignored
#[test]
fn test_acknowledge_nonexistent_returns_false() {
    let store = MemoryBlobStore::new();

    store.store("recipient", StoredBlob::new("sender".to_string(), vec![1]));

    let result = store.acknowledge("recipient", "nonexistent-id");
    assert!(!result);
    assert_eq!(store.blob_count(), 1);

    let result = store.acknowledge("wrong-recipient", "any-id");
    assert!(!result);
}

/// Test: Take removes all blobs for recipient
/// Based on: Scenario: Recipient retrieves all pending updates
#[test]
fn test_take_removes_all() {
    let store = MemoryBlobStore::new();

    store.store("recipient", StoredBlob::new("sender".to_string(), vec![1]));
    store.store("recipient", StoredBlob::new("sender".to_string(), vec![2]));

    let taken = store.take("recipient");
    assert_eq!(taken.len(), 2);
    assert_eq!(store.blob_count(), 0);

    // Take again returns empty
    let taken_again = store.take("recipient");
    assert!(taken_again.is_empty());
}

/// Test: Cleanup removes expired blobs
/// Based on: Scenario: Stale updates are cleaned up
#[test]
fn test_cleanup_expired() {
    let store = MemoryBlobStore::new();

    store.store("recipient", StoredBlob::new("sender".to_string(), vec![1]));

    // With long TTL, nothing should expire
    let removed = store.cleanup_expired(Duration::from_secs(3600));
    assert_eq!(removed, 0);
    assert_eq!(store.blob_count(), 1);

    // With zero TTL, everything expires immediately
    let removed = store.cleanup_expired(Duration::ZERO);
    assert_eq!(removed, 1);
    assert_eq!(store.blob_count(), 0);
}

/// Test: Storage metrics are accurate
/// Based on: Scenario: Relay reports storage metrics
#[test]
fn test_storage_metrics() {
    let store = MemoryBlobStore::new();

    assert_eq!(store.blob_count(), 0);
    assert_eq!(store.recipient_count(), 0);

    store.store(
        "recipient-1",
        StoredBlob::new("sender".to_string(), vec![1, 2, 3]),
    );
    store.store(
        "recipient-1",
        StoredBlob::new("sender".to_string(), vec![4, 5]),
    );
    store.store(
        "recipient-2",
        StoredBlob::new("sender".to_string(), vec![6]),
    );

    assert_eq!(store.blob_count(), 3);
    assert_eq!(store.recipient_count(), 2);

    // Storage size should be > 0
    let size = store.storage_size_bytes();
    assert!(size > 0, "Storage size should be non-zero");
}

/// Test: Thread-safe concurrent access
/// Based on: Scenario: Multiple clients connect simultaneously
#[test]
fn test_concurrent_access() {
    use std::thread;

    let store = Arc::new(MemoryBlobStore::new());

    let mut handles = vec![];

    // Spawn multiple writer threads
    for i in 0..10 {
        let store = Arc::clone(&store);
        handles.push(thread::spawn(move || {
            for j in 0..100 {
                store.store(
                    &format!("recipient-{}", i),
                    StoredBlob::new("sender".to_string(), vec![j as u8]),
                );
            }
        }));
    }

    // Wait for all writers
    for handle in handles {
        handle.join().unwrap();
    }

    // Each recipient should have 100 blobs
    assert_eq!(store.blob_count(), 1000);
    assert_eq!(store.recipient_count(), 10);

    for i in 0..10 {
        let pending = store.peek(&format!("recipient-{}", i));
        assert_eq!(pending.len(), 100);
    }
}

/// Test: Peek doesn't modify storage
/// Based on: Scenario: Peeking doesn't consume updates
#[test]
fn test_peek_idempotent() {
    let store = MemoryBlobStore::new();

    store.store(
        "recipient",
        StoredBlob::new("sender".to_string(), vec![1, 2, 3]),
    );

    // Multiple peeks should return the same data
    for _ in 0..5 {
        let pending = store.peek("recipient");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].data, vec![1, 2, 3]);
    }

    // Blob should still be there
    assert_eq!(store.blob_count(), 1);
}

/// Test: Empty recipient returns empty vec
#[test]
fn test_empty_recipient() {
    let store = MemoryBlobStore::new();

    let pending = store.peek("nonexistent");
    assert!(pending.is_empty());

    let taken = store.take("nonexistent");
    assert!(taken.is_empty());
}
