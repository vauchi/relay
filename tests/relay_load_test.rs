//! Relay Load Tests
//!
//! Performance and stress tests for the relay server.
//! Tests throughput, concurrency, and resource limits.
//!
//! Based on: Non-functional requirements for relay scalability

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::storage::{BlobStore, MemoryBlobStore, StoredBlob};

mod common;

/// Test: High throughput blob storage
/// Measures storage performance under load
#[test]
fn test_high_throughput_storage() {
    let store = MemoryBlobStore::new();
    let num_operations = 10_000;

    let start = Instant::now();

    for i in 0..num_operations {
        store.store(
            &format!("recipient-{}", i % 100),
            StoredBlob::new("sender".to_string(), vec![i as u8; 256]),
        );
    }

    let elapsed = start.elapsed();

    assert_eq!(store.blob_count(), num_operations);

    // Should complete in reasonable time (less than 5 seconds)
    assert!(
        elapsed < Duration::from_secs(5),
        "Storage took too long: {:?}",
        elapsed
    );

    println!(
        "Stored {} blobs in {:?} ({:.0} ops/sec)",
        num_operations,
        elapsed,
        num_operations as f64 / elapsed.as_secs_f64()
    );
}

/// Test: Concurrent writers don't block readers
/// Verifies read/write concurrency
#[test]
fn test_concurrent_read_write() {
    let store = Arc::new(MemoryBlobStore::new());
    let num_writers = 5;
    let num_readers = 5;
    let ops_per_thread = 1000;

    let mut handles = vec![];

    // Spawn writers
    for w in 0..num_writers {
        let store = Arc::clone(&store);
        handles.push(thread::spawn(move || {
            for i in 0..ops_per_thread {
                store.store(
                    &format!("recipient-{}", w),
                    StoredBlob::new("sender".to_string(), vec![i as u8]),
                );
                // Small yield to increase interleaving
                if i % 100 == 0 {
                    thread::yield_now();
                }
            }
        }));
    }

    // Spawn readers
    for r in 0..num_readers {
        let store = Arc::clone(&store);
        handles.push(thread::spawn(move || {
            for i in 0..ops_per_thread {
                let _ = store.peek(&format!("recipient-{}", r % num_writers));
                if i % 100 == 0 {
                    thread::yield_now();
                }
            }
        }));
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    // All writes should have succeeded
    assert_eq!(store.blob_count(), (num_writers * ops_per_thread) as usize);
}

/// Test: Rate limiter performance under load
/// Verifies rate limiter doesn't become a bottleneck
#[test]
fn test_rate_limiter_performance() {
    let limiter = RateLimiter::new(1000);
    let num_clients = 100;
    let checks_per_client = 100;

    let start = Instant::now();

    for c in 0..num_clients {
        let client_id = format!("client-{}", c);
        for _ in 0..checks_per_client {
            let _ = limiter.consume(&client_id);
        }
    }

    let elapsed = start.elapsed();

    // Should complete quickly (< 1 second for 10k checks)
    assert!(
        elapsed < Duration::from_secs(1),
        "Rate limiter too slow: {:?}",
        elapsed
    );

    println!(
        "Processed {} rate checks in {:?}",
        num_clients * checks_per_client,
        elapsed
    );
}

/// Test: Memory usage stays bounded
/// Verifies cleanup prevents unbounded growth
#[test]
fn test_memory_bounded_with_cleanup() {
    let store = MemoryBlobStore::new();

    // Store many blobs
    for i in 0..1000 {
        store.store(
            &format!("recipient-{}", i),
            StoredBlob::new("sender".to_string(), vec![0u8; 1024]),
        );
    }

    let size_before = store.storage_size_bytes();
    assert!(size_before > 0);

    // Cleanup with zero TTL should remove everything
    let removed = store.cleanup_expired(Duration::ZERO);
    assert_eq!(removed, 1000);

    let size_after = store.storage_size_bytes();
    assert_eq!(size_after, 0);
}

/// Test: Large blob handling
/// Verifies system handles large payloads
#[test]
fn test_large_blob_handling() {
    let store = MemoryBlobStore::new();

    // 1MB blob
    let large_data = vec![0u8; 1024 * 1024];

    store.store(
        "recipient",
        StoredBlob::new("sender".to_string(), large_data.clone()),
    );

    let retrieved = store.peek("recipient");
    assert_eq!(retrieved.len(), 1);
    assert_eq!(retrieved[0].data.len(), 1024 * 1024);
    assert_eq!(retrieved[0].data, large_data);
}

/// Test: Many recipients scalability
/// Verifies performance with many distinct recipients
#[test]
fn test_many_recipients() {
    let store = MemoryBlobStore::new();
    let num_recipients = 10_000;

    let start = Instant::now();

    for i in 0..num_recipients {
        store.store(
            &format!("recipient-{:05}", i),
            StoredBlob::new("sender".to_string(), vec![i as u8]),
        );
    }

    let store_elapsed = start.elapsed();

    // Verify all stored
    assert_eq!(store.blob_count(), num_recipients);
    assert_eq!(store.recipient_count(), num_recipients);

    // Test random access
    let access_start = Instant::now();
    for i in (0..num_recipients).step_by(100) {
        let pending = store.peek(&format!("recipient-{:05}", i));
        assert_eq!(pending.len(), 1);
    }
    let access_elapsed = access_start.elapsed();

    println!(
        "Stored {} recipients in {:?}, accessed 100 in {:?}",
        num_recipients, store_elapsed, access_elapsed
    );

    // Should be fast
    assert!(store_elapsed < Duration::from_secs(5));
    assert!(access_elapsed < Duration::from_millis(500));
}

/// Test: Rate limiter cleanup under load
/// Verifies inactive bucket cleanup works correctly
#[test]
fn test_rate_limiter_cleanup() {
    let limiter = RateLimiter::new(100);

    // Create many client buckets
    for i in 0..1000 {
        limiter.consume(&format!("client-{}", i));
    }

    assert_eq!(limiter.client_count(), 1000);

    // Wait a bit, then access some clients to keep them active
    thread::sleep(Duration::from_millis(20));

    for i in 0..10 {
        limiter.consume(&format!("client-{}", i));
    }

    // Cleanup with short idle time
    let removed = limiter.cleanup_inactive(Duration::from_millis(10));

    // Most clients should be removed (990 of them)
    assert!(
        removed >= 900,
        "Expected most clients removed, got {} removed",
        removed
    );
    assert!(limiter.client_count() <= 100);
}

/// Test: Concurrent acknowledgments
/// Verifies acknowledgments work correctly under concurrency
#[test]
fn test_concurrent_acknowledgments() {
    let store = Arc::new(MemoryBlobStore::new());

    // Store blobs with known IDs
    let mut blob_ids = vec![];
    for i in 0..100 {
        let blob = StoredBlob::new("sender".to_string(), vec![i as u8]);
        blob_ids.push(blob.id.clone());
        store.store("recipient", blob);
    }

    assert_eq!(store.blob_count(), 100);

    // Acknowledge from multiple threads
    let mut handles = vec![];
    for chunk in blob_ids.chunks(10) {
        let store = Arc::clone(&store);
        let ids: Vec<String> = chunk.to_vec();
        handles.push(thread::spawn(move || {
            for id in ids {
                store.acknowledge("recipient", &id);
            }
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // All blobs should be acknowledged
    assert_eq!(store.blob_count(), 0);
}

/// Test: Storage under memory pressure
/// Verifies storage remains stable with many small blobs
#[test]
fn test_storage_memory_pressure() {
    let store = MemoryBlobStore::new();

    // Store many small blobs across many recipients
    for r in 0..100 {
        for b in 0..100 {
            store.store(
                &format!("recipient-{}", r),
                StoredBlob::new(format!("sender-{}", b), vec![r as u8, b as u8]),
            );
        }
    }

    assert_eq!(store.blob_count(), 10_000);
    assert_eq!(store.recipient_count(), 100);

    // Take all blobs for half the recipients
    for r in 0..50 {
        let taken = store.take(&format!("recipient-{}", r));
        assert_eq!(taken.len(), 100);
    }

    assert_eq!(store.blob_count(), 5_000);
    assert_eq!(store.recipient_count(), 50);
}
