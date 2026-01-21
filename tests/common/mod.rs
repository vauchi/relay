//! Common test utilities for relay integration tests.

use std::sync::Arc;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::storage::{BlobStore, MemoryBlobStore, StoredBlob};

/// Creates a test blob store with sample data.
#[allow(dead_code)]
pub fn create_test_store_with_data(
    num_recipients: usize,
    blobs_per_recipient: usize,
) -> Arc<MemoryBlobStore> {
    let store = Arc::new(MemoryBlobStore::new());

    for r in 0..num_recipients {
        for b in 0..blobs_per_recipient {
            store.store(
                &format!("recipient-{}", r),
                StoredBlob::new(format!("sender-{}", b % 10), vec![r as u8, b as u8]),
            );
        }
    }

    store
}

/// Creates a rate limiter for testing.
#[allow(dead_code)]
pub fn create_test_rate_limiter(max_per_minute: u32) -> Arc<RateLimiter> {
    Arc::new(RateLimiter::new(max_per_minute))
}

/// Generates a valid 64-character hex client ID.
#[allow(dead_code)]
pub fn generate_test_client_id(seed: u8) -> String {
    let bytes: Vec<u8> = (0..32).map(|i| seed.wrapping_add(i)).collect();
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Generates test ciphertext data of specified size.
#[allow(dead_code)]
pub fn generate_test_ciphertext(size: usize, seed: u8) -> Vec<u8> {
    (0..size).map(|i| seed.wrapping_add(i as u8)).collect()
}
