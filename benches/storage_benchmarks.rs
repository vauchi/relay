// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Criterion benchmarks for relay storage and rate limiting hot paths.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::storage::{BlobStore, SqliteBlobStore, StoredBlob};

fn make_blob(size: usize) -> StoredBlob {
    StoredBlob::new(vec![0xAB; size])
}

fn setup_store() -> SqliteBlobStore {
    SqliteBlobStore::in_memory().expect("in-memory SQLite must succeed")
}

fn setup_store_with_blobs(recipient: &str, count: usize) -> SqliteBlobStore {
    let store = setup_store();
    for _ in 0..count {
        store.store(recipient, make_blob(256));
    }
    store
}

fn bench_blob_store(c: &mut Criterion) {
    let mut group = c.benchmark_group("blob_store");

    // Store benchmarks (SQLite INSERT — per-message hot path)
    group.bench_function("store_256B", |b| {
        let store = setup_store();
        b.iter(|| {
            store.store("recipient-bench", make_blob(256));
        });
    });

    group.bench_function("store_4KB", |b| {
        let store = setup_store();
        b.iter(|| {
            store.store("recipient-bench", make_blob(4096));
        });
    });

    // Peek benchmarks (SQLite SELECT — delivery hot path)
    for count in [1, 10, 100] {
        group.bench_with_input(BenchmarkId::new("peek", count), &count, |b, &count| {
            let store = setup_store_with_blobs("recipient-peek", count);
            b.iter(|| {
                store.peek("recipient-peek");
            });
        });
    }

    // Acknowledge benchmark (SQLite DELETE by PK)
    group.bench_function("acknowledge_single", |b| {
        let store = setup_store();
        b.iter_with_setup(
            || {
                let blob = make_blob(256);
                let id = blob.id.clone();
                store.store("recipient-ack", blob);
                id
            },
            |blob_id| {
                store.acknowledge("recipient-ack", &blob_id);
            },
        );
    });

    // Quota check (COUNT(*) — per-message gate)
    group.bench_function("blob_count_for_50", |b| {
        let store = setup_store_with_blobs("recipient-count", 50);
        b.iter(|| {
            store.blob_count_for("recipient-count");
        });
    });

    // Cleanup (periodic TTL — no blobs actually expired)
    group.bench_function("cleanup_expired_100_blobs_none_expired", |b| {
        let store = setup_store_with_blobs("recipient-cleanup", 100);
        let ttl = Duration::from_secs(86400);
        b.iter(|| {
            store.cleanup_expired(ttl);
        });
    });

    // Multi-recipient scale benchmarks
    group.bench_function("peek_in_500_blob_store", |b| {
        let store = setup_store();
        for i in 0..50 {
            for _ in 0..10 {
                store.store(&format!("recipient-{i}"), make_blob(256));
            }
        }
        b.iter(|| {
            store.peek("recipient-25");
        });
    });

    group.bench_function("blob_count_in_500_blob_store", |b| {
        let store = setup_store();
        for i in 0..50 {
            for _ in 0..10 {
                store.store(&format!("recipient-{i}"), make_blob(256));
            }
        }
        b.iter(|| {
            store.blob_count_for("recipient-25");
        });
    });

    group.finish();
}

fn bench_rate_limiter(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiter");

    // First request (new bucket creation + HashMap insert)
    group.bench_function("consume_first_request", |b| {
        let limiter = RateLimiter::new(60);
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            limiter.consume(&format!("client-{counter}"));
        });
    });

    // Warmed client (existing bucket, token refill + consume)
    group.bench_function("consume_warmed_client", |b| {
        let limiter = RateLimiter::new(1000);
        limiter.consume("warmed-client");
        b.iter(|| {
            limiter.consume("warmed-client");
        });
    });

    // Lookup in populated HashMap (100 existing clients)
    group.bench_function("consume_100_clients_existing", |b| {
        let limiter = RateLimiter::new(1000);
        for i in 0..100 {
            limiter.consume(&format!("existing-{i}"));
        }
        b.iter(|| {
            limiter.consume("existing-50");
        });
    });

    // Cleanup (periodic bucket eviction)
    group.bench_function("cleanup_100_clients", |b| {
        b.iter_with_setup(
            || {
                let limiter = RateLimiter::new(60);
                for i in 0..100 {
                    limiter.consume(&format!("cleanup-{i}"));
                }
                limiter
            },
            |limiter| {
                limiter.cleanup_inactive(Duration::from_secs(0));
            },
        );
    });

    group.finish();
}

criterion_group!(benches, bench_blob_store, bench_rate_limiter);
criterion_main!(benches);
