// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Periodic housekeeping (`vauchi_relay::maintenance`): each sweep once,
//! the repeating loop and the shutdown drain under tokio's paused clock.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vauchi_relay::connection_limit::ConnectionLimiter;
use vauchi_relay::forwarding_hints::{
    ForwardingHint, ForwardingHintStore, SqliteForwardingHintStore,
};
use vauchi_relay::maintenance;
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::recovery_storage::{
    RecoveryProofStore, SqliteRecoveryProofStore, StoredRecoveryProof,
};
use vauchi_relay::storage::{BlobStore, SqliteBlobStore, StoredBlob};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The value line of one metric in the encoded text, e.g. `"name 3"`.
fn metric_line(metrics: &RelayMetrics, name: &str) -> String {
    metrics
        .encode()
        .lines()
        .find(|line| line.starts_with(&format!("{name} ")))
        .unwrap_or_else(|| panic!("metric {name} not encoded"))
        .to_string()
}

// @internal
#[test]
fn sweep_blobs_removes_expired_blobs_and_counts_them() {
    let storage = SqliteBlobStore::in_memory().unwrap();
    let two_hours_ago = unix_now() - 7200;
    storage.store(
        "recipient",
        StoredBlob::with_metadata(vec![1], two_hours_ago, 0),
    );
    storage.store("recipient", StoredBlob::new(vec![2]));
    let metrics = RelayMetrics::new();

    let removed = maintenance::sweep_blobs(&storage, Duration::from_secs(3600), &metrics);

    assert_eq!(removed, 1);
    assert_eq!(storage.peek("recipient").len(), 1);
    assert_eq!(
        metric_line(&metrics, "relay_blobs_expired_total"),
        "relay_blobs_expired_total 1"
    );
}

// @internal
#[test]
fn sweep_forwarding_hints_moves_expired_hints_from_active_to_expired() {
    let store = SqliteForwardingHintStore::in_memory().unwrap();
    for (route, expires_at_secs) in [("expired", 1), ("live", 9_999_999_999)] {
        store.store_hint(ForwardingHint {
            routing_id: route.to_string(),
            blob_id: format!("blob-of-{route}"),
            target_relay: "https://peer-a:8080".to_string(),
            created_at_secs: 0,
            expires_at_secs,
        });
    }
    let metrics = RelayMetrics::new();
    metrics.federation_hints_active.set(2);

    let removed = maintenance::sweep_forwarding_hints(&store, &metrics);

    assert_eq!(removed, 1);
    assert_eq!(store.get_hints("live").len(), 1);
    assert_eq!(
        metric_line(&metrics, "relay_federation_hints_expired_total"),
        "relay_federation_hints_expired_total 1"
    );
    assert_eq!(
        metric_line(&metrics, "relay_federation_hints_active"),
        "relay_federation_hints_active 1"
    );
}

// @internal
#[test]
fn sweep_recovery_proofs_takes_expired_proofs_off_the_active_gauge() {
    let store = SqliteRecoveryProofStore::in_memory().unwrap();
    store.store(StoredRecoveryProof {
        expires_at_secs: unix_now() - 100,
        ..StoredRecoveryProof::new([1; 32], vec![1, 2, 3])
    });
    store.store(StoredRecoveryProof::new([2; 32], vec![1, 2, 3]));
    let metrics = RelayMetrics::new();
    metrics.recovery_proofs_active.set(2);

    let removed = maintenance::sweep_recovery_proofs(&store, &metrics);

    assert_eq!(removed, 1);
    assert!(store.get(&[2; 32]).is_some());
    assert_eq!(
        metric_line(&metrics, "relay_recovery_proofs_active"),
        "relay_recovery_proofs_active 1"
    );
}

// @internal
#[test]
fn sweep_rate_limiters_totals_the_idle_buckets_of_every_limiter() {
    let one_client = RateLimiter::new(10);
    one_client.consume("a");
    let two_clients = RateLimiter::new(10);
    two_clients.consume("a");
    two_clients.consume("b");
    let limiters = [&one_client, &two_clients];

    let kept_while_recent = maintenance::sweep_rate_limiters(&limiters, Duration::from_secs(3600));
    let removed_once_idle = maintenance::sweep_rate_limiters(&limiters, Duration::ZERO);

    assert_eq!(kept_while_recent, 0);
    assert_eq!(removed_once_idle, 3);
    assert_eq!(one_client.client_count() + two_clients.client_count(), 0);
}

// @internal
#[tokio::test(start_paused = true)]
async fn run_every_ticks_once_per_interval_starting_after_the_first() {
    let ticks = Arc::new(AtomicUsize::new(0));
    let counter = ticks.clone();
    let task = tokio::spawn(maintenance::run_every(Duration::from_secs(60), move || {
        counter.fetch_add(1, Ordering::SeqCst);
    }));

    tokio::time::sleep(Duration::from_secs(30)).await;
    let before_first_interval = ticks.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(120)).await;
    task.abort();

    assert_eq!(before_first_interval, 0);
    assert_eq!(ticks.load(Ordering::SeqCst), 2);
}

// @internal
#[tokio::test(start_paused = true)]
async fn drain_returns_at_once_when_nothing_is_connected() {
    let limiter = ConnectionLimiter::new(10);
    let start = tokio::time::Instant::now();

    let still_open = maintenance::drain_connections(&limiter, Duration::from_secs(30)).await;

    assert_eq!(still_open, 0);
    assert_eq!(start.elapsed(), Duration::ZERO);
}

// @internal
#[tokio::test(start_paused = true)]
async fn drain_gives_up_at_the_timeout_and_reports_what_is_still_open() {
    let limiter = ConnectionLimiter::new(10);
    let _held_for_the_whole_test = limiter.try_acquire().unwrap();
    let start = tokio::time::Instant::now();

    let still_open = maintenance::drain_connections(&limiter, Duration::from_secs(30)).await;

    assert_eq!(still_open, 1);
    assert_eq!(start.elapsed(), Duration::from_secs(30));
}

// @internal
#[tokio::test(start_paused = true)]
async fn drain_finishes_early_once_the_last_connection_closes() {
    let limiter = ConnectionLimiter::new(10);
    let connection = limiter.try_acquire().unwrap();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        drop(connection);
    });
    let start = tokio::time::Instant::now();

    let still_open = maintenance::drain_connections(&limiter, Duration::from_secs(30)).await;

    assert_eq!(still_open, 0);
    assert!(
        start.elapsed() <= Duration::from_secs(2),
        "drain took {:?}",
        start.elapsed()
    );
}
