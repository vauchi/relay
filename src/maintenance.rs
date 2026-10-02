// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Periodic housekeeping: what each sweep does once, the loop that repeats
//! it, and the connection drain at shutdown.
//!
//! `main` only wires these together. Each sweep returns what it removed,
//! so its effect on storage and metrics is testable without waiting for
//! an interval (relay-pfc-violations R1).

use std::time::Duration;

use tracing::{info, warn};

use crate::connection_limit::ConnectionLimiter;
use crate::forwarding_hints::ForwardingHintStore;
use crate::metrics::RelayMetrics;
use crate::rate_limit::RateLimiter;
use crate::recovery_storage::RecoveryProofStore;
use crate::storage::BlobStore;

/// Escrow gates are swept every minute.
pub const ESCROW_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// Recovery proofs are swept every hour.
pub const RECOVERY_SWEEP_INTERVAL: Duration = Duration::from_secs(3600);
/// Guardian sets expire yearly, so every six hours is ample.
pub const GUARDIAN_SWEEP_INTERVAL: Duration = Duration::from_secs(21_600);
/// Rate-limiter buckets are swept every ten minutes…
pub const RATE_LIMITER_SWEEP_INTERVAL: Duration = Duration::from_secs(600);
/// …and dropped once idle for half an hour.
pub const RATE_LIMITER_MAX_IDLE: Duration = Duration::from_secs(1800);
/// How long shutdown waits for open connections to finish.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

const DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Calls `tick` once per `interval`, forever; the first call comes after
/// one full interval.
pub async fn run_every(interval: Duration, mut tick: impl FnMut()) {
    loop {
        tokio::time::sleep(interval).await;
        tick();
    }
}

/// Logs a sweep that removed something; a sweep that found nothing is silent.
pub fn log_removed(what: &str, removed: usize) {
    if removed > 0 {
        info!("Cleaned up {} {}", removed, what);
    }
}

/// Removes expired blobs and counts them in `relay_blobs_expired_total`.
pub fn sweep_blobs(storage: &dyn BlobStore, ttl: Duration, metrics: &RelayMetrics) -> usize {
    let removed = storage.cleanup_expired(ttl);
    metrics.blobs_expired.inc_by(removed as u64);
    removed
}

/// Removes expired forwarding hints, counting them as expired and no
/// longer active.
///
/// The active gauge may transiently go negative: the `inc()` on offload
/// and the `sub()` here are not atomic with each other. Cosmetic only.
pub fn sweep_forwarding_hints(store: &dyn ForwardingHintStore, metrics: &RelayMetrics) -> usize {
    let removed = store.cleanup_expired();
    metrics
        .federation_hints_expired
        .inc_by(removed.try_into().unwrap_or(u64::MAX));
    metrics
        .federation_hints_active
        .sub(removed.try_into().unwrap_or(i64::MAX));
    removed
}

/// Removes expired recovery proofs and takes them off the active gauge.
pub fn sweep_recovery_proofs(store: &dyn RecoveryProofStore, metrics: &RelayMetrics) -> usize {
    let removed = store.cleanup_expired();
    metrics.recovery_proofs_active.sub(removed as i64);
    removed
}

/// Drops the buckets idle for `max_idle` from every limiter; returns how
/// many went in total.
pub fn sweep_rate_limiters(limiters: &[&RateLimiter], max_idle: Duration) -> usize {
    limiters
        .iter()
        .map(|limiter| limiter.cleanup_inactive(max_idle))
        .sum()
}

/// Waits for open connections to finish, up to `timeout`; returns how many
/// were still open when it gave up (0 when all finished).
pub async fn drain_connections(limiter: &ConnectionLimiter, timeout: Duration) -> usize {
    let active = limiter.active_count();
    if active == 0 {
        return 0;
    }
    info!(
        "Draining {} active connections ({}s timeout)...",
        active,
        timeout.as_secs()
    );
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    loop {
        let current = limiter.active_count();
        if current == 0 {
            info!("All connections drained");
            return 0;
        }
        tokio::select! {
            _ = &mut deadline => {
                warn!("{} connections still active after drain timeout", current);
                return current;
            }
            _ = tokio::time::sleep(DRAIN_POLL_INTERVAL) => {}
        }
    }
}
