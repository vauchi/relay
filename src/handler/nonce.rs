// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Nonce tracking for replay prevention.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Nonces expire after 120 seconds (2× the ±60s timestamp window).
pub(super) const NONCE_TTL: Duration = Duration::from_secs(120);
/// R-C3: Default maximum nonce entries to prevent memory exhaustion.
const DEFAULT_NONCE_CAPACITY: usize = 200_000;

/// Cleanup interval: only run `retain` every N insertions to amortize cost.
const CLEANUP_INTERVAL: usize = 1000;

/// Tracks recently seen nonces to prevent replay attacks.
///
/// Uses a HashMap for O(1) membership checks instead of O(n) linear scan.
/// Nonces older than `TTL` are evicted every `CLEANUP_INTERVAL` insertions
/// (OHTTP-10: amortized O(n/1000) instead of O(n) per call). Shared via
/// `Arc` across all connections handled by a single relay instance.
pub struct NonceTracker {
    nonces: Mutex<HashMap<Vec<u8>, Instant>>,
    /// R-C3: Maximum number of nonces to track before rejecting new ones.
    max_capacity: usize,
    /// Counter for amortized cleanup (OHTTP-10).
    ops_since_cleanup: Mutex<usize>,
}

impl Default for NonceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceTracker {
    /// Creates a new empty nonce tracker with the default capacity (200,000).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_NONCE_CAPACITY)
    }

    /// Creates a new empty nonce tracker with a custom capacity limit.
    pub fn with_capacity(max_capacity: usize) -> Self {
        NonceTracker {
            nonces: Mutex::new(HashMap::new()),
            max_capacity,
            ops_since_cleanup: Mutex::new(0),
        }
    }

    /// Returns the configured capacity limit.
    pub fn capacity(&self) -> usize {
        self.max_capacity
    }

    /// Checks if a nonce has been seen before. If not, inserts it and returns `true`.
    /// Returns `false` if the nonce is a replay or if the tracker is at capacity.
    ///
    /// OHTTP-10: Eviction runs every `CLEANUP_INTERVAL` insertions instead of
    /// on every call, amortizing the O(n) retain cost.
    pub fn check_and_insert(&self, nonce: &[u8]) -> bool {
        let mut nonces = self.nonces.lock();

        // Check for replay first (O(1) lookup) — always checked
        if nonces.contains_key(nonce) {
            return false;
        }

        // OHTTP-10: Amortized eviction — only run retain every N ops
        let mut ops = self.ops_since_cleanup.lock();
        *ops += 1;
        if *ops >= CLEANUP_INTERVAL {
            let cutoff = Instant::now() - NONCE_TTL;
            nonces.retain(|_, ts| *ts > cutoff);
            *ops = 0;
        }

        // R-C3: Reject if at capacity after potential cleanup
        if nonces.len() >= self.max_capacity {
            return false;
        }

        // Insert new nonce (O(1) amortized)
        nonces.insert(nonce.to_vec(), Instant::now());
        true
    }

    /// Evicts all entries. Intended for testing; in production entries expire via TTL.
    pub fn evict_all(&self) {
        self.nonces.lock().clear();
    }
}
