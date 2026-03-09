// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Delivery jitter for traffic analysis resistance.
//!
//! Adds configurable random delays before forwarding blobs to prevent
//! timing-based correlation between sender updates and recipient deliveries.

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use std::time::Duration;

/// Minimum jitter delay in milliseconds.
pub const DEFAULT_JITTER_MIN_MS: u64 = 50;

/// Maximum jitter delay in milliseconds.
pub const DEFAULT_JITTER_MAX_MS: u64 = 500;

/// Generates a random jitter duration between `min_ms` and `max_ms` (inclusive).
///
/// Uses `aws_lc_rs::rand::SystemRandom` for cryptographically secure randomness.
/// If `min_ms >= max_ms`, returns `min_ms` (graceful handling of invalid config).
pub fn generate_jitter(min_ms: u64, max_ms: u64) -> Duration {
    if min_ms >= max_ms {
        return Duration::from_millis(min_ms);
    }

    let rng = SystemRandom::new();
    let range = max_ms - min_ms + 1; // +1 for inclusive upper bound

    let mut buf = [0u8; 8];
    rng.fill(&mut buf)
        .expect("SystemRandom::fill failed — OS RNG unavailable");

    let random_value = u64::from_le_bytes(buf);
    let offset = random_value % range;

    Duration::from_millis(min_ms + offset)
}

// INLINE_TEST_REQUIRED: Tests verify generate_jitter internals (bounds, variation) that are not exported
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_jitter_within_bounds() {
        // Jitter duration must always be between min and max (inclusive)
        let min_ms = 50;
        let max_ms = 500;
        for _ in 0..100 {
            let jitter = generate_jitter(min_ms, max_ms);
            let ms = jitter.as_millis() as u64;
            assert!(
                ms >= min_ms && ms <= max_ms,
                "Jitter {ms}ms out of bounds [{min_ms}, {max_ms}]"
            );
        }
    }

    #[test]
    fn test_generate_jitter_zero_range() {
        // When min == max, must return exactly that value
        let exact_ms = 200;
        let jitter = generate_jitter(exact_ms, exact_ms);
        assert_eq!(
            jitter.as_millis() as u64,
            exact_ms,
            "Zero-range jitter must return exact value"
        );
    }

    #[test]
    fn test_generate_jitter_varies() {
        // Multiple calls should produce different values (probabilistic).
        // With range 50-500 and 100 samples, seeing only one unique value
        // has probability ~(1/451)^99, effectively zero.
        let min_ms = 50;
        let max_ms = 500;
        let values: Vec<u64> = (0..100)
            .map(|_| generate_jitter(min_ms, max_ms).as_millis() as u64)
            .collect();
        let unique_count = {
            let mut sorted = values.clone();
            sorted.sort_unstable();
            sorted.dedup();
            sorted.len()
        };
        assert!(
            unique_count > 1,
            "Expected variation in jitter values, but got {unique_count} unique value(s) out of 100"
        );
    }

    #[test]
    fn test_generate_jitter_min_greater_than_max_returns_min() {
        // Graceful handling: when min > max, return min
        let min_ms = 500;
        let max_ms = 50;
        let jitter = generate_jitter(min_ms, max_ms);
        assert_eq!(
            jitter.as_millis() as u64,
            min_ms,
            "When min > max, must return min"
        );
    }
}
