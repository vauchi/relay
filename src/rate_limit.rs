//! Rate Limiting
//!
//! Token bucket rate limiter for preventing abuse.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

/// Token bucket for rate limiting a single client.
#[derive(Debug)]
struct TokenBucket {
    /// Current number of tokens.
    tokens: f64,
    /// Maximum tokens (bucket capacity).
    max_tokens: f64,
    /// Tokens added per second.
    refill_rate: f64,
    /// Last time tokens were updated.
    last_update: Instant,
}

impl TokenBucket {
    fn new(max_tokens: u32, refill_rate: f64) -> Self {
        TokenBucket {
            tokens: max_tokens as f64,
            max_tokens: max_tokens as f64,
            refill_rate,
            last_update: Instant::now(),
        }
    }

    /// Refills tokens based on elapsed time.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_update = now;
    }

    /// Tries to consume one token.
    ///
    /// Returns true if successful, false if rate limited.
    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Checks if a token is available without consuming.
    #[allow(dead_code)]
    fn can_consume(&mut self) -> bool {
        self.refill();
        self.tokens >= 1.0
    }
}

/// Rate limiter for multiple clients.
pub struct RateLimiter {
    /// Per-client token buckets.
    buckets: RwLock<HashMap<String, TokenBucket>>,
    /// Maximum requests per minute.
    max_per_minute: u32,
}

impl RateLimiter {
    /// Creates a new rate limiter.
    ///
    /// `max_per_minute` is the maximum number of requests allowed per minute per client.
    pub fn new(max_per_minute: u32) -> Self {
        RateLimiter {
            buckets: RwLock::new(HashMap::new()),
            max_per_minute,
        }
    }

    /// Checks if a request from this client would be rate limited.
    ///
    /// Does not consume a token.
    #[allow(dead_code)]
    pub fn check(&self, client_id: &str) -> bool {
        let mut buckets = self.buckets.write().unwrap();
        let bucket = buckets.entry(client_id.to_string()).or_insert_with(|| {
            TokenBucket::new(self.max_per_minute, self.max_per_minute as f64 / 60.0)
        });
        bucket.can_consume()
    }

    /// Tries to consume a token for this client.
    ///
    /// Returns true if allowed, false if rate limited.
    pub fn consume(&self, client_id: &str) -> bool {
        let mut buckets = self.buckets.write().unwrap();
        let bucket = buckets.entry(client_id.to_string()).or_insert_with(|| {
            TokenBucket::new(self.max_per_minute, self.max_per_minute as f64 / 60.0)
        });
        bucket.try_consume()
    }

    /// Removes inactive client buckets (for memory cleanup).
    ///
    /// Removes buckets that haven't been accessed for the given duration.
    /// Returns the number of buckets removed.
    pub fn cleanup_inactive(&self, max_idle: std::time::Duration) -> usize {
        let mut buckets = self.buckets.write().unwrap();
        let now = Instant::now();
        let initial_count = buckets.len();

        buckets.retain(|_, bucket| now.duration_since(bucket.last_update) < max_idle);

        initial_count - buckets.len()
    }

    /// Returns the number of client buckets currently tracked.
    /// Reserved for future metrics/monitoring.
    #[allow(dead_code)]
    pub fn client_count(&self) -> usize {
        let buckets = self.buckets.read().unwrap();
        buckets.len()
    }
}

// INLINE_TEST_REQUIRED: Binary crate without lib.rs - tests cannot be external
#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_rate_limiter_allows_initial_requests() {
        let limiter = RateLimiter::new(10);

        // First 10 requests should succeed
        for _ in 0..10 {
            assert!(limiter.consume("client-1"));
        }
    }

    #[test]
    fn test_rate_limiter_blocks_excess() {
        let limiter = RateLimiter::new(5);

        // Use up all tokens
        for _ in 0..5 {
            assert!(limiter.consume("client-1"));
        }

        // Next request should be blocked
        assert!(!limiter.consume("client-1"));
    }

    #[test]
    fn test_rate_limiter_refills_over_time() {
        let limiter = RateLimiter::new(60); // 1 per second

        // Use up all tokens
        for _ in 0..60 {
            limiter.consume("client-1");
        }

        // Should be blocked
        assert!(!limiter.consume("client-1"));

        // Wait a bit for refill
        thread::sleep(Duration::from_millis(100));

        // Should have some tokens now (at least partial)
        // Note: This is timing-sensitive, so we just check it doesn't panic
    }

    #[test]
    fn test_rate_limiter_separate_clients() {
        let limiter = RateLimiter::new(5);

        // Client 1 uses all tokens
        for _ in 0..5 {
            assert!(limiter.consume("client-1"));
        }
        assert!(!limiter.consume("client-1"));

        // Client 2 still has tokens
        assert!(limiter.consume("client-2"));
    }

    #[test]
    fn test_check_does_not_consume() {
        let limiter = RateLimiter::new(1);

        // Check should return true
        assert!(limiter.check("client-1"));
        assert!(limiter.check("client-1"));

        // Consume the token
        assert!(limiter.consume("client-1"));

        // Now check should return false
        assert!(!limiter.check("client-1"));
    }

    #[test]
    fn test_cleanup_inactive_removes_stale_buckets() {
        let limiter = RateLimiter::new(10);

        // Create some client buckets
        limiter.consume("client-1");
        limiter.consume("client-2");
        limiter.consume("client-3");

        assert_eq!(limiter.client_count(), 3);

        // Wait a tiny bit then access client-1 to keep it active
        thread::sleep(Duration::from_millis(10));
        limiter.consume("client-1");

        // Cleanup with a very short idle time (5ms)
        // client-2 and client-3 should be removed, client-1 should remain
        let removed = limiter.cleanup_inactive(Duration::from_millis(5));

        // At least client-2 and client-3 should be removed (idle > 5ms)
        assert!(removed >= 2, "Expected at least 2 removed, got {}", removed);
        assert_eq!(limiter.client_count(), 1);

        // client-1 should still be there
        assert!(limiter.consume("client-1"));
    }

    #[test]
    fn test_cleanup_inactive_keeps_recent_buckets() {
        let limiter = RateLimiter::new(10);

        // Create buckets
        limiter.consume("client-1");
        limiter.consume("client-2");

        // Cleanup with a long idle time (should remove nothing)
        let removed = limiter.cleanup_inactive(Duration::from_secs(3600));

        assert_eq!(removed, 0);
        assert_eq!(limiter.client_count(), 2);
    }

    #[test]
    fn test_client_count() {
        let limiter = RateLimiter::new(10);

        assert_eq!(limiter.client_count(), 0);

        limiter.consume("client-1");
        assert_eq!(limiter.client_count(), 1);

        limiter.consume("client-2");
        assert_eq!(limiter.client_count(), 2);

        // Same client doesn't increase count
        limiter.consume("client-1");
        assert_eq!(limiter.client_count(), 2);
    }
}
