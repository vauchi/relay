//! Connection Limiting
//!
//! Enforces maximum concurrent connections to prevent resource exhaustion.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Connection limiter that tracks and enforces connection limits.
#[derive(Clone)]
pub struct ConnectionLimiter {
    inner: Arc<ConnectionLimiterInner>,
}

struct ConnectionLimiterInner {
    /// Current number of active connections.
    active: AtomicUsize,
    /// Maximum allowed connections.
    max_connections: usize,
}

impl ConnectionLimiter {
    /// Creates a new connection limiter with the given maximum.
    pub fn new(max_connections: usize) -> Self {
        ConnectionLimiter {
            inner: Arc::new(ConnectionLimiterInner {
                active: AtomicUsize::new(0),
                max_connections,
            }),
        }
    }

    /// Tries to acquire a connection slot.
    ///
    /// Returns `Some(ConnectionGuard)` if successful, `None` if at capacity.
    /// The guard automatically releases the slot when dropped.
    pub fn try_acquire(&self) -> Option<ConnectionGuard> {
        loop {
            let current = self.inner.active.load(Ordering::SeqCst);
            if current >= self.inner.max_connections {
                return None;
            }

            // Try to increment atomically
            if self
                .inner
                .active
                .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Some(ConnectionGuard {
                    inner: self.inner.clone(),
                });
            }
            // If CAS failed, another thread changed the value, retry
        }
    }

    /// Returns the current number of active connections.
    pub fn active_count(&self) -> usize {
        self.inner.active.load(Ordering::SeqCst)
    }

    /// Returns the maximum allowed connections.
    #[allow(dead_code)]
    pub fn max_connections(&self) -> usize {
        self.inner.max_connections
    }
}

/// RAII guard that releases the connection slot on drop.
pub struct ConnectionGuard {
    inner: Arc<ConnectionLimiterInner>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.inner.active.fetch_sub(1, Ordering::SeqCst);
    }
}

// INLINE_TEST_REQUIRED: Binary crate without lib.rs - tests cannot be external
#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_connection_limiter_allows_under_limit() {
        let limiter = ConnectionLimiter::new(3);

        let _g1 = limiter.try_acquire().expect("Should allow first");
        let _g2 = limiter.try_acquire().expect("Should allow second");
        let _g3 = limiter.try_acquire().expect("Should allow third");

        assert_eq!(limiter.active_count(), 3);
    }

    #[test]
    fn test_connection_limiter_rejects_at_limit() {
        let limiter = ConnectionLimiter::new(2);

        let _g1 = limiter.try_acquire().expect("Should allow first");
        let _g2 = limiter.try_acquire().expect("Should allow second");

        // Third should be rejected
        assert!(limiter.try_acquire().is_none(), "Should reject at limit");
    }

    #[test]
    fn test_connection_guard_releases_on_drop() {
        let limiter = ConnectionLimiter::new(1);

        {
            let _guard = limiter.try_acquire().expect("Should allow");
            assert_eq!(limiter.active_count(), 1);
        }

        // Guard dropped, should be released
        assert_eq!(limiter.active_count(), 0);

        // Should be able to acquire again
        let _guard = limiter.try_acquire().expect("Should allow after release");
    }

    #[test]
    fn test_connection_limiter_thread_safe() {
        let limiter = ConnectionLimiter::new(10);
        let mut handles = vec![];

        // Spawn 20 threads, each trying to acquire
        for _ in 0..20 {
            let limiter = limiter.clone();
            handles.push(thread::spawn(move || {
                if let Some(guard) = limiter.try_acquire() {
                    // Hold the connection briefly
                    thread::sleep(std::time::Duration::from_millis(10));
                    drop(guard);
                    true
                } else {
                    false
                }
            }));
        }

        let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // At least 10 should have succeeded (the first batch)
        let successes = results.iter().filter(|&&b| b).count();
        assert!(successes >= 10, "At least 10 should succeed");

        // After all threads complete, count should be 0
        assert_eq!(limiter.active_count(), 0);
    }

    #[test]
    fn test_zero_max_connections() {
        let limiter = ConnectionLimiter::new(0);
        assert!(
            limiter.try_acquire().is_none(),
            "Zero limit should reject all"
        );
    }

    #[test]
    fn test_guard_is_send() {
        // Verify the guard can be sent across threads (required for tokio::spawn)
        fn assert_send<T: Send>() {}
        assert_send::<ConnectionGuard>();
    }
}
