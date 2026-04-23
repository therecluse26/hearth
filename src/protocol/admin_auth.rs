//! Shared admin API rate limiter.
//!
//! Tracks per-admin-user request counts in a rolling 1-minute window. Shared
//! between the HTTP admin surface (`src/protocol/http.rs`) and the gRPC
//! admin surface (`src/protocol/grpc/`) so a caller cannot evade the limit
//! by alternating protocols.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::core::UserId;

/// Maximum admin API requests per minute per user.
pub const ADMIN_RATE_LIMIT: u32 = 100;

/// Rate limit window in microseconds (1 minute).
pub const ADMIN_RATE_WINDOW_MICROS: i64 = 60 * 1_000_000;

/// Per-user rate tracker entry.
#[derive(Debug, Clone)]
struct AdminRateTracker {
    count: u32,
    window_start_micros: i64,
}

/// Thread-safe rate limiter shared across protocol surfaces.
///
/// Guarded by a single `Mutex` — contention is low because each request only
/// performs a cheap increment under the lock.
#[derive(Debug, Default)]
pub struct AdminRateLimiter {
    trackers: Mutex<HashMap<String, AdminRateTracker>>,
}

/// Outcome of a rate-limit check.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RateLimitOutcome {
    /// The request may proceed.
    Allowed,
    /// The caller exceeded `ADMIN_RATE_LIMIT` in the current window.
    Exceeded,
}

impl AdminRateLimiter {
    /// Creates an empty limiter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a request from `user_id` and reports whether it is permitted.
    ///
    /// The caller supplies `now_micros` so tests can drive time deterministically;
    /// production callers pass the current Unix-microsecond clock.
    pub fn check(&self, user_id: &UserId, now_micros: i64) -> RateLimitOutcome {
        let key = user_id.as_uuid().to_string();
        let mut trackers = self
            .trackers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let tracker = trackers.entry(key).or_insert(AdminRateTracker {
            count: 0,
            window_start_micros: now_micros,
        });

        if now_micros - tracker.window_start_micros > ADMIN_RATE_WINDOW_MICROS {
            tracker.count = 0;
            tracker.window_start_micros = now_micros;
        }

        tracker.count += 1;
        if tracker.count > ADMIN_RATE_LIMIT {
            RateLimitOutcome::Exceeded
        } else {
            RateLimitOutcome::Allowed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn user() -> UserId {
        UserId::new(Uuid::new_v4())
    }

    #[test]
    fn allows_under_limit() {
        let limiter = AdminRateLimiter::new();
        let u = user();
        for _ in 0..ADMIN_RATE_LIMIT {
            assert_eq!(limiter.check(&u, 0), RateLimitOutcome::Allowed);
        }
    }

    #[test]
    fn rejects_over_limit() {
        let limiter = AdminRateLimiter::new();
        let u = user();
        for _ in 0..ADMIN_RATE_LIMIT {
            let _ = limiter.check(&u, 0);
        }
        assert_eq!(limiter.check(&u, 0), RateLimitOutcome::Exceeded);
    }

    #[test]
    fn resets_after_window() {
        let limiter = AdminRateLimiter::new();
        let u = user();
        for _ in 0..ADMIN_RATE_LIMIT {
            let _ = limiter.check(&u, 0);
        }
        assert_eq!(limiter.check(&u, 0), RateLimitOutcome::Exceeded);
        let later = ADMIN_RATE_WINDOW_MICROS + 1;
        assert_eq!(limiter.check(&u, later), RateLimitOutcome::Allowed);
    }

    #[test]
    fn separate_users_independent() {
        let limiter = AdminRateLimiter::new();
        let a = user();
        let b = user();
        for _ in 0..ADMIN_RATE_LIMIT {
            let _ = limiter.check(&a, 0);
        }
        assert_eq!(limiter.check(&a, 0), RateLimitOutcome::Exceeded);
        assert_eq!(limiter.check(&b, 0), RateLimitOutcome::Allowed);
    }
}
