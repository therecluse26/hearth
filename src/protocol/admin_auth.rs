//! Shared rate limiters for admin and token endpoints.
//!
//! [`AdminRateLimiter`] tracks per-admin-user request counts in a rolling
//! 1-minute window, shared between HTTP and gRPC surfaces.
//!
//! [`TokenRateLimiter`] tracks per-`(realm, client_id)` request counts on the
//! OAuth token, introspection, and device-authorization endpoints.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::core::{ClientId, RealmId, UserId};

/// Maximum admin API requests per minute per user.
pub const ADMIN_RATE_LIMIT: u32 = 100;

/// Rate limit window in microseconds (1 minute).
pub const ADMIN_RATE_WINDOW_MICROS: i64 = 60 * 1_000_000;

/// Per-request rate tracker entry (shared by both limiters).
#[derive(Debug, Clone)]
struct RateTracker {
    count: u32,
    window_start_micros: i64,
}

/// Thread-safe rate limiter shared across protocol surfaces.
///
/// Guarded by a single `Mutex` — contention is low because each request only
/// performs a cheap increment under the lock.
#[derive(Debug, Default)]
pub struct AdminRateLimiter {
    trackers: Mutex<HashMap<String, RateTracker>>,
}

/// Outcome of an admin rate-limit check.
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

        let tracker = trackers.entry(key).or_insert(RateTracker {
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

// === Token endpoint rate limiter ===

/// Maximum token-endpoint requests per minute per `(realm, client)` pair.
pub const TOKEN_RATE_LIMIT: u32 = 200;

/// Token rate-limit window in microseconds (1 minute).
pub const TOKEN_RATE_WINDOW_MICROS: i64 = 60 * 1_000_000;

/// Outcome of a token endpoint rate-limit check.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TokenRateLimitOutcome {
    /// The request may proceed.
    Allowed,
    /// Exceeded the per-client limit.  `retry_after_secs` is the number of
    /// whole seconds until the current window resets.
    Exceeded {
        /// Seconds the client should wait before retrying (for `Retry-After`).
        retry_after_secs: u32,
    },
}

/// Per-`(realm, client)` sliding-window rate limiter for OAuth token endpoints.
///
/// Keyed by `"{realm_uuid}:{client_uuid}"`.  Lock contention is low because
/// each request holds the lock only long enough to increment a counter.
#[derive(Debug, Default)]
pub struct TokenRateLimiter {
    trackers: Mutex<HashMap<String, RateTracker>>,
}

impl TokenRateLimiter {
    /// Creates an empty limiter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a request and reports whether it is permitted.
    ///
    /// `now_micros` is the current Unix timestamp in microseconds; pass a
    /// fixed value in tests to drive time deterministically.
    pub fn check(
        &self,
        realm_id: &RealmId,
        client_id: &ClientId,
        now_micros: i64,
    ) -> TokenRateLimitOutcome {
        let key = format!("{}:{}", realm_id.as_uuid(), client_id.as_uuid());
        let mut trackers = self
            .trackers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let tracker = trackers.entry(key).or_insert(RateTracker {
            count: 0,
            window_start_micros: now_micros,
        });

        if now_micros - tracker.window_start_micros > TOKEN_RATE_WINDOW_MICROS {
            tracker.count = 0;
            tracker.window_start_micros = now_micros;
        }

        tracker.count += 1;
        if tracker.count > TOKEN_RATE_LIMIT {
            let elapsed = now_micros - tracker.window_start_micros;
            let remaining_micros = TOKEN_RATE_WINDOW_MICROS - elapsed;
            let retry_after_secs =
                u32::try_from((remaining_micros / 1_000_000).max(1)).unwrap_or(60);
            TokenRateLimitOutcome::Exceeded { retry_after_secs }
        } else {
            TokenRateLimitOutcome::Allowed
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

    fn realm() -> RealmId {
        RealmId::new(Uuid::new_v4())
    }

    fn client() -> ClientId {
        ClientId::new(Uuid::new_v4())
    }

    // --- AdminRateLimiter ---

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

    // --- TokenRateLimiter ---

    #[test]
    fn token_allows_under_limit() {
        let limiter = TokenRateLimiter::new();
        let r = realm();
        let c = client();
        for _ in 0..TOKEN_RATE_LIMIT {
            assert_eq!(limiter.check(&r, &c, 0), TokenRateLimitOutcome::Allowed);
        }
    }

    #[test]
    fn token_rejects_over_limit() {
        let limiter = TokenRateLimiter::new();
        let r = realm();
        let c = client();
        for _ in 0..TOKEN_RATE_LIMIT {
            let _ = limiter.check(&r, &c, 0);
        }
        assert!(matches!(
            limiter.check(&r, &c, 0),
            TokenRateLimitOutcome::Exceeded { .. }
        ));
    }

    #[test]
    fn token_retry_after_is_positive() {
        let limiter = TokenRateLimiter::new();
        let r = realm();
        let c = client();
        for _ in 0..TOKEN_RATE_LIMIT {
            let _ = limiter.check(&r, &c, 0);
        }
        match limiter.check(&r, &c, 0) {
            TokenRateLimitOutcome::Exceeded { retry_after_secs } => {
                assert!(retry_after_secs > 0);
                assert!(retry_after_secs <= 60);
            }
            TokenRateLimitOutcome::Allowed => panic!("expected Exceeded"),
        }
    }

    #[test]
    fn token_resets_after_window() {
        let limiter = TokenRateLimiter::new();
        let r = realm();
        let c = client();
        for _ in 0..TOKEN_RATE_LIMIT {
            let _ = limiter.check(&r, &c, 0);
        }
        assert!(matches!(
            limiter.check(&r, &c, 0),
            TokenRateLimitOutcome::Exceeded { .. }
        ));
        let later = TOKEN_RATE_WINDOW_MICROS + 1;
        assert_eq!(limiter.check(&r, &c, later), TokenRateLimitOutcome::Allowed);
    }

    #[test]
    fn token_separate_clients_independent() {
        let limiter = TokenRateLimiter::new();
        let r = realm();
        let c1 = client();
        let c2 = client();
        for _ in 0..TOKEN_RATE_LIMIT {
            let _ = limiter.check(&r, &c1, 0);
        }
        assert!(matches!(
            limiter.check(&r, &c1, 0),
            TokenRateLimitOutcome::Exceeded { .. }
        ));
        assert_eq!(limiter.check(&r, &c2, 0), TokenRateLimitOutcome::Allowed);
    }

    #[test]
    fn token_separate_realms_independent() {
        let limiter = TokenRateLimiter::new();
        let r1 = realm();
        let r2 = realm();
        let c = client();
        for _ in 0..TOKEN_RATE_LIMIT {
            let _ = limiter.check(&r1, &c, 0);
        }
        assert!(matches!(
            limiter.check(&r1, &c, 0),
            TokenRateLimitOutcome::Exceeded { .. }
        ));
        assert_eq!(limiter.check(&r2, &c, 0), TokenRateLimitOutcome::Allowed);
    }
}
