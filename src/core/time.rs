//! Timestamp and Clock abstractions for deterministic time handling.
//!
//! All timestamps are UTC Unix microseconds. The `Clock` trait enables
//! injectable time for deterministic testing.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::SystemTime;

/// A UTC timestamp stored as Unix microseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Timestamp(i64);

impl Timestamp {
    /// Returns the current UTC timestamp from the system clock.
    ///
    /// Convenience method for code that doesn't need an injectable clock.
    /// For testable code, prefer using the `Clock` trait.
    pub fn now() -> Self {
        let duration = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let micros = duration.as_micros() as i64;
        Self(micros)
    }

    /// Creates a timestamp from raw microseconds since Unix epoch.
    pub fn from_micros(micros: i64) -> Self {
        Self(micros)
    }

    /// Returns the raw microseconds since Unix epoch.
    pub fn as_micros(&self) -> i64 {
        self.0
    }

    /// Returns a new timestamp advanced by the given microseconds.
    #[must_use]
    pub fn add_micros(&self, micros: i64) -> Self {
        Self(self.0 + micros)
    }

    /// Returns a new timestamp rewound by the given microseconds.
    #[must_use]
    pub fn sub_micros(&self, micros: i64) -> Self {
        Self(self.0 - micros)
    }
}

/// Trait for obtaining the current time. Implementations must be thread-safe.
pub trait Clock: Send + Sync {
    /// Returns the current timestamp.
    fn now(&self) -> Timestamp;
}

/// Real system clock implementation.
///
/// Zero-sized type that delegates to `SystemTime::now()`.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let duration = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();

        // duration_since returns Ok for any time after epoch, and we use
        // unwrap_or_default for pre-epoch (returns Duration::ZERO).
        // Truncation is acceptable: u128 micros won't exceed i64 range
        // until year ~292,277 CE.
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let micros = duration.as_micros() as i64;
        Timestamp::from_micros(micros)
    }
}

/// Deterministic clock for testing. Thread-safe via `AtomicI64`.
pub struct FakeClock {
    micros: AtomicI64,
}

impl FakeClock {
    /// Creates a new fake clock starting at the given timestamp.
    pub fn new(initial: Timestamp) -> Self {
        Self {
            micros: AtomicI64::new(initial.as_micros()),
        }
    }

    /// Advances the clock by the given number of microseconds.
    pub fn advance(&self, micros: i64) {
        self.micros.fetch_add(micros, Ordering::SeqCst);
    }

    /// Sets the clock to an exact timestamp.
    pub fn set(&self, ts: Timestamp) {
        self.micros.store(ts.as_micros(), Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_micros(self.micros.load(Ordering::SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_from_micros() {
        let ts = Timestamp::from_micros(1_700_000_000_000_000);
        assert_eq!(ts.as_micros(), 1_700_000_000_000_000);
    }

    #[test]
    fn timestamp_arithmetic() {
        let ts = Timestamp::from_micros(1000);
        assert_eq!(ts.add_micros(500).as_micros(), 1500);
        assert_eq!(ts.sub_micros(300).as_micros(), 700);
    }

    #[test]
    fn timestamp_ordering() {
        let t1 = Timestamp::from_micros(100);
        let t2 = Timestamp::from_micros(200);
        assert!(t1 < t2);
        assert!(t2 > t1);
        assert_eq!(t1, Timestamp::from_micros(100));
    }

    #[test]
    fn timestamp_serde_round_trip() {
        let ts = Timestamp::from_micros(1_700_000_000_000_000);
        let json = serde_json::to_string(&ts).expect("serialize");
        let deserialized: Timestamp = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ts, deserialized);
    }

    #[test]
    fn system_clock_returns_reasonable_time() {
        let clock = SystemClock;
        let now = clock.now();
        // After 2024-01-01 UTC in microseconds
        let after_2024 = 1_704_067_200_000_000_i64;
        // Before 2100-01-01 UTC in microseconds
        let before_2100 = 4_102_444_800_000_000_i64;
        assert!(
            now.as_micros() > after_2024,
            "too early: {}",
            now.as_micros()
        );
        assert!(
            now.as_micros() < before_2100,
            "too late: {}",
            now.as_micros()
        );
    }

    #[test]
    fn fake_clock_deterministic() {
        let clock = FakeClock::new(Timestamp::from_micros(42));
        assert_eq!(clock.now().as_micros(), 42);
        assert_eq!(clock.now().as_micros(), 42); // stable
    }

    #[test]
    fn fake_clock_advance() {
        let clock = FakeClock::new(Timestamp::from_micros(1000));
        clock.advance(500);
        assert_eq!(clock.now().as_micros(), 1500);
        clock.advance(200);
        assert_eq!(clock.now().as_micros(), 1700);
    }

    #[test]
    fn fake_clock_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FakeClock>();
    }
}
