//! Core error types shared across layers.

use std::fmt;

/// Errors originating from the core types layer.
#[derive(Debug)]
#[non_exhaustive]
pub enum CoreError {
    /// An entity ID string could not be parsed.
    InvalidId(String),
    /// A timestamp value was outside the representable range.
    TimestampOutOfRange,
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidId(msg) => write!(f, "invalid ID: {msg}"),
            Self::TimestampOutOfRange => write!(f, "timestamp out of range"),
        }
    }
}

impl std::error::Error for CoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_error_display_and_trait() {
        let err = CoreError::InvalidId("bad-uuid".to_string());
        let display = format!("{err}");
        assert!(display.contains("invalid ID"), "got: {display}");

        let err2 = CoreError::TimestampOutOfRange;
        let display2 = format!("{err2}");
        assert!(display2.contains("timestamp"), "got: {display2}");

        // Verify it implements std::error::Error
        let _: &dyn std::error::Error = &err2;
    }
}
