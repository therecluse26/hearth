//! Storage engine error types.

use std::fmt;

/// Errors originating from the storage engine.
#[derive(Debug)]
#[non_exhaustive]
pub enum StorageError {
    /// An I/O error occurred during a storage operation.
    Io(std::io::Error),
    /// A CRC checksum did not match the expected value.
    ChecksumMismatch {
        /// Byte offset in the WAL where the mismatch was detected.
        offset: u64,
    },
    /// A record could not be deserialized from its binary representation.
    DeserializationFailed {
        /// Description of what went wrong.
        reason: String,
    },
    /// The storage file is corrupted at the given offset.
    Corrupted {
        /// Byte offset where corruption was detected.
        offset: u64,
    },
    /// An SST file has an invalid format or structure.
    InvalidSstFormat {
        /// Description of what was invalid.
        reason: String,
    },
    /// The hot tier is full and eviction could not free space.
    HotTierFull,
    /// A cryptographic operation failed (encryption, decryption, or key
    /// generation).
    Crypto {
        /// Description of what went wrong. MUST NOT contain key material.
        reason: String,
    },
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "storage I/O error: {err}"),
            Self::ChecksumMismatch { offset } => {
                write!(f, "checksum mismatch at byte offset {offset}")
            }
            Self::DeserializationFailed { reason } => {
                write!(f, "deserialization failed: {reason}")
            }
            Self::Corrupted { offset } => {
                write!(f, "storage corrupted at byte offset {offset}")
            }
            Self::InvalidSstFormat { reason } => {
                write!(f, "invalid SST format: {reason}")
            }
            Self::HotTierFull => write!(f, "hot tier is full and eviction could not free space"),
            Self::Crypto { reason } => {
                write!(f, "cryptographic operation failed: {reason}")
            }
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::ChecksumMismatch { .. }
            | Self::DeserializationFailed { .. }
            | Self::Corrupted { .. }
            | Self::InvalidSstFormat { .. }
            | Self::HotTierFull
            | Self::Crypto { .. } => None,
        }
    }
}

impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_error_display() {
        let err = StorageError::ChecksumMismatch { offset: 42 };
        let display = format!("{err}");
        assert!(display.contains("checksum"), "got: {display}");
        assert!(display.contains("42"), "got: {display}");

        let io_err = StorageError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file missing",
        ));
        let display = format!("{io_err}");
        assert!(display.contains("I/O"), "got: {display}");

        // Verify it implements std::error::Error
        let _: &dyn std::error::Error = &err;
    }
}
