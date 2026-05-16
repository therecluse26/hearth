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
    /// The WAL file uses a format version newer than this binary supports.
    ///
    /// The file was likely written by a newer version of Hearth. Downgrading
    /// is not supported — upgrade the binary or restore from backup.
    UnsupportedWalVersion {
        /// The version number found in the file.
        found: u16,
    },
    /// Realm KEKs cannot be decrypted with the current (or previous) host key.
    ///
    /// Startup is blocked. The operator must either set `HEARTH_PREVIOUS_MASTER_KEY`
    /// to the old value or restore from backup.
    HostKeyMismatch {
        /// Display names of the realms whose KEKs could not be decrypted.
        affected_realms: Vec<String>,
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
            Self::UnsupportedWalVersion { found } => {
                write!(
                    f,
                    "WAL format version {found} is not supported by this binary; \
                     upgrade Hearth or restore from backup"
                )
            }
            Self::HostKeyMismatch { affected_realms } => {
                let realms = affected_realms.join(", ");
                write!(
                    f,
                    "realm KEKs could not be decrypted with the current HEARTH_MASTER_KEY; \
                     affected realms: {realms}"
                )
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
            | Self::Crypto { .. }
            | Self::UnsupportedWalVersion { .. }
            | Self::HostKeyMismatch { .. } => None,
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
