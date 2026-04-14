//! Test infrastructure for black box testing.
//!
//! Provides [`TestHarness`] for running tests against Hearth in both
//! embedded and server modes. The same test logic can run against both
//! modes to verify the public API contract.

use std::fmt;

use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Errors from test harness operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum TestHarnessError {
    /// Server mode is not yet available (HTTP layer not implemented).
    ServerNotAvailable,
    /// Storage engine failed to initialize.
    Storage(hearth::storage::StorageError),
}

impl fmt::Display for TestHarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServerNotAvailable => {
                write!(
                    f,
                    "server mode not yet available: HTTP layer not implemented"
                )
            }
            Self::Storage(err) => write!(f, "storage initialization failed: {err}"),
        }
    }
}

impl std::error::Error for TestHarnessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ServerNotAvailable => None,
            Self::Storage(err) => Some(err),
        }
    }
}

impl From<hearth::storage::StorageError> for TestHarnessError {
    fn from(err: hearth::storage::StorageError) -> Self {
        Self::Storage(err)
    }
}

/// The operational mode of the test harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarnessMode {
    /// In-process embedded engine (library mode).
    Embedded,
    /// HTTP server on a random port.
    Server,
}

/// Test harness wrapping a Hearth instance for black box testing.
///
/// Supports embedded (library) and server (HTTP) modes. The same test
/// logic can run against both modes to verify the public API contract.
///
/// # Cleanup
///
/// The harness owns a [`tempfile::TempDir`] that is automatically
/// removed when the harness is dropped, ensuring test isolation.
pub struct TestHarness {
    /// The operational mode.
    mode: HarnessMode,
    /// Storage engine (embedded mode only).
    engine: EmbeddedStorageEngine,
    /// Temporary directory — held for lifetime management.
    _temp_dir: tempfile::TempDir,
}

impl fmt::Debug for TestHarness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestHarness")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl TestHarness {
    /// Creates a test harness in embedded mode.
    ///
    /// Opens an [`EmbeddedStorageEngine`] in an isolated temporary directory
    /// with development-friendly configuration (no fsync, default thresholds).
    #[allow(clippy::unused_async)]
    pub async fn embedded() -> Result<Self, TestHarnessError> {
        let temp_dir = tempfile::tempdir().map_err(hearth::storage::StorageError::Io)?;
        let config = StorageConfig::dev(temp_dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config)?;

        Ok(Self {
            mode: HarnessMode::Embedded,
            engine,
            _temp_dir: temp_dir,
        })
    }

    /// Creates a test harness in server mode.
    ///
    /// Currently returns [`TestHarnessError::ServerNotAvailable`] because
    /// the HTTP layer is not yet implemented. Will be enabled when the
    /// protocol layer is built.
    #[allow(clippy::unused_async)]
    pub async fn server() -> Result<Self, TestHarnessError> {
        Err(TestHarnessError::ServerNotAvailable)
    }

    /// Returns the operational mode of this harness.
    pub fn mode(&self) -> HarnessMode {
        self.mode
    }

    /// Returns a reference to the storage engine.
    ///
    /// Available in both modes — embedded mode returns the in-process engine,
    /// server mode will return a client-backed implementation.
    pub fn storage(&self) -> &dyn StorageEngine {
        &self.engine
    }

    /// Returns the base URL for server mode, or `None` for embedded mode.
    pub fn base_url(&self) -> Option<&str> {
        match self.mode {
            // Server mode will return Some(...) when HTTP layer is implemented
            HarnessMode::Embedded | HarnessMode::Server => None,
        }
    }
}
