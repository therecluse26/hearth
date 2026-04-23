//! Test infrastructure for black box testing.
//!
//! Provides [`TestHarness`] for running tests against Hearth in both
//! embedded and server modes. The same test logic can run against both
//! modes to verify the public API contract.

// Each integration test binary compiles this module independently,
// so not all variants/methods are used in every binary.
#![allow(dead_code)]

use std::fmt;
use std::sync::Arc;

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::authz::{AuthorizationEngine, EmbeddedAuthzEngine};
use hearth::core::{Clock, SystemClock};
use hearth::identity::{CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// Kept alongside the harness so tests can hand the engines to gRPC / HTTP
// rigs that require `Arc<dyn Trait>`.

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
    /// Storage engine (embedded mode only), wrapped in Arc for sharing with authz.
    engine: Arc<EmbeddedStorageEngine>,
    /// Authorization engine.
    authz_engine: Arc<EmbeddedAuthzEngine>,
    /// Identity engine.
    identity_engine: Arc<EmbeddedIdentityEngine>,
    /// Audit engine.
    audit_engine: Arc<EmbeddedAuditEngine>,
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
        let engine = Arc::new(EmbeddedStorageEngine::open(config)?);
        let authz_engine = EmbeddedAuthzEngine::new(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            hearth::authz::AuthzConfig::default(),
        );
        let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let identity_engine = EmbeddedIdentityEngine::new(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            identity_config,
        )
        .expect("identity engine creation");
        let audit_engine =
            EmbeddedAuditEngine::new(Arc::clone(&engine) as Arc<dyn StorageEngine>, clock);

        Ok(Self {
            mode: HarnessMode::Embedded,
            engine,
            authz_engine: Arc::new(authz_engine),
            identity_engine: Arc::new(identity_engine),
            audit_engine: Arc::new(audit_engine),
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
        self.engine.as_ref()
    }

    /// Returns a reference to the authorization engine.
    ///
    /// Available in both modes — embedded mode returns the in-process engine,
    /// server mode will return a client-backed implementation.
    pub fn authz(&self) -> &dyn AuthorizationEngine {
        self.authz_engine.as_ref()
    }

    /// Returns a reference to the identity engine.
    ///
    /// Available in both modes — embedded mode returns the in-process engine,
    /// server mode will return a client-backed implementation.
    pub fn identity(&self) -> &dyn IdentityEngine {
        self.identity_engine.as_ref()
    }

    /// Returns a reference to the audit engine.
    ///
    /// Available in both modes — embedded mode returns the in-process engine,
    /// server mode will return a client-backed implementation.
    pub fn audit(&self) -> &dyn AuditEngine {
        self.audit_engine.as_ref()
    }

    /// Returns an `Arc<dyn IdentityEngine>` for constructing protocol-layer
    /// state (gRPC / HTTP) that demands shared ownership.
    pub fn identity_arc(&self) -> Arc<dyn IdentityEngine> {
        self.identity_engine.clone() as Arc<dyn IdentityEngine>
    }

    /// Returns an `Arc<dyn AuthorizationEngine>` for shared ownership.
    pub fn authz_arc(&self) -> Arc<dyn AuthorizationEngine> {
        self.authz_engine.clone() as Arc<dyn AuthorizationEngine>
    }

    /// Returns an `Arc<dyn AuditEngine>` for shared ownership.
    pub fn audit_arc(&self) -> Arc<dyn AuditEngine> {
        self.audit_engine.clone() as Arc<dyn AuditEngine>
    }

    /// Returns the base URL for server mode, or `None` for embedded mode.
    pub fn base_url(&self) -> Option<&str> {
        match self.mode {
            // Server mode will return Some(...) when HTTP layer is implemented
            HarnessMode::Embedded | HarnessMode::Server => None,
        }
    }
}
