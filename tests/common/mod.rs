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
use hearth::core::{Clock, SystemClock};
use hearth::identity::{CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
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
pub struct TestHarness {
    /// The operational mode.
    mode: HarnessMode,
    /// Storage engine.
    engine: Arc<EmbeddedStorageEngine>,
    /// RBAC engine.
    rbac_engine: Arc<EmbeddedRbacEngine>,
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
    #[allow(clippy::unused_async)]
    pub async fn embedded() -> Result<Self, TestHarnessError> {
        let temp_dir = tempfile::tempdir().map_err(hearth::storage::StorageError::Io)?;
        let config = StorageConfig::dev(temp_dir.path().to_path_buf());
        let engine = Arc::new(EmbeddedStorageEngine::open(config)?);
        let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
        let rbac_engine = Arc::new(EmbeddedRbacEngine::new(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
        ));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let identity_engine = EmbeddedIdentityEngine::with_rbac(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            identity_config,
            Arc::clone(&rbac_engine) as Arc<dyn RbacEngine>,
        )
        .expect("identity engine creation");
        let audit_engine =
            EmbeddedAuditEngine::new(Arc::clone(&engine) as Arc<dyn StorageEngine>, clock);

        Ok(Self {
            mode: HarnessMode::Embedded,
            engine,
            rbac_engine,
            identity_engine: Arc::new(identity_engine),
            audit_engine: Arc::new(audit_engine),
            _temp_dir: temp_dir,
        })
    }

    /// Creates a test harness in server mode.
    #[allow(clippy::unused_async)]
    pub async fn server() -> Result<Self, TestHarnessError> {
        Err(TestHarnessError::ServerNotAvailable)
    }

    /// Returns the operational mode of this harness.
    pub fn mode(&self) -> HarnessMode {
        self.mode
    }

    /// Returns a reference to the storage engine.
    pub fn storage(&self) -> &dyn StorageEngine {
        self.engine.as_ref()
    }

    /// Returns a reference to the RBAC engine.
    pub fn rbac(&self) -> &dyn RbacEngine {
        self.rbac_engine.as_ref()
    }

    /// Legacy alias kept so existing tests still compile. Returns the RBAC engine.
    pub fn authz(&self) -> &dyn RbacEngine {
        self.rbac_engine.as_ref()
    }

    /// Returns a reference to the identity engine.
    pub fn identity(&self) -> &dyn IdentityEngine {
        self.identity_engine.as_ref()
    }

    /// Returns a reference to the audit engine.
    pub fn audit(&self) -> &dyn AuditEngine {
        self.audit_engine.as_ref()
    }

    /// Returns an `Arc<dyn IdentityEngine>`.
    pub fn identity_arc(&self) -> Arc<dyn IdentityEngine> {
        self.identity_engine.clone() as Arc<dyn IdentityEngine>
    }

    /// Returns an `Arc<dyn RbacEngine>`.
    pub fn rbac_arc(&self) -> Arc<dyn RbacEngine> {
        self.rbac_engine.clone() as Arc<dyn RbacEngine>
    }

    /// Legacy alias kept so existing tests still compile. Returns the RBAC engine.
    pub fn authz_arc(&self) -> Arc<dyn RbacEngine> {
        self.rbac_arc()
    }

    /// Returns an `Arc<dyn AuditEngine>`.
    pub fn audit_arc(&self) -> Arc<dyn AuditEngine> {
        self.audit_engine.clone() as Arc<dyn AuditEngine>
    }

    /// Returns the base URL for server mode, or `None` for embedded mode.
    pub fn base_url(&self) -> Option<&str> {
        match self.mode {
            HarnessMode::Embedded | HarnessMode::Server => None,
        }
    }
}
