//! Test infrastructure for black box testing.
//!
//! Provides `TestHarness` for running tests against Hearth in both
//! embedded and server modes.

/// Test harness wrapping a Hearth instance for black box testing.
///
/// Supports embedded (library) and server (HTTP) modes. The same test
/// logic can run against both modes to verify the public API contract.
pub struct TestHarness;
