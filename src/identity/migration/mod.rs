//! Migration from external identity providers.
//!
//! This module converts third-party identity exports into Hearth's data
//! model. Currently only Keycloak realm exports are supported; Auth0,
//! Okta, and others are deferred to later phases.
//!
//! # Surface
//!
//! The public API is intentionally narrow:
//!
//! - [`KeycloakImporter`] — orchestrates a realm import against an
//!   `IdentityEngine` + `AuthzEngine` pair.
//! - [`KeycloakRealmExport`] — serde model for a realm export JSON file.
//! - [`MigrationError`] — unified error type wrapping lower-layer errors.
//!
//! Credential conversion (Keycloak's `{credentialData, secretData}` →
//! PHC format) is an internal detail of the importer; direct callers
//! should use `import_realm()`.

mod credentials;
mod error;
mod keycloak;

pub use error::MigrationError;
pub use keycloak::{ImportOptions, KeycloakImporter, KeycloakRealmExport};
