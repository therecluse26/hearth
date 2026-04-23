//! Migration from external identity providers.
//!
//! This module converts third-party identity exports into Hearth's data
//! model. Currently supported sources:
//!
//! - **Keycloak**: single realm-export JSON file.
//! - **Auth0**: operator-assembled bundle JSON (see
//!   `examples/auth0-migration-bundler/`).
//!
//! # Surface
//!
//! - [`KeycloakImporter`] + [`KeycloakRealmExport`] + [`ImportOptions`]
//!   for Keycloak.
//! - [`Auth0Importer`] + [`Auth0Bundle`] + [`Auth0ImportOptions`] for
//!   Auth0.
//! - [`MigrationError`] — unified error type wrapping lower-layer errors.
//!
//! Credential conversion (source-specific hash formats → PHC) is an
//! internal detail of each importer; direct callers use the importer's
//! `import_*` entry point.

mod auth0;
mod auth0_credentials;
mod credentials;
mod error;
mod keycloak;

pub use auth0::{
    Auth0Bundle, Auth0Client, Auth0ImportOptions, Auth0Importer, Auth0Organization,
    Auth0OrganizationMember, Auth0PasswordHash, Auth0PasswordHashValue, Auth0Role, Auth0Tenant,
    Auth0User,
};
pub use error::MigrationError;
pub use keycloak::{ImportOptions, KeycloakImporter, KeycloakRealmExport};
