//! Hearth identity platform Rust SDK.
//!
//! Provides [`HearthClient`] (auth flows, RBAC predicates, WebAuthn)
//! and [`AdminClient`] (user/realm CRUD).

mod admin;
mod claims;
mod client;
mod error;
mod types;

pub use admin::AdminClient;
pub use claims::Claims;
pub use client::HearthClient;
pub use error::HearthError;
pub use types::*;
