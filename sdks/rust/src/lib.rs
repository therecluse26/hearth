//! Hearth identity platform Rust SDK.
//!
//! Provides [`HearthClient`] (auth flows, RBAC predicates, WebAuthn)
//! and [`AdminClient`] (user/realm CRUD).

mod admin;
mod client;
mod error;
mod types;

pub use admin::AdminClient;
pub use client::HearthClient;
pub use error::HearthError;
pub use types::*;
