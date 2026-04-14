//! Hearth — a purpose-built identity database.
//!
//! Single-binary Rust server for authentication, authorization (Zanzibar-style),
//! and session management with a custom embedded storage engine.

pub mod authz;
pub mod cluster;
pub mod config;
pub mod core;
pub mod identity;
pub mod protocol;
pub mod storage;
