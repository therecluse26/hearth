//! Hearth — a purpose-built identity database.
//!
//! Single-binary Rust server for authentication, claims-based RBAC
//! authorization, and session management with a custom embedded
//! storage engine.

pub mod audit;
pub mod cluster;
pub mod config;
pub mod core;
pub mod identity;
pub mod metrics;
pub mod protocol;
pub mod rbac;
pub mod storage;
pub mod webhook;
