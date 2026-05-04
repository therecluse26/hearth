//! gRPC protocol surface.
//!
//! Exposes the admin management API, OAuth 2.0 flows, authorization engine,
//! and audit log over gRPC alongside the existing REST surface. Both surfaces
//! call the same engine methods and share the admin rate limiter.
// `tonic::Status` is 176 bytes, which trips `result_large_err` whenever a
// function returns `Result<T, Status>` — but that is the fundamental return
// shape tonic requires, and boxing it breaks the service-trait signatures.
// Similarly, many conversions consume an owned error by value to produce a
// Status, which is idiomatic even though the compiler could see it as
// pass-by-value without consumption.
#![allow(clippy::result_large_err)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
//!
//! # Services
//!
//! | Service | Auth | Purpose |
//! |---------|------|---------|
//! | `IdentityAdminService` | admin bearer + `hearth.admin` claim | Users, realms, organizations |
//! | `ApplicationAdminService` | admin bearer + `hearth.admin` claim | OAuth clients |
//! | `RbacAdminService` | admin bearer + `hearth.admin` claim | Roles, groups, assignments |
//! | `AuditService` | admin bearer + `hearth.admin` claim | List events, verify integrity |
//! | `OAuthService` | RFC 6749 client auth | Authorize/Token/Revoke/Introspect/... |
//! | `grpc.health.v1.Health` | unauth | Kubernetes / L4 readiness probes |
//! | `grpc.reflection.v1.ServerReflection` | unauth | grpcurl / Postman |

pub mod audit;
pub mod auth;
pub mod convert;
pub mod identity;
pub mod oauth;
pub mod rbac_admin;
pub mod server;

pub use server::{build_router, serve, GrpcState};

/// Precompiled file-descriptor set bytes, used by `tonic-reflection` so
/// grpcurl / Postman can enumerate services at runtime without source access.
pub const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!("../generated/proto_descriptor.bin");
