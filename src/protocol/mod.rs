//! Protocol layer: wire format adapters (REST, gRPC, OIDC, SAML, SCIM).
//!
//! Thin, stateless adapters that translate wire requests into Identity Engine
//! calls and serialize responses.

pub mod admin_auth;
pub(crate) mod client_info;
pub mod convert;
pub mod error_codes;
pub mod grpc;
pub mod http;
pub mod proto;
pub mod scim;
pub mod tls;
pub mod web;
