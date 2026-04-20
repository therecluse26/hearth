//! Protocol layer: wire format adapters (REST, gRPC, OIDC, SAML, SCIM).
//!
//! Thin, stateless adapters that translate wire requests into Identity Engine
//! calls and serialize responses.

pub(crate) mod client_info;
pub mod convert;
pub mod http;
pub mod proto;
pub mod tls;
pub mod web;
