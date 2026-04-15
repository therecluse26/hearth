//! Protocol layer: wire format adapters (REST, gRPC, OIDC, SAML, SCIM).
//!
//! Thin, stateless adapters that translate wire requests into Identity Engine
//! calls and serialize responses.

pub mod http;
