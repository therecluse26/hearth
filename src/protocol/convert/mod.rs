//! Wire-to-domain type conversions.
//!
//! This module owns all translation between protobuf (wire) types in
//! [`super::proto`] and domain types in the identity, authorization,
//! and audit layers. The protocol layer is the only place these
//! conversions live — neither domain nor proto types know about each other.

pub mod audit;
pub mod authz;
pub mod identity;
pub mod oauth;
