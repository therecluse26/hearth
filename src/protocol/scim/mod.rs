//! SCIM 2.0 provisioning endpoint (RFC 7643 + RFC 7644).
//!
//! Mounted at `/scim/v2/*`. Auth is a realm-scoped bearer token plus
//! `X-Realm-ID`, with rate limiting shared with the admin surface.
//!
//! # Phase 1 scope
//!
//! - Endpoints: `/Users`, `/Groups`, `/ServiceProviderConfig`,
//!   `/Schemas`, `/ResourceTypes` — GET/POST/PUT/PATCH/DELETE where
//!   applicable.
//! - User core schema: `userName`, `externalId`, `name.{givenName,familyName}`,
//!   `displayName`, `emails[]` (primary only persisted), `active`, `meta`.
//! - Group core schema: `displayName`, `externalId`, `members[]` (role
//!   `Member`).
//! - Filter operators: `eq`, `ne`, `co`, `sw`, `ew`, `pr`, `and`, `or`.
//! - PATCH: simple path (`active`, `name.givenName`, `emails`, `members`…)
//!   and root-object replacement. Bracketed paths are rejected.
//! - Pagination: `startIndex` + `count`, in-memory page slice over a
//!   1000-record scan. Adequate for the per-IdP provisioning volumes we
//!   care about in v1.
//! - ETag: weak (`W/"<micros>"`) emitted on responses; inbound
//!   `If-Match` is accepted-and-ignored.
//!
//! # Deferred to hardening
//!
//! - Bracketed filter paths and PATCH complex value filters.
//! - `/Bulk`, `/Me`, sorting, attribute projection.
//! - Enterprise User schema extension + additional schema URNs.
//! - `If-Match` enforcement / 412 responses.
//! - Engine-level filter / pagination push-down.

use std::sync::Arc;

use axum::routing::{get, patch, post};
use axum::Router;

use crate::protocol::http::AppState;

pub mod auth;
pub mod discovery;
pub mod error;
pub mod filter;
pub mod groups;
pub mod patch_apply;
pub mod types;
pub mod users;

/// Builds the SCIM sub-router. State is inherited from the parent
/// router; do NOT call `.with_state(...)` here or `nest()` will refuse
/// to type-check.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/ServiceProviderConfig",
            get(discovery::service_provider_config),
        )
        .route("/ResourceTypes", get(discovery::resource_types))
        .route("/Schemas", get(discovery::schemas))
        .route("/Users", post(users::create_user).get(users::list_users))
        .route(
            "/Users/{id}",
            get(users::get_user)
                .put(users::replace_user)
                .delete(users::delete_user),
        )
        .route("/Users/{id}", patch(users::patch_user))
        .route(
            "/Groups",
            post(groups::create_group).get(groups::list_groups),
        )
        .route(
            "/Groups/{id}",
            get(groups::get_group)
                .put(groups::replace_group)
                .delete(groups::delete_group),
        )
        .route("/Groups/{id}", patch(groups::patch_group))
}
