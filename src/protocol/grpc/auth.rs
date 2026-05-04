//! gRPC authentication helpers.
//!
//! Mirrors the `extract_admin_auth` flow from `src/protocol/http.rs`: the
//! caller must supply a bearer token in the `authorization` metadata header
//! and a realm id in the `x-realm-id` metadata header. The token is validated,
//! the caller's `hearth.admin` permission claim is checked, and the shared
//! [`AdminRateLimiter`] is consulted.
//!
//! The helper runs per-RPC (inside each handler) rather than as a tonic
//! interceptor because the decision needs access to the service's
//! [`GrpcState`] — interceptors don't carry typed per-service state.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tonic::{metadata::MetadataMap, Code, Status};

use crate::core::{RealmId, UserId};
use crate::protocol::admin_auth::{AdminRateLimiter, RateLimitOutcome};

use super::server::GrpcState;

/// Authenticated admin context returned by [`authenticate_admin`].
#[derive(Debug, Clone)]
pub struct AdminAuth {
    /// The target realm supplied via the `x-realm-id` metadata header.
    pub realm_id: RealmId,
    /// The authenticated admin user.
    pub user_id: UserId,
}

/// Validates an admin caller and returns their realm + user id.
///
/// Fails with:
/// - `UNAUTHENTICATED` — missing/invalid bearer token or realm header.
/// - `PERMISSION_DENIED` — valid token but missing `hearth.admin` claim.
/// - `RESOURCE_EXHAUSTED` — rate-limit exceeded.
pub fn authenticate_admin(md: &MetadataMap, state: &GrpcState) -> Result<AdminAuth, Status> {
    let realm_id = super::convert::extract_realm_id(md)?;
    let token = extract_bearer_token(md)?;

    let claims = state
        .identity
        .validate_token(&realm_id, &token)
        .map_err(|_| Status::new(Code::Unauthenticated, "invalid token"))?;

    let uuid_str = claims.sub.strip_prefix("user_").unwrap_or(&claims.sub);
    let user_uuid: uuid::Uuid = uuid_str
        .parse()
        .map_err(|_| Status::new(Code::Unauthenticated, "invalid token"))?;
    let user_id = UserId::new(user_uuid);

    let is_admin = claims.permissions.iter().any(|p| p == "hearth.admin");
    if !is_admin {
        return Err(Status::new(Code::PermissionDenied, "forbidden"));
    }

    check_rate_limit(&state.admin_rate_limiter, &user_id)?;

    Ok(AdminAuth { realm_id, user_id })
}

fn extract_bearer_token(md: &MetadataMap) -> Result<String, Status> {
    let raw = md
        .get("authorization")
        .ok_or_else(|| Status::new(Code::Unauthenticated, "missing authorization metadata"))?
        .to_str()
        .map_err(|_| Status::new(Code::Unauthenticated, "invalid authorization metadata"))?;
    raw.strip_prefix("Bearer ")
        .map(str::to_owned)
        .ok_or_else(|| Status::new(Code::Unauthenticated, "invalid authorization scheme"))
}

fn check_rate_limit(limiter: &Arc<AdminRateLimiter>, user_id: &UserId) -> Result<(), Status> {
    #[allow(clippy::cast_possible_truncation)]
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64;
    match limiter.check(user_id, now) {
        RateLimitOutcome::Allowed => Ok(()),
        RateLimitOutcome::Exceeded => {
            Err(Status::new(Code::ResourceExhausted, "rate limit exceeded"))
        }
    }
}
