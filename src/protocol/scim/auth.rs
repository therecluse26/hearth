//! Realm-scoped SCIM bearer authentication helpers.

use axum::http::{HeaderMap, StatusCode};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::core::{RealmId, UserId};
use crate::protocol::admin_auth::RateLimitOutcome;
use crate::protocol::http::AppState;
use crate::protocol::scim::error::ScimError;

#[derive(Debug, Clone)]
pub struct ScimAuth {
    pub realm_id: RealmId,
    pub actor: String,
}

pub fn authenticate(headers: &HeaderMap, state: &AppState) -> Result<ScimAuth, ScimError> {
    let realm_id = extract_realm_id(headers)?;
    let token = extract_bearer_token(headers)?;

    let realm = state
        .identity
        .get_realm(&realm_id)
        .map_err(|e| {
            tracing::warn!(error = %e, "SCIM auth realm lookup failed");
            ScimError::internal()
        })?
        .ok_or_else(|| ScimError::forbidden("realm unavailable"))?;

    let expected_hash = realm
        .config()
        .scim_bearer_token_hash
        .as_deref()
        .ok_or_else(|| ScimError::forbidden("scim not enabled for realm"))?;

    let incoming_hash = sha256_hex(&token);
    let hash_match: bool = expected_hash
        .as_bytes()
        .ct_eq(incoming_hash.as_bytes())
        .into();
    if !hash_match {
        return Err(ScimError::unauthorized("invalid bearer token"));
    }

    check_scim_rate_limit(state, &realm_id)?;

    Ok(ScimAuth {
        actor: format!("scim_token:{}", realm_id.as_uuid()),
        realm_id,
    })
}

fn extract_realm_id(headers: &HeaderMap) -> Result<RealmId, ScimError> {
    let header_value = headers
        .get("x-realm-id")
        .ok_or_else(|| ScimError::bad_request("invalidValue", "missing X-Realm-ID header"))?
        .to_str()
        .map_err(|_| ScimError::bad_request("invalidValue", "invalid X-Realm-ID header"))?;

    let uuid: uuid::Uuid = header_value
        .parse()
        .map_err(|_| ScimError::bad_request("invalidValue", "X-Realm-ID must be a valid UUID"))?;

    Ok(RealmId::new(uuid))
}

fn extract_bearer_token(headers: &HeaderMap) -> Result<String, ScimError> {
    let auth_header = headers
        .get("authorization")
        .ok_or_else(|| ScimError::unauthorized("missing authorization header"))?
        .to_str()
        .map_err(|_| ScimError::unauthorized("invalid authorization header"))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| ScimError::unauthorized("invalid authorization scheme"))?;

    Ok(token.to_string())
}

fn check_scim_rate_limit(state: &AppState, realm_id: &RealmId) -> Result<(), ScimError> {
    #[allow(clippy::cast_possible_truncation)]
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64;

    // Reuse the shared limiter by keying SCIM traffic on the realm UUID.
    let synthetic_actor = UserId::new(*realm_id.as_uuid());
    match state.admin_rate_limiter.check(&synthetic_actor, now) {
        RateLimitOutcome::Allowed => Ok(()),
        RateLimitOutcome::Exceeded => Err(ScimError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded",
        )),
    }
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}
