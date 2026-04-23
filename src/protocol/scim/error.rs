//! SCIM 2.0 error response envelope (RFC 7644 §3.12).
//!
//! Every non-2xx response from the SCIM surface MUST carry the JSON shape:
//!
//! ```text
//! {
//!   "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
//!   "status": "404",
//!   "scimType": "invalidFilter",
//!   "detail": "Unsupported filter operator"
//! }
//! ```
//!
//! `scimType` is optional (omitted for generic errors like 401/500). `detail`
//! is sanitized — it MUST NOT contain secrets, raw upstream bodies, or
//! stack traces.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

/// The SCIM 2.0 error message schema URN.
pub const SCIM_ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

/// A structured SCIM error. Maps to the JSON envelope on serialize.
#[derive(Debug, Clone)]
pub struct ScimError {
    /// HTTP status code. Carried on the wire as a string per RFC.
    pub status: StatusCode,
    /// Machine-readable error kind (`invalidFilter`, `uniqueness`, …).
    /// `None` for generic errors where only `status` + `detail` are carried.
    pub scim_type: Option<&'static str>,
    /// Short human-readable description. MUST NOT contain PII.
    pub detail: String,
}

impl ScimError {
    /// Generic HTTP-status-only error (no `scimType`).
    pub fn new(status: StatusCode, detail: impl Into<String>) -> Self {
        Self {
            status,
            scim_type: None,
            detail: detail.into(),
        }
    }

    /// Convenience constructor for 400 + a specific `scimType`.
    pub fn bad_request(scim_type: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            scim_type: Some(scim_type),
            detail: detail.into(),
        }
    }

    /// 404 — resource not found.
    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, detail)
    }

    /// 401 — authentication failure.
    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, detail)
    }

    /// 403 — caller authenticated but lacks permission.
    pub fn forbidden(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, detail)
    }

    /// 409 + `scimType: uniqueness` — duplicate userName / externalId.
    pub fn uniqueness(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            scim_type: Some("uniqueness"),
            detail: detail.into(),
        }
    }

    /// 400 + `scimType: invalidFilter`.
    pub fn invalid_filter(detail: impl Into<String>) -> Self {
        Self::bad_request("invalidFilter", detail)
    }

    /// 400 + `scimType: invalidSyntax` — body did not parse.
    pub fn invalid_syntax(detail: impl Into<String>) -> Self {
        Self::bad_request("invalidSyntax", detail)
    }

    /// 400 + `scimType: invalidValue` — an attribute value is malformed.
    pub fn invalid_value(detail: impl Into<String>) -> Self {
        Self::bad_request("invalidValue", detail)
    }

    /// 400 + `scimType: invalidPath` — PATCH `path` is malformed.
    pub fn invalid_path(detail: impl Into<String>) -> Self {
        Self::bad_request("invalidPath", detail)
    }

    /// 500 — internal error. Detail is fixed ("internal error") to avoid
    /// leaking implementation details; real cause is logged via `tracing`.
    pub fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }
}

#[derive(Serialize)]
struct ScimErrorBody<'a> {
    schemas: [&'static str; 1],
    status: String,
    #[serde(rename = "scimType", skip_serializing_if = "Option::is_none")]
    scim_type: Option<&'a str>,
    detail: &'a str,
}

impl IntoResponse for ScimError {
    fn into_response(self) -> Response {
        let body = ScimErrorBody {
            schemas: [SCIM_ERROR_SCHEMA],
            status: self.status.as_u16().to_string(),
            scim_type: self.scim_type,
            detail: &self.detail,
        };
        let mut resp = (self.status, Json(body)).into_response();
        if let Ok(ct) = axum::http::HeaderValue::from_str("application/scim+json") {
            resp.headers_mut().insert(axum::http::header::CONTENT_TYPE, ct);
        }
        resp
    }
}

/// Maps a domain `IdentityError` to the closest SCIM error. Callers on
/// the SCIM edge should use this instead of the generic HTTP mapping so
/// the error envelope stays SCIM-shaped.
pub fn from_identity_error(err: &crate::identity::IdentityError) -> ScimError {
    use crate::identity::IdentityError;
    match err {
        IdentityError::UserNotFound | IdentityError::OrganizationNotFound => {
            ScimError::not_found("resource not found")
        }
        IdentityError::DuplicateEmail => {
            ScimError::uniqueness("userName/email already in use")
        }
        IdentityError::DuplicateScimExternalId => {
            ScimError::uniqueness("externalId already in use")
        }
        IdentityError::DuplicateOrgSlug => {
            ScimError::uniqueness("displayName collides with existing group")
        }
        IdentityError::InvalidInput { reason } => {
            ScimError::invalid_value(reason.clone())
        }
        IdentityError::RealmNotFound | IdentityError::RealmSuspended => {
            ScimError::forbidden("realm unavailable")
        }
        _ => {
            tracing::warn!(error = %err, "SCIM mapping to internal error");
            ScimError::internal()
        }
    }
}
