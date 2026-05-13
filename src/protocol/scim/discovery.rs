//! Hardcoded SCIM 2.0 discovery responses.
//!
//! These three endpoints advertise the server's capabilities, supported
//! schemas, and resource types (RFC 7644 §4). Clients read them to know
//! which operators and attributes Hearth accepts before sending writes.

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::protocol::http::{extract_admin_auth, AppState};
use crate::protocol::scim::error::ScimError;

fn authenticate(headers: &HeaderMap, state: &AppState) -> Result<(), ScimError> {
    extract_admin_auth(headers, state)
        .map(|_| ())
        .map_err(|(status, body)| {
            let detail = body
                .0
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("authentication failed")
                .to_string();
            ScimError::new(status, detail)
        })
}

/// `GET /scim/v2/ServiceProviderConfig` — RFC 7644 §4.
///
/// Advertises capabilities. Phase 1 supports: PATCH, filtering (limited),
/// and bulk=false. Authentication is a realm-scoped admin token.
pub async fn service_provider_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(err) = authenticate(&headers, &state) {
        return err.into_response();
    }

    Json(json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://hearth.dev/docs/scim",
        "patch":         { "supported": true  },
        "bulk":          { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter":        { "supported": true,  "maxResults": 200 },
        "changePassword":{ "supported": false },
        "sort":          { "supported": false },
        "etag":          { "supported": true  },
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "Bearer Token",
                "description": "Realm-scoped SCIM bearer token configured in Hearth.",
                "specUri": "https://www.rfc-editor.org/rfc/rfc6750"
            }
        ]
    }))
    .into_response()
}

/// `GET /scim/v2/ResourceTypes` — RFC 7644 §4.
pub async fn resource_types(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(err) = authenticate(&headers, &state) {
        return err.into_response();
    }

    Json(json!([
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "description": "A Hearth user.",
            "schema": crate::protocol::scim::types::USER_SCHEMA
        },
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "description": "A Hearth organization (SCIM Group).",
            "schema": crate::protocol::scim::types::GROUP_SCHEMA
        }
    ]))
    .into_response()
}

/// `GET /scim/v2/Schemas` — RFC 7643 §8.
pub async fn schemas(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(err) = authenticate(&headers, &state) {
        return err.into_response();
    }

    Json(json!([user_schema(), group_schema()])).into_response()
}

fn user_schema() -> serde_json::Value {
    json!({
        "id": crate::protocol::scim::types::USER_SCHEMA,
        "name": "User",
        "description": "Hearth User resource.",
        "attributes": [
            {"name": "userName", "type": "string", "required": true,  "uniqueness": "server", "mutability": "readWrite"},
            {"name": "externalId","type": "string", "required": false, "uniqueness": "server", "mutability": "readWrite"},
            {"name": "displayName","type": "string", "required": false, "mutability": "readWrite"},
            {"name": "active",    "type": "boolean", "required": false, "mutability": "readWrite"},
            {"name": "name",      "type": "complex", "required": false,
             "subAttributes": [
                 {"name": "givenName",  "type": "string", "mutability": "readWrite"},
                 {"name": "familyName", "type": "string", "mutability": "readWrite"}
             ]},
            {"name": "emails", "type": "complex", "multiValued": true,
             "subAttributes": [
                 {"name": "value",   "type": "string"},
                 {"name": "primary", "type": "boolean"},
                 {"name": "type",    "type": "string"}
             ]}
        ]
    })
}

fn group_schema() -> serde_json::Value {
    json!({
        "id": crate::protocol::scim::types::GROUP_SCHEMA,
        "name": "Group",
        "description": "Hearth organization exposed as a SCIM Group.",
        "attributes": [
            {"name": "displayName","type": "string", "required": true, "uniqueness": "none", "mutability": "readWrite"},
            {"name": "externalId", "type": "string", "required": false, "uniqueness": "server", "mutability": "readWrite"},
            {"name": "members", "type": "complex", "multiValued": true, "mutability": "readWrite",
             "subAttributes": [
                 {"name": "value",   "type": "string"},
                 {"name": "display", "type": "string"},
                 {"name": "type",    "type": "string"}
             ]}
        ]
    })
}
