//! Hardcoded SCIM 2.0 discovery responses.
//!
//! These three endpoints advertise the server's capabilities, supported
//! schemas, and resource types (RFC 7644 §4). Clients read them to know
//! which operators and attributes Hearth accepts before sending writes.

use axum::response::IntoResponse;
use axum::Json;
use serde_json::json;

/// `GET /scim/v2/ServiceProviderConfig` — RFC 7644 §4.
///
/// Advertises capabilities. Phase 1 supports: PATCH, filtering (limited),
/// and bulk=false. Authentication is Bearer (admin tokens).
pub async fn service_provider_config() -> impl IntoResponse {
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
                "description": "Admin-scoped bearer token issued by Hearth.",
                "specUri": "https://www.rfc-editor.org/rfc/rfc6750"
            }
        ]
    }))
}

/// `GET /scim/v2/ResourceTypes` — RFC 7644 §4.
pub async fn resource_types() -> impl IntoResponse {
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
}

/// `GET /scim/v2/Schemas` — RFC 7643 §8.
pub async fn schemas() -> impl IntoResponse {
    Json(json!([user_schema(), group_schema()]))
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
