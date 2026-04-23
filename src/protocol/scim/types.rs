//! SCIM 2.0 wire types (RFC 7643).
//!
//! Only the attributes Hearth actually persists + the ones real IdPs
//! (Okta, Azure AD) emit are modeled. Unknown incoming attributes are
//! ignored via serde's default-permissive behavior; emitted resources
//! carry only the populated fields.

use serde::{Deserialize, Serialize};

/// The SCIM 2.0 User resource schema URN.
pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";

/// The SCIM 2.0 Group resource schema URN.
pub const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

/// The SCIM 2.0 list response schema URN.
pub const LIST_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

/// The SCIM 2.0 PATCH operation schema URN.
pub const PATCH_OP_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

/// Common `meta` sub-attribute (§3.1 of RFC 7643).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    /// Resource kind — `"User"` or `"Group"`.
    #[serde(rename = "resourceType")]
    pub resource_type: String,
    /// ISO 8601 creation timestamp.
    pub created: String,
    /// ISO 8601 last-modified timestamp.
    #[serde(rename = "lastModified")]
    pub last_modified: String,
    /// Canonical resource URL. Relative to the server base.
    pub location: String,
    /// Weak ETag used by SCIM clients for optimistic concurrency.
    pub version: String,
}

/// Structured user name (§4.1.1 of RFC 7643).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScimName {
    /// Full name as displayed (`{given} {family}`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    /// Last (family) name.
    #[serde(rename = "familyName", default, skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    /// First (given) name.
    #[serde(rename = "givenName", default, skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
}

/// A single email entry (§4.1.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimEmail {
    /// The email address.
    pub value: String,
    /// Whether this is the primary email. Only `primary: true` is
    /// persisted by Hearth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
    /// Email type (`"work"`, `"home"`). Accepted-and-ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
}

/// SCIM 2.0 User resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimUser {
    /// Schemas declared by the client or emitted on read.
    #[serde(default = "default_user_schemas")]
    pub schemas: Vec<String>,
    /// Server-assigned ID. Omitted on inbound POST, populated on read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Client-supplied external identifier (IdP's stable user key).
    #[serde(rename = "externalId", default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// Unique login identifier. Hearth treats this as the email address.
    #[serde(rename = "userName")]
    pub user_name: String,
    /// Optional display name (human label).
    #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Structured name components.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<ScimName>,
    /// Collection of email addresses. Hearth persists the primary one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<ScimEmail>,
    /// Whether the account is enabled. Maps onto `UserStatus::Active`.
    #[serde(default = "default_active")]
    pub active: bool,
    /// Server-populated metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,
}

fn default_user_schemas() -> Vec<String> {
    vec![USER_SCHEMA.to_string()]
}

const fn default_active() -> bool {
    true
}

/// A member reference inside a SCIM Group (§4.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimMember {
    /// The referenced user's ID.
    pub value: String,
    /// Member display name — optional hint, not authoritative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    /// Member type. Hearth only speaks `"User"`.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
}

/// SCIM 2.0 Group resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimGroup {
    /// Schemas declared by the client or emitted on read.
    #[serde(default = "default_group_schemas")]
    pub schemas: Vec<String>,
    /// Server-assigned ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Client-supplied external identifier.
    #[serde(rename = "externalId", default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// Group name as displayed.
    #[serde(rename = "displayName")]
    pub display_name: String,
    /// Member list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<ScimMember>,
    /// Server-populated metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,
}

fn default_group_schemas() -> Vec<String> {
    vec![GROUP_SCHEMA.to_string()]
}

/// A SCIM list response envelope (RFC 7644 §3.4.2).
#[derive(Debug, Clone, Serialize)]
pub struct ListResponse<T: Serialize> {
    /// Schema URN.
    pub schemas: [&'static str; 1],
    /// Total result count. Advisory — clients use it for pagination UX.
    #[serde(rename = "totalResults")]
    pub total_results: usize,
    /// Number of resources in this page.
    #[serde(rename = "itemsPerPage")]
    pub items_per_page: usize,
    /// 1-indexed start position of this page.
    #[serde(rename = "startIndex")]
    pub start_index: usize,
    /// The resources themselves.
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

impl<T: Serialize> ListResponse<T> {
    /// Builds a new list response from a resource slice plus pagination
    /// metadata.
    pub fn new(total: usize, start_index: usize, resources: Vec<T>) -> Self {
        Self {
            schemas: [LIST_RESPONSE_SCHEMA],
            total_results: total,
            items_per_page: resources.len(),
            start_index,
            resources,
        }
    }
}

/// A single PATCH operation (RFC 7644 §3.5.2).
#[derive(Debug, Clone, Deserialize)]
pub struct PatchOp {
    /// Operation verb: `"add"`, `"replace"`, or `"remove"` (case-insensitive).
    pub op: String,
    /// Optional JSON-pointer-ish path (e.g. `"active"`, `"name.familyName"`,
    /// `"members"`). Absent means "the root value".
    #[serde(default)]
    pub path: Option<String>,
    /// Operand — semantics depend on `op`.
    #[serde(default)]
    pub value: Option<serde_json::Value>,
}

/// The PATCH request envelope.
#[derive(Debug, Clone, Deserialize)]
pub struct PatchRequest {
    /// Schema URNs declared by the client. Not validated strictly — Okta
    /// and Azure occasionally send the message schema URN too.
    #[serde(default)]
    pub schemas: Vec<String>,
    /// The operations to apply, in order.
    #[serde(rename = "Operations", default)]
    pub operations: Vec<PatchOp>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_deserializes_okta_style_payload() {
        let payload = r#"{
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "alice@example.com",
            "externalId": "okta-abc",
            "name": {"givenName": "Alice", "familyName": "Example"},
            "emails": [{"value": "alice@example.com", "primary": true, "type": "work"}],
            "active": true
        }"#;
        let u: ScimUser = serde_json::from_str(payload).expect("parse");
        assert_eq!(u.user_name, "alice@example.com");
        assert_eq!(u.external_id.as_deref(), Some("okta-abc"));
        assert_eq!(u.name.as_ref().unwrap().given_name.as_deref(), Some("Alice"));
        assert_eq!(u.emails.len(), 1);
        assert!(u.active);
    }

    #[test]
    fn user_active_defaults_to_true_when_absent() {
        let payload = r#"{"userName": "a@b.c", "schemas": []}"#;
        let u: ScimUser = serde_json::from_str(payload).expect("parse");
        assert!(u.active);
    }

    #[test]
    fn group_deserializes_with_members() {
        let payload = r#"{
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Engineering",
            "members": [{"value": "user-uuid-1", "display": "Alice"}]
        }"#;
        let g: ScimGroup = serde_json::from_str(payload).expect("parse");
        assert_eq!(g.display_name, "Engineering");
        assert_eq!(g.members.len(), 1);
    }

    #[test]
    fn list_response_emits_envelope() {
        let resources: Vec<ScimUser> = vec![];
        let list = ListResponse::new(0, 1, resources);
        let json = serde_json::to_value(&list).expect("serialize");
        assert_eq!(json["totalResults"], 0);
        assert_eq!(json["startIndex"], 1);
        assert_eq!(json["schemas"][0], LIST_RESPONSE_SCHEMA);
    }

    #[test]
    fn patch_op_parses_simple_replace() {
        let payload = r#"{"op": "replace", "path": "active", "value": false}"#;
        let op: PatchOp = serde_json::from_str(payload).expect("parse");
        assert_eq!(op.op, "replace");
        assert_eq!(op.path.as_deref(), Some("active"));
        assert_eq!(op.value, Some(serde_json::json!(false)));
    }
}
