//! Entity ID newtypes for type-safe identification.
//!
//! Each ID type wraps a UUID and provides a prefixed Display format.
//! No `Deref` to inner type — access via `.as_uuid()` only.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Generates a newtype ID wrapper around `Uuid` with consistent behavior.
///
/// Each generated type gets:
/// - `new(Uuid)` and `generate()` constructors
/// - `as_uuid()` accessor (no `Deref`)
/// - Prefixed `Display` implementation
/// - Standard derives: `Clone`, `Debug`, `PartialEq`, `Eq`, `Hash`, `Serialize`, `Deserialize`
macro_rules! define_id_type {
    (
        $(#[$meta:meta])*
        $name:ident, $prefix:literal
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a new ID from an existing UUID.
            pub fn new(id: Uuid) -> Self {
                Self(id)
            }

            /// Generates a new random ID.
            pub fn generate() -> Self {
                Self(Uuid::new_v4())
            }

            /// Returns a reference to the inner UUID.
            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{}", $prefix, self.0)
            }
        }
    };
}

define_id_type!(
    /// Unique identifier for a realm. All storage operations require this.
    RealmId, "realm_"
);

define_id_type!(
    /// Unique identifier for a user within a realm.
    UserId, "user_"
);

define_id_type!(
    /// Unique identifier for an authentication session.
    SessionId, "session_"
);

define_id_type!(
    /// Unique identifier for an OAuth 2.0 client registration.
    ClientId, "client_"
);

define_id_type!(
    /// Unique identifier for an audit log event.
    AuditEventId, "audit_"
);

define_id_type!(
    /// Unique identifier for an organization within a realm.
    OrganizationId, "org_"
);

define_id_type!(
    /// Unique identifier for an organization invitation.
    InvitationId, "inv_"
);

define_id_type!(
    /// Unique identifier for an external Identity Provider (IdP) connector
    /// registered against a realm for social login / federated sign-in.
    ///
    /// Scoped to a single realm via the containing `RealmId`; the same
    /// `IdpId` value would not appear across realms in practice because
    /// each `register_idp` call generates a fresh UUID.
    IdpId, "idp_"
);

/// Validated RFC 8707 resource URI.
///
/// Must be absolute (scheme present), non-empty, and MUST NOT contain a
/// fragment component (fragment-bearing URIs are rejected at construction
/// to prevent resource-indicator collisions).
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Uri(String);

/// Error returned when a URI fails validation.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum UriError {
    #[error("invalid resource URI: {0}")]
    InvalidUri(String),
}

impl Uri {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Normalize the URI for storage-key hashing.
    ///
    /// Per RFC 3986 §6.2.2.1:
    /// - Lowercase scheme + host only (not path or query).
    /// - Strip default ports (443 for https, 80 for http).
    /// - Remove trailing slash on the authority+path portion.
    ///
    /// Returns the normalized form for hashing, NOT for display
    /// (the original exact string is stored separately).
    pub(crate) fn normalized(&self) -> String {
        let s = &self.0;
        let (scheme, rest) = match s.find("://") {
            Some(pos) => (&s[..pos], &s[pos + 3..]),
            None => return s.to_lowercase(),
        };
        let scheme_lower = scheme.to_lowercase();
        let (authority_and_path, _query) = match rest.find('?') {
            Some(pos) => (&rest[..pos], Some(&rest[pos..])),
            None => (rest, None),
        };
        let (authority, path) = match authority_and_path.find('/') {
            Some(pos) => (&rest[..pos], &authority_and_path[pos..]),
            None => (authority_and_path, "/"),
        };
        let authority_lower = authority.to_lowercase();
        let authority_no_default_port = strip_default_port(&authority_lower);
        let path_no_trailing = match path.strip_suffix('/') {
            Some(stripped) if stripped.len() > 1 => stripped,
            _ => path,
        };
        format!("{scheme_lower}://{authority_no_default_port}{path_no_trailing}")
    }

    /// SHA-256 first 12 hex characters of the normalized form.
    pub(crate) fn storage_hash(&self) -> String {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.normalized().as_bytes());
        let digest = hasher.finalize();
        hex::encode(&digest[..6])
    }
}

fn strip_default_port(authority: &str) -> &str {
    if let Some(stripped) = authority.strip_suffix(":443") {
        stripped
    } else if let Some(stripped) = authority.strip_suffix(":80") {
        stripped
    } else {
        authority
    }
}

impl TryFrom<String> for Uri {
    type Error = UriError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let trimmed = s.trim().to_string();
        if trimmed.is_empty() {
            return Err(UriError::InvalidUri(s));
        }
        if !trimmed.contains("://") {
            return Err(UriError::InvalidUri(s));
        }
        if trimmed.contains('#') {
            return Err(UriError::InvalidUri(s));
        }
        Ok(Self(trimmed))
    }
}

impl std::fmt::Display for Uri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn realm_id_creation_and_accessor() {
        let uuid = Uuid::new_v4();
        let id = RealmId::new(uuid);
        assert_eq!(*id.as_uuid(), uuid);
    }

    #[test]
    fn realm_id_equality_and_hashing() {
        let uuid = Uuid::new_v4();
        let id1 = RealmId::new(uuid);
        let id2 = RealmId::new(uuid);
        assert_eq!(id1, id2);

        let mut set = HashSet::new();
        set.insert(id1.clone());
        assert!(set.contains(&id2));

        let other = RealmId::generate();
        assert!(!set.contains(&other));
    }

    #[test]
    fn realm_id_display_shows_prefix() {
        let id = RealmId::generate();
        let display = format!("{id}");
        assert!(display.starts_with("realm_"), "got: {display}");
    }

    #[test]
    fn realm_id_serde_round_trip() {
        let id = RealmId::generate();
        let json = serde_json::to_string(&id).expect("serialize");
        let deserialized: RealmId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, deserialized);
    }

    #[test]
    fn user_id_basics() {
        let uuid = Uuid::new_v4();
        let id = UserId::new(uuid);
        assert_eq!(*id.as_uuid(), uuid);

        let display = format!("{id}");
        assert!(display.starts_with("user_"), "got: {display}");

        let json = serde_json::to_string(&id).expect("serialize");
        let deserialized: UserId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, deserialized);
    }

    #[test]
    fn session_id_basics() {
        let uuid = Uuid::new_v4();
        let id = SessionId::new(uuid);
        assert_eq!(*id.as_uuid(), uuid);

        let display = format!("{id}");
        assert!(display.starts_with("session_"), "got: {display}");

        let json = serde_json::to_string(&id).expect("serialize");
        let deserialized: SessionId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, deserialized);
    }

    #[test]
    fn organization_id_basics() {
        let uuid = Uuid::new_v4();
        let id = OrganizationId::new(uuid);
        assert_eq!(*id.as_uuid(), uuid);

        let display = format!("{id}");
        assert!(display.starts_with("org_"), "got: {display}");

        let json = serde_json::to_string(&id).expect("serialize");
        let deserialized: OrganizationId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, deserialized);
    }

    #[test]
    fn invitation_id_basics() {
        let uuid = Uuid::new_v4();
        let id = InvitationId::new(uuid);
        assert_eq!(*id.as_uuid(), uuid);

        let display = format!("{id}");
        assert!(display.starts_with("inv_"), "got: {display}");

        let json = serde_json::to_string(&id).expect("serialize");
        let deserialized: InvitationId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, deserialized);
    }

    #[test]
    fn idp_id_basics() {
        let uuid = Uuid::new_v4();
        let id = IdpId::new(uuid);
        assert_eq!(*id.as_uuid(), uuid);

        let display = format!("{id}");
        assert!(display.starts_with("idp_"), "got: {display}");

        let json = serde_json::to_string(&id).expect("serialize");
        let deserialized: IdpId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, deserialized);
    }

    #[test]
    fn idp_id_generate_is_unique() {
        let id1 = IdpId::generate();
        let id2 = IdpId::generate();
        assert_ne!(id1, id2);
    }

    // ===== Uri tests =====

    #[test]
    fn uri_valid_construction() {
        let uri = Uri::try_from("https://api.example.com/resource".to_string())
            .expect("valid URI should parse");
        assert_eq!(uri.as_str(), "https://api.example.com/resource");
    }

    #[test]
    fn uri_rejects_empty() {
        assert!(Uri::try_from("".to_string()).is_err());
    }

    #[test]
    fn uri_rejects_relative() {
        assert!(Uri::try_from("/relative/path".to_string()).is_err());
    }

    #[test]
    fn uri_rejects_fragment() {
        assert!(Uri::try_from("https://api.example.com#admin".to_string()).is_err());
    }

    #[test]
    fn uri_normalization_lowercases_scheme_and_host() {
        let uri = Uri::try_from("HTTPS://API.Example.COM/Path".to_string())
            .expect("valid URI");
        assert_eq!(
            uri.normalized(),
            "https://api.example.com/Path"
        );
    }

    #[test]
    fn uri_normalization_strips_default_ports() {
        let uri = Uri::try_from("https://api.example.com:443/data".to_string())
            .expect("valid URI");
        assert_eq!(uri.normalized(), "https://api.example.com/data");
    }

    #[test]
    fn uri_normalization_removes_trailing_slash() {
        let uri = Uri::try_from("https://api.example.com/v1/".to_string())
            .expect("valid URI");
        assert_eq!(uri.normalized(), "https://api.example.com/v1");
    }

    #[test]
    fn uri_normalization_preserves_path_case() {
        let uri = Uri::try_from("https://api.example.com/MyFiles".to_string())
            .expect("valid URI");
        assert_eq!(
            uri.normalized(),
            "https://api.example.com/MyFiles"
        );
    }

    #[test]
    fn uri_storage_hash_is_stable() {
        let uri = Uri::try_from("https://api.example.com/data".to_string())
            .expect("valid URI");
        let hash1 = uri.storage_hash();
        let hash2 = uri.storage_hash();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 12);
    }

    #[test]
    fn uri_serde_round_trip() {
        let uri = Uri::try_from("https://api.example.com".to_string())
            .expect("valid URI");
        let json = serde_json::to_string(&uri).expect("serialize");
        let deserialized: Uri = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(uri, deserialized);
    }
}
