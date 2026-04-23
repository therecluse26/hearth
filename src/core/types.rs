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
}
