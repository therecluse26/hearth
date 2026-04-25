//! Identity type conversions: domain <-> proto wire types.

use crate::identity::{self as domain, UserStatus as DomainUserStatus};
use crate::protocol::proto::identity::v1 as pb;

// ==================== User ====================

impl From<&domain::User> for pb::User {
    fn from(u: &domain::User) -> Self {
        Self {
            id: u.id().as_uuid().to_string(),
            email: u.email().to_string(),
            display_name: u.display_name().to_string(),
            status: domain_user_status_to_proto(u.status()).into(),
            created_at: u.created_at().as_micros(),
            updated_at: u.updated_at().as_micros(),
            first_name: u.first_name().to_string(),
            last_name: u.last_name().to_string(),
        }
    }
}

// ==================== UserStatus ====================

/// Converts domain `UserStatus` to proto enum value.
pub(crate) fn domain_user_status_to_proto(s: DomainUserStatus) -> pb::UserStatus {
    match s {
        DomainUserStatus::Active => pb::UserStatus::Active,
        DomainUserStatus::Disabled => pb::UserStatus::Disabled,
        DomainUserStatus::PendingVerification => pb::UserStatus::PendingVerification,
    }
}

/// Converts proto `UserStatus` i32 to domain `UserStatus`.
///
/// Returns `None` for `UNSPECIFIED` or unknown values.
pub(crate) fn proto_user_status_to_domain(v: i32) -> Option<DomainUserStatus> {
    match pb::UserStatus::try_from(v).ok()? {
        pb::UserStatus::Unspecified => None,
        pb::UserStatus::Active => Some(DomainUserStatus::Active),
        pb::UserStatus::Disabled => Some(DomainUserStatus::Disabled),
        pb::UserStatus::PendingVerification => Some(DomainUserStatus::PendingVerification),
    }
}

// ==================== CreateUserRequest ====================

impl From<pb::CreateUserRequest> for domain::CreateUserRequest {
    fn from(r: pb::CreateUserRequest) -> Self {
        Self {
            email: r.email,
            display_name: r.display_name,
            first_name: r.first_name,
            last_name: r.last_name,
        }
    }
}

// ==================== UpdateUserRequest ====================

impl From<pb::UpdateUserRequest> for domain::UpdateUserRequest {
    fn from(r: pb::UpdateUserRequest) -> Self {
        Self {
            email: r.email,
            display_name: r.display_name,
            first_name: r.first_name,
            last_name: r.last_name,
            status: r.status.and_then(proto_user_status_to_domain),
            attributes: None,
        }
    }
}

// ==================== Realm ====================

impl From<&domain::Realm> for pb::Realm {
    fn from(t: &domain::Realm) -> Self {
        Self {
            id: t.id().as_uuid().to_string(),
            name: t.name().to_string(),
            status: domain_realm_status_to_proto(t.status()).into(),
            config: Some(pb::RealmConfig::from(t.config())),
            created_at: t.created_at().as_micros(),
            updated_at: t.updated_at().as_micros(),
        }
    }
}

// ==================== RealmStatus ====================

/// Converts domain `RealmStatus` to proto enum value.
pub(crate) fn domain_realm_status_to_proto(s: domain::RealmStatus) -> pb::RealmStatus {
    match s {
        domain::RealmStatus::Active => pb::RealmStatus::Active,
        // Archived behaves like Suspended on the wire (no proto value yet).
        domain::RealmStatus::Suspended | domain::RealmStatus::Archived => {
            pb::RealmStatus::Suspended
        }
    }
}

/// Converts proto `RealmStatus` i32 to domain `RealmStatus`.
///
/// Returns `None` for `UNSPECIFIED` or unknown values.
pub(crate) fn proto_realm_status_to_domain(v: i32) -> Option<domain::RealmStatus> {
    match pb::RealmStatus::try_from(v).ok()? {
        pb::RealmStatus::Unspecified => None,
        pb::RealmStatus::Active => Some(domain::RealmStatus::Active),
        pb::RealmStatus::Suspended => Some(domain::RealmStatus::Suspended),
    }
}

// ==================== RealmConfig ====================

impl From<&domain::RealmConfig> for pb::RealmConfig {
    fn from(c: &domain::RealmConfig) -> Self {
        Self {
            session_ttl_micros: c.session_ttl_micros,
            password_memory_cost: c.password_memory_cost,
            password_time_cost: c.password_time_cost,
        }
    }
}

impl From<pb::RealmConfig> for domain::RealmConfig {
    fn from(c: pb::RealmConfig) -> Self {
        Self {
            session_ttl_micros: c.session_ttl_micros,
            password_memory_cost: c.password_memory_cost,
            password_time_cost: c.password_time_cost,
            ..Self::default()
        }
    }
}

// ==================== CreateRealmRequest ====================

impl From<pb::CreateRealmRequest> for domain::CreateRealmRequest {
    fn from(r: pb::CreateRealmRequest) -> Self {
        Self {
            name: r.name,
            config: r.config.map(domain::RealmConfig::from),
        }
    }
}

// ==================== UpdateRealmRequest ====================

impl From<pb::UpdateRealmRequest> for domain::UpdateRealmRequest {
    fn from(r: pb::UpdateRealmRequest) -> Self {
        Self {
            name: r.name,
            status: r.status.and_then(proto_realm_status_to_domain),
            config: r.config.map(domain::RealmConfig::from),
        }
    }
}

// ==================== Page ====================

/// Converts a domain `Page<User>` to a proto `UserPage`.
pub(crate) fn user_page_to_proto(page: &domain::Page<domain::User>) -> pb::UserPage {
    pb::UserPage {
        items: page.items.iter().map(pb::User::from).collect(),
        next_cursor: page.next_cursor.clone(),
    }
}

/// Converts a domain `Page<Realm>` to a proto `RealmPage`.
pub(crate) fn realm_page_to_proto(page: &domain::Page<domain::Realm>) -> pb::RealmPage {
    pb::RealmPage {
        items: page.items.iter().map(pb::Realm::from).collect(),
        next_cursor: page.next_cursor.clone(),
    }
}

// ==================== BulkResult ====================

/// Converts a domain `BulkResult<User>` to a proto `BulkResultEntry`.
pub(crate) fn user_bulk_result_to_proto(
    r: &domain::BulkResult<domain::User>,
) -> pb::BulkResultEntry {
    match &r.result {
        Ok(user) => pb::BulkResultEntry {
            #[allow(clippy::cast_possible_truncation)]
            index: r.index as u32,
            success: true,
            user: Some(pb::User::from(user)),
            error: None,
        },
        Err(err) => pb::BulkResultEntry {
            #[allow(clippy::cast_possible_truncation)]
            index: r.index as u32,
            success: false,
            user: None,
            error: Some(err.clone()),
        },
    }
}

/// Converts a bulk delete/disable result to a proto `BulkResultEntry`.
pub(crate) fn void_bulk_result_to_proto(r: &domain::BulkResult<()>) -> pb::BulkResultEntry {
    match &r.result {
        Ok(()) => pb::BulkResultEntry {
            #[allow(clippy::cast_possible_truncation)]
            index: r.index as u32,
            success: true,
            user: None,
            error: None,
        },
        Err(err) => pb::BulkResultEntry {
            #[allow(clippy::cast_possible_truncation)]
            index: r.index as u32,
            success: false,
            user: None,
            error: Some(err.clone()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{RealmId, Timestamp, UserId};

    #[test]
    fn user_domain_to_proto_round_trip() {
        let user = domain::User::new(
            UserId::generate(),
            "alice@example.com".to_string(),
            "Alice".to_string(),
            "Alice".to_string(),
            "Smith".to_string(),
            DomainUserStatus::Active,
            Timestamp::from_micros(1_000_000),
            Timestamp::from_micros(2_000_000),
        );

        let proto = pb::User::from(&user);
        assert_eq!(proto.id, user.id().as_uuid().to_string());
        assert_eq!(proto.email, "alice@example.com");
        assert_eq!(proto.display_name, "Alice");
        assert_eq!(proto.status, pb::UserStatus::Active as i32);
        assert_eq!(proto.created_at, 1_000_000);
        assert_eq!(proto.updated_at, 2_000_000);

        // Verify JSON serialization matches expected field names and enum format
        let json: serde_json::Value = serde_json::to_value(&proto).expect("serialize");
        assert_eq!(json["status"], "USER_STATUS_ACTIVE");
        assert_eq!(json["display_name"], "Alice");
    }

    #[test]
    fn user_status_round_trip() {
        for (domain_status, proto_status) in [
            (DomainUserStatus::Active, pb::UserStatus::Active),
            (DomainUserStatus::Disabled, pb::UserStatus::Disabled),
            (
                DomainUserStatus::PendingVerification,
                pb::UserStatus::PendingVerification,
            ),
        ] {
            let proto = domain_user_status_to_proto(domain_status);
            assert_eq!(proto, proto_status);

            let back = proto_user_status_to_domain(proto as i32).expect("valid");
            assert_eq!(back, domain_status);
        }
    }

    #[test]
    fn unspecified_user_status_returns_none() {
        assert!(proto_user_status_to_domain(0).is_none());
    }

    #[test]
    fn realm_domain_to_proto_round_trip() {
        let realm = domain::Realm::new(
            RealmId::generate(),
            "Acme Corp".to_string(),
            domain::RealmStatus::Active,
            domain::RealmConfig {
                session_ttl_micros: Some(3_600_000_000),
                ..domain::RealmConfig::default()
            },
            Timestamp::from_micros(1_000_000),
            Timestamp::from_micros(2_000_000),
        );

        let proto = pb::Realm::from(&realm);
        assert_eq!(proto.id, realm.id().as_uuid().to_string());
        assert_eq!(proto.name, "Acme Corp");
        assert_eq!(proto.status, pb::RealmStatus::Active as i32);
        assert_eq!(
            proto
                .config
                .as_ref()
                .expect("config present")
                .session_ttl_micros,
            Some(3_600_000_000)
        );

        // Verify JSON serialization
        let json: serde_json::Value = serde_json::to_value(&proto).expect("serialize");
        assert_eq!(json["status"], "REALM_STATUS_ACTIVE");
    }

    #[test]
    fn create_user_request_conversion() {
        let proto_req = pb::CreateUserRequest {
            email: "bob@example.com".to_string(),
            display_name: "Bob".to_string(),
            ..Default::default()
        };
        let domain_req = domain::CreateUserRequest::from(proto_req);
        assert_eq!(domain_req.email, "bob@example.com");
        assert_eq!(domain_req.display_name, "Bob");
    }

    #[test]
    fn update_user_request_conversion() {
        let proto_req = pb::UpdateUserRequest {
            email: Some("new@example.com".to_string()),
            display_name: None,
            status: Some(pb::UserStatus::Disabled as i32),
            ..Default::default()
        };
        let domain_req = domain::UpdateUserRequest::from(proto_req);
        assert_eq!(domain_req.email.as_deref(), Some("new@example.com"));
        assert!(domain_req.display_name.is_none());
        assert_eq!(domain_req.status, Some(DomainUserStatus::Disabled));
    }

    #[test]
    fn realm_config_round_trip() {
        let domain_cfg = domain::RealmConfig {
            session_ttl_micros: Some(7_200_000_000),
            password_memory_cost: Some(65536),
            password_time_cost: Some(3),
            ..domain::RealmConfig::default()
        };
        let proto_cfg = pb::RealmConfig::from(&domain_cfg);
        let back = domain::RealmConfig::from(proto_cfg);
        assert_eq!(domain_cfg, back);
    }

    /// Helper: parse a UUID string into a `UserId`.
    fn parse_user_id(s: &str) -> Option<UserId> {
        uuid::Uuid::parse_str(s).ok().map(UserId::new)
    }

    #[test]
    fn parse_user_id_valid() {
        let uuid = uuid::Uuid::new_v4();
        let id = parse_user_id(&uuid.to_string()).expect("valid");
        assert_eq!(*id.as_uuid(), uuid);
    }

    #[test]
    fn parse_user_id_invalid() {
        assert!(parse_user_id("not-a-uuid").is_none());
    }
}
