//! Tests for user-level permission grant/revoke paths (AUTHZ_EXPANSION gap #6)
//! and `AuditAction` variants `UserPermissionGranted` / `UserPermissionRevoked`.

mod common;

use hearth::audit::AuditAction;
use hearth::core::{RealmId, Timestamp, UserId};
use hearth::rbac::{Permission, RbacEngine, Scope, UserPermissionGrant};

// ---------------------------------------------------------------------------
// AuditAction round-trips
// ---------------------------------------------------------------------------

#[test]
fn audit_action_user_permission_granted_as_str_round_trip() {
    let action = AuditAction::UserPermissionGranted;
    assert_eq!(action.as_str(), "user_permission_granted");
    let parsed: AuditAction = "user_permission_granted".parse().expect("parse");
    assert_eq!(parsed, AuditAction::UserPermissionGranted);
}

#[test]
fn audit_action_user_permission_revoked_as_str_round_trip() {
    let action = AuditAction::UserPermissionRevoked;
    assert_eq!(action.as_str(), "user_permission_revoked");
    let parsed: AuditAction = "user_permission_revoked".parse().expect("parse");
    assert_eq!(parsed, AuditAction::UserPermissionRevoked);
}

#[test]
fn audit_action_display_delegates_to_as_str() {
    assert_eq!(
        format!("{}", AuditAction::UserPermissionGranted),
        "user_permission_granted"
    );
    assert_eq!(
        format!("{}", AuditAction::UserPermissionRevoked),
        "user_permission_revoked"
    );
}

// ---------------------------------------------------------------------------
// grant_user_permission / revoke_user_permission
// ---------------------------------------------------------------------------

fn realm_grant(realm: &RealmId, user: &UserId, perm: &Permission) -> UserPermissionGrant {
    UserPermissionGrant {
        realm_id: realm.clone(),
        user_id: user.clone(),
        permission: perm.clone(),
        scope: Scope::Realm,
        granted_at: Timestamp::from_micros(1_000_000),
        granted_by: None,
    }
}

#[tokio::test]
async fn grant_user_permission_returns_identical_grant() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user = UserId::generate();
    let perm = Permission::new("docs.view").expect("valid perm");

    let grant = realm_grant(&realm, &user, &perm);
    let returned = h
        .rbac()
        .grant_user_permission(&realm, &grant)
        .expect("grant");

    assert_eq!(returned.user_id, user);
    assert_eq!(returned.permission, perm);
    assert!(matches!(returned.scope, Scope::Realm));
}

#[tokio::test]
async fn grant_user_permission_appears_in_list() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user = UserId::generate();
    let perm = Permission::new("docs.view").expect("valid perm");

    h.rbac()
        .grant_user_permission(&realm, &realm_grant(&realm, &user, &perm))
        .expect("grant");

    let list = h.rbac().list_user_permissions(&realm, &user).expect("list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].permission, perm);
}

#[tokio::test]
async fn revoke_user_permission_clears_grant() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user = UserId::generate();
    let perm = Permission::new("docs.view").expect("valid perm");

    h.rbac()
        .grant_user_permission(&realm, &realm_grant(&realm, &user, &perm))
        .expect("grant");
    h.rbac()
        .revoke_user_permission(&realm, &user, &perm, &Scope::Realm)
        .expect("revoke");

    let list = h.rbac().list_user_permissions(&realm, &user).expect("list");
    assert!(list.is_empty(), "list must be empty after revoke");
}

#[tokio::test]
async fn grant_org_scoped_permission_appears_in_list() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user = UserId::generate();
    let org = hearth::core::OrganizationId::generate();
    let perm = Permission::new("org.billing").expect("valid perm");

    let grant = UserPermissionGrant {
        realm_id: realm.clone(),
        user_id: user.clone(),
        permission: perm.clone(),
        scope: Scope::Org {
            org_id: org.clone(),
        },
        granted_at: Timestamp::from_micros(1_000_000),
        granted_by: None,
    };
    h.rbac()
        .grant_user_permission(&realm, &grant)
        .expect("grant org-scoped");

    let list = h.rbac().list_user_permissions(&realm, &user).expect("list");
    assert_eq!(list.len(), 1);
    assert!(matches!(&list[0].scope, Scope::Org { org_id } if *org_id == org));
}
