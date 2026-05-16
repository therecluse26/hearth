//! Integration tests for cross-realm user migration (`migrate_from` / `copy_from`).
//!
//! Exercises `execute_cross_realm_migration` directly through the public
//! IdentityEngine + RbacEngine + StorageEngine trait surface.

mod common;

use hearth::config::MigrateConflictPolicy;
use hearth::identity::migration::cross_realm::{
    CrossRealmMigrateOptions, execute_cross_realm_migration,
};
use hearth::identity::{CleartextPassword, CreateRealmRequest, CreateUserRequest, IdentityEngine};
use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, RoleScopeKind, Scope, Subject};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_realm(identity: &dyn IdentityEngine, name: &str) -> hearth::core::RealmId {
    identity
        .create_realm(&CreateRealmRequest {
            name: name.to_string(),
            config: None,
        })
        .unwrap_or_else(|_| panic!("create realm {name}"))
        .id()
        .clone()
}

fn make_user(identity: &dyn IdentityEngine, realm: &hearth::core::RealmId, email: &str) -> hearth::identity::User {
    identity
        .create_user(
            realm,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: "Test".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .unwrap_or_else(|_| panic!("create user {email}"))
}

fn set_password(identity: &dyn IdentityEngine, realm: &hearth::core::RealmId, user_id: &hearth::core::UserId, password: &str) {
    identity
        .set_password(realm, user_id, &CleartextPassword::from_string(password.to_string()))
        .expect("set password");
}

fn default_opts(move_semantics: bool) -> CrossRealmMigrateOptions {
    CrossRealmMigrateOptions {
        move_semantics,
        users: true,
        orgs: true,
        on_conflict: MigrateConflictPolicy::Error,
    }
}

// ---------------------------------------------------------------------------
// Scenario 1: move — users and credentials present in destination, absent from source
// ---------------------------------------------------------------------------

#[tokio::test]
async fn move_copies_users_and_deletes_source() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let identity = h.identity();
    let rbac = h.rbac();
    let storage = h.storage();

    let src = make_realm(identity, "migration-move-src");
    let dst = make_realm(identity, "migration-move-dst");

    let user = make_user(identity, &src, "alice@example.com");
    set_password(identity, &src, user.id(), "hunter2");

    let report = execute_cross_realm_migration(
        identity, rbac, storage, &src, &dst, "migration-move-src", &default_opts(true),
    )
    .expect("migration should succeed");

    assert_eq!(report.migrated, 1);
    assert_eq!(report.skipped, 0);

    // User must exist in destination.
    let dst_user = identity
        .get_user(&dst, user.id())
        .expect("get dst user")
        .expect("user should be in dst realm");
    assert_eq!(dst_user.email(), "alice@example.com");

    // Password must verify in destination.
    let ok = identity
        .verify_password(&dst, user.id(), &CleartextPassword::from_string("hunter2".to_string()))
        .expect("verify dst password");
    assert!(ok, "password should verify in destination realm");

    // Source user record must be gone (move semantics).
    let src_user = identity
        .get_user(&src, user.id())
        .expect("get src user");
    assert!(src_user.is_none(), "user should be removed from source after move");

    // Email index must be gone from source.
    let email_key = format!("usr:email:alice@example.com");
    let src_email = storage.get(&src, email_key.as_bytes()).expect("storage get");
    assert!(src_email.is_none(), "email index must be removed from source");
}

// ---------------------------------------------------------------------------
// Scenario 2: copy — source left intact
// ---------------------------------------------------------------------------

#[tokio::test]
async fn copy_leaves_source_intact() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let identity = h.identity();
    let rbac = h.rbac();
    let storage = h.storage();

    let src = make_realm(identity, "migration-copy-src");
    let dst = make_realm(identity, "migration-copy-dst");

    let user = make_user(identity, &src, "bob@example.com");
    set_password(identity, &src, user.id(), "password123");

    let report = execute_cross_realm_migration(
        identity, rbac, storage, &src, &dst, "migration-copy-src", &default_opts(false),
    )
    .expect("copy should succeed");

    assert_eq!(report.migrated, 1);

    // User in destination.
    assert!(identity.get_user(&dst, user.id()).expect("dst get").is_some());

    // User still in source (copy semantics).
    assert!(
        identity.get_user(&src, user.id()).expect("src get").is_some(),
        "user must remain in source after copy"
    );
}

// ---------------------------------------------------------------------------
// Scenario 3: RBAC assignments translated by role name
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rbac_assignments_translated_by_role_name() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let identity = h.identity();
    let rbac = h.rbac();
    let storage = h.storage();

    let src = make_realm(identity, "rbac-src");
    let dst = make_realm(identity, "rbac-dst");

    // Create same-named role in both realms.
    let src_role = rbac
        .create_role(
            &src,
            &CreateRoleRequest {
                name: "editor".to_string(),
                description: Some("Editor role".to_string()),
                permissions: vec![],
                scope_kind: RoleScopeKind::Realm,
                parent_roles: vec![],
            },
        )
        .expect("create src role");
    let dst_role = rbac
        .create_role(
            &dst,
            &CreateRoleRequest {
                name: "editor".to_string(),
                description: Some("Editor role".to_string()),
                permissions: vec![],
                scope_kind: RoleScopeKind::Realm,
                parent_roles: vec![],
            },
        )
        .expect("create dst role");

    let user = make_user(identity, &src, "carol@example.com");

    // Assign the source role to the user.
    rbac.assign_role(
        &src,
        &AssignRoleRequest {
            role_id: src_role.id,
            subject: Subject::User(user.id().clone()),
            scope: Scope::Realm,
            assigned_by: None,
        },
    )
    .expect("assign src role");

    let report = execute_cross_realm_migration(
        identity, rbac, storage, &src, &dst, "rbac-src", &default_opts(true),
    )
    .expect("migration should succeed");

    assert_eq!(report.role_assignments_translated, 1);
    assert_eq!(report.role_assignments_skipped, 0);

    // Verify the user has the destination role.
    let dst_assignments = rbac
        .list_user_assignments(&dst, user.id())
        .expect("list dst assignments");
    assert!(
        dst_assignments.iter().any(|a| a.role_id == dst_role.id),
        "user should have the translated editor role in destination"
    );
}

// ---------------------------------------------------------------------------
// Scenario 4: org-scoped assignments stripped when orgs: false
// ---------------------------------------------------------------------------

#[tokio::test]
async fn org_scoped_assignments_stripped_when_orgs_false() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let identity = h.identity();
    let rbac = h.rbac();
    let storage = h.storage();

    let src = make_realm(identity, "orgstrip-src");
    let dst = make_realm(identity, "orgstrip-dst");

    let src_role = rbac
        .create_role(
            &src,
            &CreateRoleRequest {
                name: "member".to_string(),
                description: None,
                permissions: vec![],
                scope_kind: RoleScopeKind::Realm,
                parent_roles: vec![],
            },
        )
        .expect("create role");
    // Same role in dst (so name translation would succeed if we tried).
    rbac.create_role(
        &dst,
        &CreateRoleRequest {
            name: "member".to_string(),
            description: None,
            permissions: vec![],
            scope_kind: RoleScopeKind::Realm,
            parent_roles: vec![],
        },
    )
    .expect("create dst role");

    let org_id = hearth::core::OrganizationId::generate();

    let user = make_user(identity, &src, "dave@example.com");

    // Assign an org-scoped role to the user.
    rbac.assign_role(
        &src,
        &AssignRoleRequest {
            role_id: src_role.id,
            subject: Subject::User(user.id().clone()),
            scope: Scope::Org { org_id },
            assigned_by: None,
        },
    )
    .expect("assign org-scoped role");

    let opts = CrossRealmMigrateOptions {
        move_semantics: true,
        users: true,
        orgs: false, // <-- orgs disabled
        on_conflict: MigrateConflictPolicy::Error,
    };

    let report = execute_cross_realm_migration(
        identity, rbac, storage, &src, &dst, "orgstrip-src", &opts,
    )
    .expect("migration should succeed");

    // Org-scoped assignment should have been skipped.
    assert_eq!(report.role_assignments_skipped, 1, "org-scoped assignment should be skipped");
    assert_eq!(report.role_assignments_translated, 0);
}

// ---------------------------------------------------------------------------
// Scenario 5: on_conflict: error — blocks with full conflict list
// ---------------------------------------------------------------------------

#[tokio::test]
async fn on_conflict_error_fails_with_conflict_list() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let identity = h.identity();
    let rbac = h.rbac();
    let storage = h.storage();

    let src = make_realm(identity, "conflict-src");
    let dst = make_realm(identity, "conflict-dst");

    // Create the same user (by email) in both realms.
    make_user(identity, &src, "eve@example.com");
    make_user(identity, &src, "frank@example.com");
    // Pre-exist eve in destination.
    make_user(identity, &dst, "eve@example.com");

    let result = execute_cross_realm_migration(
        identity, rbac, storage, &src, &dst, "conflict-src",
        &CrossRealmMigrateOptions {
            move_semantics: true,
            users: true,
            orgs: true,
            on_conflict: MigrateConflictPolicy::Error,
        },
    );

    assert!(result.is_err(), "should fail when conflict exists");
    let conflict = result.unwrap_err();
    assert!(conflict.emails.contains(&"eve@example.com".to_string()));
    // frank has no conflict — only eve should be listed.
    assert!(!conflict.emails.contains(&"frank@example.com".to_string()));
}

// ---------------------------------------------------------------------------
// Scenario 6: on_conflict: skip — conflicting users skipped, rest migrated
// ---------------------------------------------------------------------------

#[tokio::test]
async fn on_conflict_skip_migrates_non_conflicting() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let identity = h.identity();
    let rbac = h.rbac();
    let storage = h.storage();

    let src = make_realm(identity, "skip-src");
    let dst = make_realm(identity, "skip-dst");

    let conflicting = make_user(identity, &src, "grace@example.com");
    let non_conflicting = make_user(identity, &src, "heidi@example.com");

    // Pre-exist grace in destination.
    make_user(identity, &dst, "grace@example.com");

    let report = execute_cross_realm_migration(
        identity, rbac, storage, &src, &dst, "skip-src",
        &CrossRealmMigrateOptions {
            move_semantics: true,
            users: true,
            orgs: true,
            on_conflict: MigrateConflictPolicy::Skip,
        },
    )
    .expect("skip policy should not return Err");

    assert_eq!(report.skipped, 1, "conflicting user should be skipped");
    assert_eq!(report.migrated, 1, "non-conflicting user should be migrated");

    // Heidi must be in destination.
    assert!(
        identity.get_user(&dst, non_conflicting.id()).expect("get heidi dst").is_some(),
        "heidi should be in destination"
    );

    // Grace's original record in dst is preserved (not overwritten).
    let dst_grace = identity
        .get_user_by_email(&dst, "grace@example.com")
        .expect("get grace dst")
        .expect("grace should still be in dst");
    // The destination grace user was created independently — her ID differs from src grace.
    assert_ne!(dst_grace.id(), conflicting.id());
}

// ---------------------------------------------------------------------------
// Scenario 7: idempotent resume — already-completed migration is a no-op
// ---------------------------------------------------------------------------

#[tokio::test]
async fn completed_migration_is_idempotent() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let identity = h.identity();
    let rbac = h.rbac();
    let storage = h.storage();

    let src = make_realm(identity, "idempotent-src");
    let dst = make_realm(identity, "idempotent-dst");

    make_user(identity, &src, "ivan@example.com");

    let r1 = execute_cross_realm_migration(
        identity, rbac, storage, &src, &dst, "idempotent-src", &default_opts(true),
    )
    .expect("first run");
    assert_eq!(r1.migrated, 1);

    // Second run: completed marker present → returns immediately with zero counts.
    let r2 = execute_cross_realm_migration(
        identity, rbac, storage, &src, &dst, "idempotent-src", &default_opts(true),
    )
    .expect("second run");
    assert_eq!(r2.migrated, 0, "second run should be a no-op due to completed marker");
}
