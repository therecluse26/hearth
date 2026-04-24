//! Concurrent role-assignment writes.
//!
//! Oracle invariant (from `MIGRATE_TO_RBAC.md` § 9 risk table):
//! "Concurrent role-assignment writes produce no data corruption — after
//!  quiescence, `resolve_permissions` returns a set consistent with some
//!  serializable order of the ops, with no partial index writes or
//!  dangling assignments."
//!
//! Uses `std::thread::spawn` (like `realm_concurrent_io.rs`) to avoid
//! pulling tokio into the simulation crate's dependency footprint.

use std::sync::Arc;

use hearth::core::{Clock, RealmId, SystemClock, UserId};
use hearth::rbac::{
    AssignRoleRequest, AssignmentId, CreateRoleRequest, EmbeddedRbacEngine, Permission, RbacEngine,
    RoleId, Scope, Subject,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

fn perms(list: &[&str]) -> Vec<Permission> {
    list.iter()
        .map(|p| Permission::new(*p).expect("valid"))
        .collect()
}

fn open() -> (Arc<dyn RbacEngine>, RealmId) {
    let dir = tempfile::tempdir().expect("tmp");
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let storage =
        Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let rbac =
        Arc::new(EmbeddedRbacEngine::new(Arc::clone(&storage), clock)) as Arc<dyn RbacEngine>;
    let realm = RealmId::generate();
    // Leak tempdir so storage handles stay valid beyond the caller.
    std::mem::forget(dir);
    (rbac, realm)
}

#[test]
fn concurrent_assign_unassign_converge_to_consistent_set() {
    let (rbac, realm) = open();

    // Pre-seed 4 distinct roles (serial).
    let mut roles: Vec<RoleId> = Vec::new();
    for i in 0..4 {
        let r = rbac
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: format!("r{i}"),
                    description: None,
                    permissions: perms(&[&format!("p.r{i}")]),
                    parent_roles: vec![],
                },
            )
            .expect("create role");
        roles.push(r.id);
    }

    let user = UserId::generate();

    // Concurrent assigns.
    let mut assign_handles = Vec::new();
    for role_id in roles.iter().cloned() {
        let rbac = Arc::clone(&rbac);
        let realm = realm.clone();
        let user = user.clone();
        assign_handles.push(std::thread::spawn(move || {
            rbac.assign_role(
                &realm,
                &AssignRoleRequest {
                    subject: Subject::User(user),
                    role_id,
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign ok")
        }));
    }

    // Concurrent resolves alongside the writes — must not panic or tear.
    let mut resolve_handles = Vec::new();
    for _ in 0..8 {
        let rbac = Arc::clone(&rbac);
        let realm = realm.clone();
        let user = user.clone();
        resolve_handles.push(std::thread::spawn(move || {
            let _ = rbac
                .resolve_permissions(&user, &realm, None, None)
                .expect("resolve ok");
        }));
    }

    let assigned: Vec<_> = assign_handles
        .into_iter()
        .map(|h| h.join().expect("thread join"))
        .collect();
    for h in resolve_handles {
        h.join().expect("thread join");
    }

    // Post-quiescence: all four permissions visible.
    let resolved = rbac
        .resolve_permissions(&user, &realm, None, None)
        .expect("final resolve");
    let names: Vec<&str> = resolved
        .permissions
        .iter()
        .map(Permission::as_str)
        .collect();
    assert_eq!(names.len(), 4, "expected 4 perms; got {names:?}");
    for i in 0..4 {
        let want = format!("p.r{i}");
        assert!(names.contains(&want.as_str()), "missing {want}");
    }

    // Concurrent unassign — converge to empty.
    let mut unassign_handles = Vec::new();
    for a in assigned {
        let rbac = Arc::clone(&rbac);
        let realm = realm.clone();
        let id: AssignmentId = a.id;
        unassign_handles.push(std::thread::spawn(move || {
            rbac.unassign_role(&realm, &id).expect("unassign ok");
        }));
    }
    for h in unassign_handles {
        h.join().expect("thread join");
    }

    let resolved = rbac
        .resolve_permissions(&user, &realm, None, None)
        .expect("final resolve after unassign");
    assert!(
        resolved.permissions.is_empty(),
        "expected empty post-unassign set; got {resolved:?}"
    );
    assert!(
        resolved.roles.is_empty(),
        "no dangling roles should remain after unassign"
    );
}
