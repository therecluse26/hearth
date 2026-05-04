//! Bootstrap seeding for new realms.
//!
//! Implements AUTHORIZATION.md § 9.1–§ 9.3: registers the default
//! permission set, installs the five seed roles, and establishes the
//! default OAuth scope-to-permission mapping.
//!
//! All operations are idempotent. Re-running seed on a realm that has
//! any or all of the seed data already present is a safe no-op — we
//! check existing records before writing.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::core::{Clock, RealmId, Timestamp};
use crate::storage::StorageEngine;

use super::error::RbacError;
use super::keys;
use super::types::{Permission, Role, RoleId, RoleScopeKind};

/// Seed permission identifiers and human-readable descriptions (§ 9.1).
///
/// Tuples are `(name, description)`. Descriptions are surfaced through the
/// admin UI when no override is declared in the realm's YAML `permissions:`
/// block; the storage record itself remains a bare `Permission` newtype so
/// the on-disk format is unchanged.
pub(crate) const SEED_PERMISSIONS: &[(&str, &str)] = &[
    (
        "hearth.admin",
        "Full superuser access to the Hearth system realm; manage realms, global config, and platform-level settings.",
    ),
    (
        "realm.read",
        "View realm metadata, roles, groups, applications, and audit events within the current realm.",
    ),
    (
        "realm.write",
        "Modify realm-scoped resources: users, applications, roles, groups, and assignments.",
    ),
    (
        "realm.admin",
        "Full administrative control of the current realm, including settings, signing keys, and identity providers.",
    ),
    (
        "org.read",
        "View organizations, their members, and invitations within the current realm.",
    ),
    (
        "org.write",
        "Create, update, and delete organizations and manage their memberships and invitations.",
    ),
    (
        "org.admin",
        "Full administrative control of organizations, including role and member management within an org.",
    ),
    (
        "org.billing",
        "Access organization billing, subscription, and payment-related settings.",
    ),
    (
        "user.read",
        "View user profiles, attributes, sessions, and credential metadata in the current realm.",
    ),
    (
        "user.write",
        "Create, update, and delete users; manage their credentials, attributes, and direct permission grants.",
    ),
    (
        "user.impersonate",
        "Issue tokens on behalf of another user — a sensitive operation typically reserved for support staff.",
    ),
];

/// Returns the canonical description for a seed permission, or `None` if
/// `name` is not one of the built-in permissions defined in
/// [`SEED_PERMISSIONS`]. Used by the admin UI as a fallback when no override
/// is supplied via YAML.
#[must_use]
pub fn seed_permission_description(name: &str) -> Option<&'static str> {
    SEED_PERMISSIONS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, d)| *d)
}

/// Seed role specification. We store IDs resolved at first-seed time so
/// subsequent runs can find existing roles and reconcile drift.
struct SeedRoleSpec {
    name: &'static str,
    /// Permissions granted directly by this role.
    permissions: &'static [&'static str],
    /// Parent role names (resolved after first pass).
    parent_names: &'static [&'static str],
    /// Canonical scope for this role. `org.*` roles are organization-scoped;
    /// `realm.*` roles are realm-scoped. Stored explicitly (not derived from
    /// the name) so seed-time intent is unambiguous, and reconciled on every
    /// `seed_realm` call to repair legacy records that defaulted to
    /// `RoleScopeKind::Realm` on deserialization.
    scope_kind: RoleScopeKind,
}

/// The five seed roles (§ 9.2).
///
/// Order matters: parents must be created before children. `realm.admin`
/// and `realm.member` are standalone; `org.member` is parent of
/// `org.admin`, which is parent of `org.owner`.
const SEED_ROLES: &[SeedRoleSpec] = &[
    SeedRoleSpec {
        name: "realm.admin",
        permissions: &[
            "hearth.admin",
            "realm.read",
            "realm.write",
            "realm.admin",
            "org.read",
            "org.write",
            "org.admin",
            "org.billing",
            "user.read",
            "user.write",
            "user.impersonate",
        ],
        parent_names: &[],
        scope_kind: RoleScopeKind::Realm,
    },
    SeedRoleSpec {
        name: "realm.member",
        permissions: &[],
        parent_names: &[],
        scope_kind: RoleScopeKind::Realm,
    },
    SeedRoleSpec {
        name: "org.member",
        permissions: &["org.read"],
        parent_names: &[],
        scope_kind: RoleScopeKind::Organization,
    },
    SeedRoleSpec {
        name: "org.admin",
        permissions: &["org.write", "org.admin"],
        parent_names: &["org.member"],
        scope_kind: RoleScopeKind::Organization,
    },
    SeedRoleSpec {
        name: "org.owner",
        permissions: &["org.billing"],
        parent_names: &["org.admin"],
        scope_kind: RoleScopeKind::Organization,
    },
];

/// Default scope-to-permission mapping (§ 9.3).
///
/// `None` means "no narrowing" (identifier-only scope).
/// `Some(vec)` is a literal list of permissions the scope maps to.
fn seed_scope_map() -> Vec<(&'static str, Option<Vec<&'static str>>)> {
    vec![
        ("openid", None),
        ("profile", None),
        ("email", None),
        (
            "admin",
            Some(vec![
                "hearth.admin",
                "realm.read",
                "realm.write",
                "realm.admin",
                "user.read",
                "user.write",
                "user.impersonate",
            ]),
        ),
        (
            "org",
            Some(vec!["org.read", "org.write", "org.admin", "org.billing"]),
        ),
    ]
}

/// Persisted representation of a scope mapping (so `resolve.rs` can read it back).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct StoredScope {
    /// Scope name (e.g. `"docs"`, `"admin"`).
    pub(crate) name: String,
    /// `None` → no narrowing; `Some(list)` → intersect permissions with this list.
    pub(crate) permissions: Option<Vec<Permission>>,
}

/// Installs the seed permissions, roles, and scope map for `realm_id`.
///
/// Idempotent — a second call is a near-no-op (records already present
/// are left untouched).
pub(crate) fn seed_realm(
    storage: &Arc<dyn StorageEngine>,
    clock: &Arc<dyn Clock>,
    realm_id: &RealmId,
) -> Result<(), RbacError> {
    seed_permissions(storage, realm_id)?;
    seed_roles(storage, clock, realm_id)?;
    seed_scopes(storage, realm_id)?;
    Ok(())
}

fn seed_permissions(storage: &Arc<dyn StorageEngine>, realm_id: &RealmId) -> Result<(), RbacError> {
    for (p, _desc) in SEED_PERMISSIONS {
        let perm = Permission::new(*p).map_err(|reason| RbacError::InvalidPermission { reason })?;
        let key = keys::encode_permission(realm_id, perm.as_str());
        if storage.get(realm_id, &key)?.is_some() {
            continue;
        }
        let value = serde_json::to_vec(&perm).map_err(|e| RbacError::Serialization {
            reason: e.to_string(),
        })?;
        storage.put(realm_id, &key, &value)?;
    }
    Ok(())
}

fn seed_roles(
    storage: &Arc<dyn StorageEngine>,
    clock: &Arc<dyn Clock>,
    realm_id: &RealmId,
) -> Result<(), RbacError> {
    // Helper: find an existing role ID by name, or None.
    let find_role_id = |name: &str| -> Result<Option<RoleId>, RbacError> {
        let name_key = keys::encode_role_name(realm_id, name);
        let Some(raw) = storage.get(realm_id, &name_key)? else {
            return Ok(None);
        };
        let rid: RoleId = serde_json::from_slice(&raw).map_err(|e| RbacError::Serialization {
            reason: e.to_string(),
        })?;
        Ok(Some(rid))
    };

    let now: Timestamp = clock.now();

    for spec in SEED_ROLES {
        // Reconcile if already seeded: load the stored Role and rewrite its
        // scope_kind if it disagrees with the spec. This repairs legacy
        // records written before scope_kind existed (which deserialize to
        // RoleScopeKind::Realm by default).
        if let Some(existing_id) = find_role_id(spec.name)? {
            let role_key = keys::encode_role(&existing_id);
            let Some(raw) = storage.get(realm_id, &role_key)? else {
                continue;
            };
            let mut role: Role =
                serde_json::from_slice(&raw).map_err(|e| RbacError::Serialization {
                    reason: e.to_string(),
                })?;
            if role.scope_kind != spec.scope_kind {
                role.scope_kind = spec.scope_kind;
                role.updated_at = now;
                let role_bytes =
                    serde_json::to_vec(&role).map_err(|e| RbacError::Serialization {
                        reason: e.to_string(),
                    })?;
                storage.put(realm_id, &role_key, &role_bytes)?;
            }
            continue;
        }

        // Resolve parent names → IDs (must already exist since we seed in order).
        let mut parent_roles = Vec::with_capacity(spec.parent_names.len());
        for pname in spec.parent_names {
            if let Some(pid) = find_role_id(pname)? {
                parent_roles.push(pid);
            } else {
                // Should not happen given ordering above, but guard defensively.
                return Err(RbacError::Serialization {
                    reason: format!(
                        "seed role '{}' references missing parent '{pname}'",
                        spec.name
                    ),
                });
            }
        }

        let perms: Result<Vec<Permission>, RbacError> = spec
            .permissions
            .iter()
            .map(|p| Permission::new(*p).map_err(|reason| RbacError::InvalidPermission { reason }))
            .collect();
        let permissions = perms?;

        let role = Role {
            id: RoleId::generate(),
            realm_id: realm_id.clone(),
            name: spec.name.to_string(),
            description: Some(format!("Seed role: {}", spec.name)),
            permissions,
            parent_roles,
            scope_kind: spec.scope_kind,
            created_at: now,
            updated_at: now,
        };

        let role_key = keys::encode_role(&role.id);
        let name_key = keys::encode_role_name(realm_id, &role.name);

        let role_bytes = serde_json::to_vec(&role).map_err(|e| RbacError::Serialization {
            reason: e.to_string(),
        })?;
        let id_bytes = serde_json::to_vec(&role.id).map_err(|e| RbacError::Serialization {
            reason: e.to_string(),
        })?;

        storage.put_batch(realm_id, &[(role_key, role_bytes), (name_key, id_bytes)])?;
    }

    Ok(())
}

fn seed_scopes(storage: &Arc<dyn StorageEngine>, realm_id: &RealmId) -> Result<(), RbacError> {
    for (name, perms) in seed_scope_map() {
        let key = keys::encode_scope(realm_id, name);
        if storage.get(realm_id, &key)?.is_some() {
            continue;
        }
        let permissions = match perms {
            None => None,
            Some(list) => Some(
                list.into_iter()
                    .map(|p| {
                        Permission::new(p).map_err(|reason| RbacError::InvalidPermission { reason })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        };
        let stored = StoredScope {
            name: name.to_string(),
            permissions,
        };
        let value = serde_json::to_vec(&stored).map_err(|e| RbacError::Serialization {
            reason: e.to_string(),
        })?;
        storage.put(realm_id, &key, &value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{FakeClock, Timestamp};
    use crate::storage::{EmbeddedStorageEngine, StorageConfig};

    fn setup() -> (Arc<dyn StorageEngine>, Arc<dyn Clock>, RealmId) {
        let tmp = tempfile::tempdir().expect("tmp");
        let storage = Arc::new(
            EmbeddedStorageEngine::open(StorageConfig::dev(tmp.path().to_path_buf()))
                .expect("storage"),
        ) as Arc<dyn StorageEngine>;
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1))) as Arc<dyn Clock>;
        let realm_id = RealmId::generate();
        // Leak tmp so it outlives the test since storage holds a file handle.
        std::mem::forget(tmp);
        (storage, clock, realm_id)
    }

    #[test]
    fn seed_writes_all_permissions() {
        let (storage, clock, realm) = setup();
        seed_realm(&storage, &clock, &realm).expect("seed");
        for (p, _desc) in SEED_PERMISSIONS {
            let k = keys::encode_permission(&realm, p);
            assert!(
                storage.get(&realm, &k).expect("get").is_some(),
                "missing permission: {p}"
            );
        }
    }

    #[test]
    fn seed_writes_all_roles_by_name() {
        let (storage, clock, realm) = setup();
        seed_realm(&storage, &clock, &realm).expect("seed");
        for spec in SEED_ROLES {
            let k = keys::encode_role_name(&realm, spec.name);
            assert!(
                storage.get(&realm, &k).expect("get").is_some(),
                "missing role: {}",
                spec.name
            );
        }
    }

    #[test]
    fn seed_is_idempotent() {
        let (storage, clock, realm) = setup();
        seed_realm(&storage, &clock, &realm).expect("seed #1");
        // Capture role IDs after first seed.
        let mut ids1 = Vec::new();
        for spec in SEED_ROLES {
            let k = keys::encode_role_name(&realm, spec.name);
            let v = storage.get(&realm, &k).expect("get").expect("some");
            let id: RoleId = serde_json::from_slice(&v).expect("decode");
            ids1.push((spec.name, id));
        }

        seed_realm(&storage, &clock, &realm).expect("seed #2");

        for spec in SEED_ROLES {
            let k = keys::encode_role_name(&realm, spec.name);
            let v = storage.get(&realm, &k).expect("get").expect("some");
            let id: RoleId = serde_json::from_slice(&v).expect("decode");
            let prev = ids1
                .iter()
                .find(|(n, _)| *n == spec.name)
                .map(|(_, i)| i)
                .expect("prev id for role");
            assert_eq!(
                &id, prev,
                "role ID changed across seed runs for {}",
                spec.name
            );
        }
    }

    #[test]
    fn seed_role_composition_realm_admin_has_all_seed_perms() {
        let (storage, clock, realm) = setup();
        seed_realm(&storage, &clock, &realm).expect("seed");
        let k = keys::encode_role_name(&realm, "realm.admin");
        let v = storage.get(&realm, &k).expect("get").expect("some");
        let id: RoleId = serde_json::from_slice(&v).expect("decode");
        let role_key = keys::encode_role(&id);
        let role_bytes = storage.get(&realm, &role_key).expect("get").expect("some");
        let role: Role = serde_json::from_slice(&role_bytes).expect("decode role");

        // Should include hearth.admin (reserved) and all seed perms directly.
        let names: Vec<&str> = role.permissions.iter().map(Permission::as_str).collect();
        for (p, _desc) in SEED_PERMISSIONS {
            assert!(
                names.contains(p),
                "realm.admin missing direct permission: {p}"
            );
        }
    }

    #[test]
    fn seed_role_composition_org_owner_parent_is_org_admin() {
        let (storage, clock, realm) = setup();
        seed_realm(&storage, &clock, &realm).expect("seed");
        let owner = load_role_by_name(&storage, &realm, "org.owner");
        let admin = load_role_by_name(&storage, &realm, "org.admin");
        assert_eq!(owner.parent_roles, vec![admin.id.clone()]);
    }

    #[test]
    fn seed_scope_map_installs_expected_scopes() {
        let (storage, clock, realm) = setup();
        seed_realm(&storage, &clock, &realm).expect("seed");
        for name in ["openid", "profile", "email", "admin", "org"] {
            let k = keys::encode_scope(&realm, name);
            assert!(
                storage.get(&realm, &k).expect("get").is_some(),
                "missing scope: {name}"
            );
        }

        // openid/profile/email → None permissions (no narrowing).
        let k = keys::encode_scope(&realm, "openid");
        let v = storage.get(&realm, &k).expect("get").expect("some");
        let s: StoredScope = serde_json::from_slice(&v).expect("decode");
        assert!(s.permissions.is_none());

        // admin → Some with hearth.admin and realm.* etc.
        let k = keys::encode_scope(&realm, "admin");
        let v = storage.get(&realm, &k).expect("get").expect("some");
        let s: StoredScope = serde_json::from_slice(&v).expect("decode");
        let list = s.permissions.expect("admin scope has list");
        let names: Vec<&str> = list.iter().map(Permission::as_str).collect();
        assert!(names.contains(&"hearth.admin"));
        assert!(names.contains(&"realm.admin"));
    }

    fn load_role_by_name(storage: &Arc<dyn StorageEngine>, realm: &RealmId, name: &str) -> Role {
        let k = keys::encode_role_name(realm, name);
        let v = storage.get(realm, &k).expect("get").expect("some");
        let id: RoleId = serde_json::from_slice(&v).expect("decode id");
        let role_key = keys::encode_role(&id);
        let role_bytes = storage.get(realm, &role_key).expect("get").expect("some");
        serde_json::from_slice(&role_bytes).expect("decode role")
    }
}
