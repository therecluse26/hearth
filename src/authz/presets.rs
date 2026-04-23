//! Canonical preset namespace for Hearth's "Roles & Permissions" product layer.
//!
//! The preset defines three canonical object types with standard relations
//! and hierarchy unions, so the Roles UI can manage access without exposing
//! raw Zanzibar tuple vocabulary to operators:
//!
//! - `realm#admin` — realm-wide administrator (same shape as the existing
//!   `hearth#admin` gate; see `src/identity/keys.rs` and
//!   `src/protocol/web/admin.rs`).
//! - `organization#{owner,admin,member,viewer}` — standard B2B role ladder
//!   with the idiomatic Zanzibar union hierarchy `owner ⊆ admin ⊆ member ⊆ viewer`.
//! - `application#{admin,viewer}` — per-application role pair with
//!   `admin ⊆ viewer`.
//!
//! Bootstrap is **opt-in**: callers invoke [`ensure_preset_namespace`] when
//! they know the realm should participate in the Roles product (e.g. on
//! first visit of the Roles admin UI). We intentionally do NOT auto-apply
//! the preset on realm creation or at startup, because many internal tests
//! write tuples with ad-hoc object types (`document`, `group`) on realms
//! that have no namespace; applying a restrictive preset to those realms
//! would reject their writes.

use std::collections::HashMap;

use crate::authz::{
    AuthorizationEngine, AuthzError, NamespaceConfig, ObjectTypeConfig, RelationConfig,
    RelationRewrite,
};
use crate::core::RealmId;

/// Returns Hearth's canonical preset namespace.
///
/// The preset is deterministic — constructing it twice yields equal
/// [`NamespaceConfig`] values — and always passes
/// [`NamespaceConfig::validate_rewrites`].
#[must_use]
pub fn preset_namespace() -> NamespaceConfig {
    let mut object_types = HashMap::new();
    object_types.insert("realm".to_string(), realm_type());
    object_types.insert("organization".to_string(), organization_type());
    object_types.insert("application".to_string(), application_type());
    // Legacy: the pre-existing `hearth#admin` gate (see `src/protocol/web/auth.rs`
    // and `src/identity/onboarding.rs`) writes tuples with the literal object
    // type `hearth`. Declaring it here keeps those writes valid on presetted
    // realms. A future cleanup may migrate the gate to `realm:<id>#admin`
    // and drop this entry.
    object_types.insert("hearth".to_string(), hearth_legacy_type());
    NamespaceConfig { object_types }
}

fn hearth_legacy_type() -> ObjectTypeConfig {
    let mut relations = HashMap::new();
    relations.insert(
        "admin".to_string(),
        RelationConfig {
            allowed_subject_types: vec!["user".to_string()],
            rewrite: None,
        },
    );
    ObjectTypeConfig { relations }
}

fn realm_type() -> ObjectTypeConfig {
    let mut relations = HashMap::new();
    relations.insert(
        "admin".to_string(),
        RelationConfig {
            allowed_subject_types: vec!["user".to_string()],
            rewrite: None,
        },
    );
    ObjectTypeConfig { relations }
}

fn organization_type() -> ObjectTypeConfig {
    let mut relations = HashMap::new();
    // Idiomatic Zanzibar union hierarchy: owner ⊆ admin ⊆ member ⊆ viewer.
    // Each higher role's tuple automatically satisfies every role below it.
    relations.insert(
        "owner".to_string(),
        RelationConfig {
            allowed_subject_types: vec!["user".to_string()],
            rewrite: None,
        },
    );
    relations.insert(
        "admin".to_string(),
        RelationConfig {
            allowed_subject_types: vec!["user".to_string()],
            rewrite: Some(RelationRewrite::Union {
                includes: vec!["owner".to_string()],
            }),
        },
    );
    relations.insert(
        "member".to_string(),
        RelationConfig {
            // `organization` as a subject type enables group-based sharing
            // later (e.g. `doc#viewer@organization:acme#member`).
            allowed_subject_types: vec!["user".to_string(), "organization".to_string()],
            rewrite: Some(RelationRewrite::Union {
                includes: vec!["admin".to_string()],
            }),
        },
    );
    relations.insert(
        "viewer".to_string(),
        RelationConfig {
            allowed_subject_types: vec!["user".to_string()],
            rewrite: Some(RelationRewrite::Union {
                includes: vec!["member".to_string()],
            }),
        },
    );
    ObjectTypeConfig { relations }
}

fn application_type() -> ObjectTypeConfig {
    let mut relations = HashMap::new();
    relations.insert(
        "admin".to_string(),
        RelationConfig {
            allowed_subject_types: vec!["user".to_string()],
            rewrite: None,
        },
    );
    relations.insert(
        "viewer".to_string(),
        RelationConfig {
            allowed_subject_types: vec!["user".to_string()],
            rewrite: Some(RelationRewrite::Union {
                includes: vec!["admin".to_string()],
            }),
        },
    );
    ObjectTypeConfig { relations }
}

/// Installs the preset namespace on `realm_id` if no namespace is currently
/// configured. Idempotent — subsequent calls are no-ops.
///
/// If a namespace is already present (preset or custom), this function
/// leaves it unchanged and returns `Ok(false)`. A return of `Ok(true)`
/// signals that the preset was freshly installed.
///
/// # Errors
/// Propagates any [`AuthzError`] from `get_namespace` / `set_namespace`.
pub fn ensure_preset_namespace(
    authz: &dyn AuthorizationEngine,
    realm_id: &RealmId,
) -> Result<bool, AuthzError> {
    if authz.get_namespace(realm_id)?.is_some() {
        return Ok(false);
    }
    authz.set_namespace(realm_id, &preset_namespace())?;
    Ok(true)
}
