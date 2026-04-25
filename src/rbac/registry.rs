//! YAML-backed RBAC registry helpers and validators.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::core::RealmId;
use crate::identity::claims_config::ClaimProfile;

use super::types::{PermissionDefinition, ProtectedResource, Role, ScopeBundle};

/// Syntactic scope classification used by the authz expansion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeKind {
    OidcStandard,
    Permission,
    Bundle,
}

/// Realm-local in-memory registry shape.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RealmPermissionRegistry {
    #[serde(default)]
    pub permissions: Vec<PermissionDefinition>,
    #[serde(default)]
    pub roles: Vec<Role>,
    #[serde(default)]
    pub scopes: Vec<ScopeBundle>,
    #[serde(default)]
    pub protected_resources: Vec<ProtectedResource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_profile: Option<ClaimProfile>,
}

/// All-realm registry snapshot.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PermissionRegistry {
    #[serde(default)]
    pub realms: BTreeMap<RealmId, RealmPermissionRegistry>,
}

/// Classifies a scope string using the separator-based grammar.
pub fn classify_scope_string(scope: &str) -> Option<ScopeKind> {
    match scope {
        "openid" | "profile" | "email" | "address" | "phone" | "offline_access" => {
            Some(ScopeKind::OidcStandard)
        }
        _ if scope.contains('.') && !scope.contains(':') => Some(ScopeKind::Permission),
        _ if scope.contains(':') && !scope.contains('.') => Some(ScopeKind::Bundle),
        _ => None,
    }
}

/// Returns true if `scope` is one of the supported OIDC standard scopes.
pub fn is_oidc_standard_scope(scope: &str) -> bool {
    classify_scope_string(scope) == Some(ScopeKind::OidcStandard)
}
