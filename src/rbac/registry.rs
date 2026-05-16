//! YAML-backed RBAC registry helpers and validators.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::core::RealmId;
use crate::identity::claims_config::ClaimProfile;

use super::types::{PermissionDefinition, ProtectedResource, Role, RoleId, ScopeBundle};

/// Maximum depth for role parent chain traversal during registry validation.
/// Matches `resolve::MAX_ROLE_DEPTH` so the same cap is enforced at load
/// time and at token-issue time.
pub const MAX_ROLE_PARENT_DEPTH: usize = 10;

/// Tier 2 claim names — known custom / informational claims already in use by
/// Hearth's token issuance or common OIDC profile extensions.
///
/// A mapper MAY target these names, but doing so overrides Hearth's built-in
/// emission. SDK helpers (`useHasPermission`, `HasRole`, …) operate on the
/// overridden shape when a Tier 2 claim is overridden. An operator overriding
/// any of these should be aware of the downstream consequences.
///
/// See `docs/specs/AUTHZ_EXPANSION.md` §"Claim name tiers".
pub const TIER2_CLAIMS: &[&str] = &[
    "employee_id",
    "department",
    "cost_center",
    "tenant_id",
    "org_id",
    "oid",
    "roles",
    "groups",
    "permissions",
];

/// Tier 1 JWT / OIDC claims that mappers MUST NOT target.
///
/// See `docs/specs/AUTHZ_EXPANSION.md` §"Claim name tiers" for the
/// authoritative list and rationale.
pub const TIER1_CLAIMS: &[&str] = &[
    // JWT registered (RFC 7519)
    "iss",
    "aud",
    "exp",
    "nbf",
    "iat",
    "jti",
    // Identity
    "sub",
    "tid",
    // Authorization
    "permissions",
    "scope",
    "sid",
    // Tenant routing (authoritative for downstream data partitioning)
    "oid",
    // OIDC flow
    "nonce",
    "auth_time",
    "acr",
    "amr",
    "azp",
    // OIDC token-binding hashes
    "at_hash",
    "c_hash",
    "s_hash",
    // OAuth client identity
    "client_id",
    // Proof-of-possession
    "cnf",
    // Delegation attestation (AGENT_AUTH §3)
    "act",
    "actor",
    // Verification attestation
    "email_verified",
    "phone_number_verified",
];

// ---------------------------------------------------------------------------
// RegistryError
// ---------------------------------------------------------------------------

/// Validation errors returned by [`RealmPermissionRegistry::validate`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryError {
    /// A permission name in the registry failed grammar validation.
    InvalidPermissionName {
        /// The raw string that failed.
        name: String,
        /// Human-readable reason.
        reason: String,
    },
    /// A scope bundle has an invalid name.
    ///
    /// Bundle names must match `^[A-Za-z0-9_\-]+(:[A-Za-z0-9_\-]+)+$`
    /// (≥1 colon, no dot, ≤128 chars). See `AUTHZ_EXPANSION.md` §"Naming
    /// convention".
    InvalidScopeBundleName {
        /// The offending bundle name.
        name: String,
        /// Human-readable reason.
        reason: String,
    },
    /// A role references a permission not declared in the registry.
    UndeclaredPermissionInRole {
        /// Name of the offending role.
        role_name: String,
        /// The undeclared permission string.
        permission: String,
    },
    /// A scope bundle references a permission not declared in the registry.
    UndeclaredPermissionInBundle {
        /// Name of the offending bundle.
        bundle_name: String,
        /// The undeclared permission string.
        permission: String,
    },
    /// A role's `parent_roles` contains a `RoleId` not present in the
    /// registry's `roles` list.
    UndeclaredParentRole {
        /// Name of the role with the dangling parent reference.
        role_name: String,
        /// Display form of the unknown parent ID.
        parent_id: String,
    },
    /// A cycle was detected in the role parent graph.
    ///
    /// The spec caps parent chains at `MAX_ROLE_PARENT_DEPTH` hops and
    /// prohibits cycles entirely.
    RoleParentCycle {
        /// Name of the role that participates in the cycle.
        role_name: String,
    },
    /// A role parent chain exceeds [`MAX_ROLE_PARENT_DEPTH`].
    RoleParentDepthExceeded {
        /// Name of the role at which the depth cap was hit.
        role_name: String,
        /// The cap that was exceeded.
        limit: usize,
    },
    /// A claim mapping targets a Tier 1 (forbidden) claim name.
    ///
    /// Tier 1 claims are reserved for core issuance code; mappers must
    /// never override them. See `AUTHZ_EXPANSION.md` §"Claim name tiers".
    ForbiddenClaimTarget {
        /// The forbidden claim name.
        claim: String,
    },
    /// A custom (Tier 3) claim name fails the naming grammar.
    ///
    /// Custom names must be either a short `^[a-z][a-z0-9_]*$` identifier
    /// (≤64 chars) or an HTTPS-namespaced URL (≤256 chars). HTTP URLs and
    /// URN-form names are not permitted in this version.
    /// See `AUTHZ_EXPANSION.md` §"Claim name tiers" for the grammar rules.
    InvalidClaimName {
        /// The offending claim name.
        claim: String,
        /// Human-readable reason.
        reason: String,
    },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPermissionName { name, reason } => {
                write!(f, "invalid permission name {name:?}: {reason}")
            }
            Self::InvalidScopeBundleName { name, reason } => {
                write!(f, "invalid scope bundle name {name:?}: {reason}")
            }
            Self::UndeclaredPermissionInRole {
                role_name,
                permission,
            } => {
                write!(
                    f,
                    "role {role_name:?} references undeclared permission {permission:?}"
                )
            }
            Self::UndeclaredPermissionInBundle {
                bundle_name,
                permission,
            } => {
                write!(
                    f,
                    "bundle {bundle_name:?} references undeclared permission {permission:?}"
                )
            }
            Self::UndeclaredParentRole {
                role_name,
                parent_id,
            } => {
                write!(
                    f,
                    "role {role_name:?} has undeclared parent role ID {parent_id:?}"
                )
            }
            Self::RoleParentCycle { role_name } => {
                write!(f, "cycle detected in parent chain of role {role_name:?}")
            }
            Self::RoleParentDepthExceeded { role_name, limit } => {
                write!(
                    f,
                    "role {role_name:?} parent chain exceeds depth limit of {limit}"
                )
            }
            Self::ForbiddenClaimTarget { claim } => {
                write!(
                    f,
                    "claim mapper target {claim:?} is a Tier 1 (reserved) claim name"
                )
            }
            Self::InvalidClaimName { claim, reason } => {
                write!(f, "invalid custom claim name {claim:?}: {reason}")
            }
        }
    }
}

impl std::error::Error for RegistryError {}

// ---------------------------------------------------------------------------
// ScopeKind
// ---------------------------------------------------------------------------

/// Syntactic scope classification used by the authz expansion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeKind {
    OidcStandard,
    Permission,
    Bundle,
}

// ---------------------------------------------------------------------------
// Registry types
// ---------------------------------------------------------------------------

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

impl RealmPermissionRegistry {
    /// Validates cross-reference and structural invariants of the registry.
    ///
    /// This is a pure in-memory check — no storage I/O. It should be called
    /// after constructing the registry from YAML (in `to_realm_config`) and
    /// on hot-reload before swapping the `ArcSwap`.
    ///
    /// Checks performed:
    /// 1. Every scope bundle name matches the bundle-name grammar.
    /// 2. Every permission referenced by a role is declared in `permissions`.
    /// 3. Every permission referenced by a scope bundle is declared in
    ///    `permissions`.
    /// 4. Every `parent_roles` ID in every role exists in this registry.
    /// 5. No cycle exists in the role parent graph (depth capped at
    ///    [`MAX_ROLE_PARENT_DEPTH`]).
    /// 6. No claim mapping targets a Tier 1 (forbidden) claim name.
    /// 7. Custom (Tier 3) claim names pass the short-identifier or
    ///    HTTPS-namespaced grammar.
    ///
    /// Returns `Ok(())` if all checks pass, or `Err(errors)` with every
    /// violation found. The caller should surface all errors at once rather
    /// than stopping at the first.
    pub fn validate(&self) -> Result<(), Vec<RegistryError>> {
        let mut errors: Vec<RegistryError> = Vec::new();

        // --- Build lookup sets -----------------------------------------------

        // Seed permissions are always installed by `seed_realm` and so are
        // implicitly available in every realm's runtime registry. Include
        // them in the declared set so YAML roles and scope bundles can
        // reference (e.g.) `user.read` or `org.read` without re-declaring
        // them in the realm's `permissions:` block.
        let mut declared_perms: HashSet<&str> =
            self.permissions.iter().map(|p| p.name.as_str()).collect();
        for (name, _desc) in super::seed::SEED_PERMISSIONS {
            declared_perms.insert(name);
        }

        let role_ids: HashSet<&RoleId> = self.roles.iter().map(|r| &r.id).collect();

        // --- Scope bundle name grammar + permission references ----------------

        for bundle in &self.scopes {
            if let Err(reason) = validate_bundle_name(&bundle.name) {
                errors.push(RegistryError::InvalidScopeBundleName {
                    name: bundle.name.clone(),
                    reason,
                });
            }
            for perm in &bundle.permissions {
                if !declared_perms.contains(perm.as_str()) {
                    errors.push(RegistryError::UndeclaredPermissionInBundle {
                        bundle_name: bundle.name.clone(),
                        permission: perm.to_string(),
                    });
                }
            }
        }

        // --- Protected-resource scope bundles --------------------------------

        for resource in &self.protected_resources {
            for bundle in &resource.scopes {
                if let Err(reason) = validate_bundle_name(&bundle.name) {
                    errors.push(RegistryError::InvalidScopeBundleName {
                        name: bundle.name.clone(),
                        reason,
                    });
                }
                for perm in &bundle.permissions {
                    if !declared_perms.contains(perm.as_str()) {
                        errors.push(RegistryError::UndeclaredPermissionInBundle {
                            bundle_name: bundle.name.clone(),
                            permission: perm.to_string(),
                        });
                    }
                }
            }
        }

        // --- Role permission references + parent ID validity -----------------

        let mut has_undeclared_parent = false;
        for role in &self.roles {
            for perm in &role.permissions {
                if !declared_perms.contains(perm.as_str()) {
                    errors.push(RegistryError::UndeclaredPermissionInRole {
                        role_name: role.name.clone(),
                        permission: perm.to_string(),
                    });
                }
            }
            for parent_id in &role.parent_roles {
                if !role_ids.contains(parent_id) {
                    errors.push(RegistryError::UndeclaredParentRole {
                        role_name: role.name.clone(),
                        parent_id: parent_id.to_string(),
                    });
                    has_undeclared_parent = true;
                }
            }
        }

        // --- Cycle detection (skip if dangling parent IDs were found) --------
        //
        // If there are undeclared parent IDs the cycle-detector would follow
        // edges into the void and produce confusing spurious errors; defer
        // cycle reporting until the undeclared-parent errors are fixed.
        if !has_undeclared_parent {
            let cycle_errors = detect_role_cycles(&self.roles);
            errors.extend(cycle_errors);
        }

        // --- Claim profile: Tier 1/2/3 name enforcement ----------------------
        //
        // Tier 1: forbidden — reject.
        // Tier 2: known overridable names — accept without additional grammar
        //         check (they are already-valid identifiers).
        // Tier 3: custom — must pass the short-identifier or HTTPS-namespaced
        //         grammar defined in `validate_tier3_claim_name`.

        if let Some(profile) = &self.claim_profile {
            for mapping in &profile.mappings {
                if TIER1_CLAIMS.contains(&mapping.claim.as_str()) {
                    errors.push(RegistryError::ForbiddenClaimTarget {
                        claim: mapping.claim.clone(),
                    });
                } else if !TIER2_CLAIMS.contains(&mapping.claim.as_str()) {
                    // Tier 3: validate the custom name grammar.
                    if let Err(reason) = validate_tier3_claim_name(&mapping.claim) {
                        errors.push(RegistryError::InvalidClaimName {
                            claim: mapping.claim.clone(),
                            reason,
                        });
                    }
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// All-realm registry snapshot.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PermissionRegistry {
    #[serde(default)]
    pub realms: BTreeMap<RealmId, RealmPermissionRegistry>,
}

// ---------------------------------------------------------------------------
// Scope string classification
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Bundle name validation
// ---------------------------------------------------------------------------

/// Validates a scope bundle name against the bundle grammar.
///
/// Grammar: `^[A-Za-z0-9_\-]+(:[A-Za-z0-9_\-]+)+$`
/// - Must contain ≥1 colon separator.
/// - Must NOT contain `.`.
/// - ≤128 chars.
/// - Each segment is non-empty and contains only `[A-Za-z0-9_\-]`.
pub fn validate_bundle_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("bundle name must not be empty".to_string());
    }
    if name.len() > 128 {
        return Err("bundle name exceeds 128 chars".to_string());
    }
    if name.contains('.') {
        return Err(
            "bundle name must not contain '.' (use ':' as separator; '.' is the permission namespace)"
                .to_string(),
        );
    }
    if !name.contains(':') {
        return Err(
            "bundle name must contain at least one ':' separator (e.g. 'read:docs')".to_string(),
        );
    }
    let segments: Vec<&str> = name.split(':').collect();
    for (i, segment) in segments.into_iter().enumerate() {
        if segment.is_empty() {
            return Err(format!("bundle name has empty segment at index {i}"));
        }
        for c in segment.chars() {
            if !(c.is_ascii_alphanumeric() || c == '_' || c == '-') {
                return Err(format!(
                    "segment {i} of bundle name contains invalid character '{c}' \
                     (allowed: A-Za-z0-9 _ -)"
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tier 3 claim name validation
// ---------------------------------------------------------------------------

/// Validates a custom (Tier 3) claim name.
///
/// Two forms are accepted:
///
/// - **Short form:** `^[a-z][a-z0-9_]*$`, ≤64 chars. Used for simple custom
///   claims such as `department` or `employee_id`.
/// - **HTTPS-namespaced form:** must start with `https://`, ≤256 chars.
///   Collision-free namespacing following the Auth0/Okta convention, e.g.
///   `https://acme.com/department`. HTTP (non-TLS) URLs are rejected.
///
/// Tier 1 and Tier 2 names are excluded from this check by the caller —
/// they are handled before `validate_tier3_claim_name` is called.
pub fn validate_tier3_claim_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("claim name must not be empty".to_string());
    }

    // HTTPS-namespaced form.
    if name.starts_with("https://") {
        if name.len() > 256 {
            return Err("HTTPS-namespaced claim name exceeds 256 chars".to_string());
        }
        if name.len() <= "https://".len() {
            return Err(
                "HTTPS-namespaced claim name must have a host after 'https://'".to_string(),
            );
        }
        return Ok(());
    }

    // Reject HTTP (non-TLS) namespace.
    if name.starts_with("http://") {
        return Err(
            "claim namespace must use 'https://' (HTTP is rejected for security)".to_string(),
        );
    }

    // Short identifier form: ^[a-z][a-z0-9_]*$, ≤64 chars.
    if name.len() > 64 {
        return Err("short-form claim name exceeds 64 chars".to_string());
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        Some(c) => {
            return Err(format!(
                "short-form claim name must start with a lowercase ASCII letter, got '{c}'"
            ));
        }
        None => return Err("claim name must not be empty".to_string()),
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return Err(format!(
                "short-form claim name contains invalid character '{c}' \
                 (allowed: a-z 0-9 _)"
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Role parent cycle detection
// ---------------------------------------------------------------------------

/// Detects cycles and depth violations in the role parent graph.
///
/// Uses DFS with an explicit path stack (white/grey/black coloring). Reports
/// every distinct cycle root found; caller deduplicates if desired.
fn detect_role_cycles(roles: &[Role]) -> Vec<RegistryError> {
    let roles_by_id: HashMap<&RoleId, &Role> = roles.iter().map(|r| (&r.id, r)).collect();

    let mut errors: Vec<RegistryError> = Vec::new();
    // Nodes that have been fully explored (no more cycles reachable from them).
    let mut fully_checked: HashSet<RoleId> = HashSet::new();

    for role in roles {
        if !fully_checked.contains(&role.id) {
            let mut in_path: Vec<RoleId> = Vec::new();
            dfs_check(
                &role.id,
                &roles_by_id,
                &mut in_path,
                &mut fully_checked,
                &mut errors,
                0,
            );
        }
    }
    errors
}

/// Recursive DFS helper for cycle detection.
///
/// - `in_path`: the current ancestry stack (grey nodes).
/// - `fully_checked`: nodes that have already been fully verified (black).
fn dfs_check(
    id: &RoleId,
    roles_by_id: &HashMap<&RoleId, &Role>,
    in_path: &mut Vec<RoleId>,
    fully_checked: &mut HashSet<RoleId>,
    errors: &mut Vec<RegistryError>,
    depth: usize,
) {
    if fully_checked.contains(id) {
        return;
    }
    if in_path.contains(id) {
        let role_name = roles_by_id
            .get(id)
            .map_or_else(|| id.to_string(), |r| r.name.clone());
        errors.push(RegistryError::RoleParentCycle { role_name });
        return;
    }
    if depth >= MAX_ROLE_PARENT_DEPTH {
        let role_name = roles_by_id
            .get(id)
            .map_or_else(|| id.to_string(), |r| r.name.clone());
        errors.push(RegistryError::RoleParentDepthExceeded {
            role_name,
            limit: MAX_ROLE_PARENT_DEPTH,
        });
        return;
    }

    in_path.push(id.clone());
    if let Some(role) = roles_by_id.get(id) {
        for parent_id in &role.parent_roles {
            dfs_check(
                parent_id,
                roles_by_id,
                in_path,
                fully_checked,
                errors,
                depth + 1,
            );
        }
    }
    in_path.pop();
    fully_checked.insert(id.clone());
}

// ---------------------------------------------------------------------------
// Re-export for callers that only need the error type
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Timestamp;
    use crate::rbac::types::RoleScopeKind;
    use uuid::Uuid;

    fn perm(name: &str) -> crate::rbac::Permission {
        crate::rbac::Permission::new(name).expect("valid perm in test")
    }

    fn pdef(name: &str) -> PermissionDefinition {
        PermissionDefinition {
            name: perm(name),
            display_name: name.to_string(),
            description: None,
            category: None,
        }
    }

    fn simple_role(name: &str) -> Role {
        Role {
            id: RoleId::generate(),
            realm_id: crate::core::RealmId::new(Uuid::nil()),
            name: name.to_string(),
            description: None,
            permissions: vec![],
            parent_roles: vec![],
            scope_kind: RoleScopeKind::Realm,
            status: crate::rbac::RoleStatus::Active,
            yaml_managed: false,
            created_at: Timestamp::from_micros(0),
            updated_at: Timestamp::from_micros(0),
        }
    }

    // ===== validate_bundle_name =====

    #[test]
    fn bundle_name_valid() {
        assert!(validate_bundle_name("read:docs").is_ok());
        assert!(validate_bundle_name("mcp:tools:invoke").is_ok());
        assert!(validate_bundle_name("a-b:c_d").is_ok());
    }

    #[test]
    fn bundle_name_no_colon() {
        assert!(validate_bundle_name("readdocs").is_err());
    }

    #[test]
    fn bundle_name_has_dot() {
        assert!(validate_bundle_name("read.docs").is_err());
    }

    #[test]
    fn bundle_name_empty() {
        assert!(validate_bundle_name("").is_err());
    }

    #[test]
    fn bundle_name_empty_segment() {
        assert!(validate_bundle_name("read::docs").is_err());
        assert!(validate_bundle_name(":docs").is_err());
    }

    // ===== TIER1_CLAIMS =====

    #[test]
    fn tier1_list_contains_required_claims() {
        for claim in &["iss", "sub", "oid", "permissions", "email_verified", "act"] {
            assert!(TIER1_CLAIMS.contains(claim), "{claim} must be Tier 1");
        }
    }

    // ===== TIER2_CLAIMS =====

    #[test]
    fn tier2_list_contains_known_claims() {
        for claim in &[
            "employee_id",
            "department",
            "roles",
            "groups",
            "permissions",
            "oid",
        ] {
            assert!(TIER2_CLAIMS.contains(claim), "{claim} must be Tier 2");
        }
    }

    // ===== validate_tier3_claim_name =====

    #[test]
    fn tier3_short_form_valid() {
        assert!(validate_tier3_claim_name("department").is_ok());
        assert!(validate_tier3_claim_name("employee_id").is_ok());
        assert!(validate_tier3_claim_name("cost_center2").is_ok());
        assert!(validate_tier3_claim_name("a").is_ok());
    }

    #[test]
    fn tier3_https_namespaced_valid() {
        assert!(validate_tier3_claim_name("https://acme.com/department").is_ok());
        assert!(validate_tier3_claim_name("https://example.com/custom/claim").is_ok());
    }

    #[test]
    fn tier3_http_rejected() {
        assert!(validate_tier3_claim_name("http://acme.com/department").is_err());
    }

    #[test]
    fn tier3_short_form_uppercase_rejected() {
        assert!(validate_tier3_claim_name("Department").is_err());
        assert!(validate_tier3_claim_name("DEPARTMENT").is_err());
    }

    #[test]
    fn tier3_short_form_starts_with_digit_rejected() {
        assert!(validate_tier3_claim_name("1department").is_err());
    }

    #[test]
    fn tier3_short_form_hyphen_rejected() {
        assert!(validate_tier3_claim_name("my-claim").is_err());
    }

    #[test]
    fn tier3_empty_rejected() {
        assert!(validate_tier3_claim_name("").is_err());
    }

    #[test]
    fn tier3_exceeds_64_chars_rejected() {
        let long = "a".repeat(65);
        assert!(validate_tier3_claim_name(&long).is_err());
    }

    #[test]
    fn tier3_https_exceeds_256_chars_rejected() {
        let long = format!("https://acme.com/{}", "x".repeat(300));
        assert!(validate_tier3_claim_name(&long).is_err());
    }

    // ===== classify_scope_string =====

    #[test]
    fn classify_oidc_scopes() {
        assert_eq!(
            classify_scope_string("openid"),
            Some(ScopeKind::OidcStandard)
        );
        assert_eq!(
            classify_scope_string("profile"),
            Some(ScopeKind::OidcStandard)
        );
    }

    #[test]
    fn classify_permission() {
        assert_eq!(
            classify_scope_string("docs.read"),
            Some(ScopeKind::Permission)
        );
    }

    #[test]
    fn classify_bundle() {
        assert_eq!(classify_scope_string("read:docs"), Some(ScopeKind::Bundle));
    }

    #[test]
    fn classify_unknown() {
        assert_eq!(classify_scope_string("bare_word"), None);
    }

    // ===== RealmPermissionRegistry::validate =====

    #[test]
    fn empty_registry_is_valid() {
        assert!(RealmPermissionRegistry::default().validate().is_ok());
    }

    #[test]
    fn registry_with_declared_perms_is_valid() {
        let reg = RealmPermissionRegistry {
            permissions: vec![pdef("docs.read")],
            roles: vec![{
                let mut r = simple_role("viewer");
                r.permissions = vec![perm("docs.read")];
                r
            }],
            scopes: vec![ScopeBundle {
                name: "read:docs".to_string(),
                display_name: "Read docs".to_string(),
                description: None,
                permissions: vec![perm("docs.read")],
            }],
            ..Default::default()
        };
        assert!(reg.validate().is_ok());
    }

    #[test]
    fn role_with_undeclared_perm_fails() {
        let reg = RealmPermissionRegistry {
            permissions: vec![pdef("docs.read")],
            roles: vec![{
                let mut r = simple_role("viewer");
                r.permissions = vec![perm("docs.write")]; // undeclared
                r
            }],
            ..Default::default()
        };
        let errs = reg.validate().expect_err("should fail");
        assert!(errs
            .iter()
            .any(|e| matches!(e, RegistryError::UndeclaredPermissionInRole { .. })));
    }
}
