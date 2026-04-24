//! Auth0 bundle importer.
//!
//! Auth0 does not expose a single unified export endpoint the way
//! Keycloak does. Instead, operators assemble a **bundle JSON** by
//! hitting several Management API endpoints (users export, clients,
//! organizations, roles) and passing the combined document to Hearth.
//! See `examples/auth0-migration-bundler/` for a reference Node script
//! that produces this shape.
//!
//! # Bundle schema
//!
//! ```json
//! {
//!   "tenant": { "name": "acme", "id": "<uuid-optional>" },
//!   "users":         [ /* Auth0 /api/v2/users shape */ ],
//!   "clients":       [ /* Auth0 /api/v2/clients shape */ ],
//!   "organizations": [ /* + flattened .members with user_id+roles */ ],
//!   "roles":         [ /* + flattened .assignments: [user_id...] */ ]
//! }
//! ```
//!
//! # Mapping summary
//!
//! | Auth0                                     | Hearth                                |
//! |-------------------------------------------|----------------------------------------|
//! | tenant (`name`, `id`)                     | realm                                  |
//! | user (`user_id`, `email`, …)              | user (id preserved only when UUID)     |
//! | `email_verified: false`                   | `UserStatus::PendingVerification`      |
//! | `blocked: true`                           | `UserStatus::Disabled`                 |
//! | `custom_password_hash`                    | PHC string (bcrypt passthrough, etc.)  |
//! | role assignments                          | `realm:<rid>#<role>@user:<uid>`        |
//! | client (`client_id`, `callbacks`, …)      | `OAuthClient`                          |
//! | organization + `.members[].roles[]`       | `Organization` + `add_member`          |
//!
//! # Out of scope (Phase 1)
//!
//! - Live Management API client (bundler is a separate Node script).
//! - MFA / TOTP / `WebAuthn` factor export.
//! - Federated-identity connections (Google / SAML / AD).
//! - Rules, Actions, Hooks.
//! - Delta / incremental sync.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde::Deserialize;

use crate::core::{ClientId, OrganizationId, RealmId, UserId};
use crate::identity::migration::auth0_credentials::parse_auth0_credential;
use crate::identity::migration::error::MigrationError;
use crate::identity::{
    CreateOrganizationRequest, CreateRealmRequest, IdentityEngine, ImportClientRequest,
    ImportUserRequest, MigrationReport, OrganizationRole, RawCredential, UserStatus,
};
use crate::rbac::{AssignRoleRequest, CreateRoleRequest, RbacEngine, RoleId, Scope, Subject};
use std::collections::HashMap as StdHashMap;

// ===== Bundle deserialization types =====

/// Top-level Auth0 migration bundle.
#[derive(Debug, Deserialize)]
pub struct Auth0Bundle {
    /// Auth0 tenant metadata.
    pub tenant: Auth0Tenant,
    /// Exported users. Defaults to empty.
    #[serde(default)]
    pub users: Vec<Auth0User>,
    /// Exported OAuth clients. Defaults to empty.
    #[serde(default)]
    pub clients: Vec<Auth0Client>,
    /// Exported organizations with embedded member lists. Defaults to empty.
    #[serde(default)]
    pub organizations: Vec<Auth0Organization>,
    /// Exported roles with embedded assignment lists. Defaults to empty.
    #[serde(default)]
    pub roles: Vec<Auth0Role>,
}

/// Auth0 tenant metadata.
#[derive(Debug, Deserialize)]
pub struct Auth0Tenant {
    /// Tenant name — becomes the Hearth realm name.
    pub name: String,
    /// Optional tenant UUID. Used as the `RealmId` when a valid UUID.
    #[serde(default)]
    pub id: Option<String>,
}

/// An Auth0 user record as returned by the Management API.
///
/// Only the fields Hearth imports are listed. Unknown fields are ignored
/// by `serde(default)` on the containing arrays.
#[derive(Debug, Deserialize)]
pub struct Auth0User {
    /// Opaque Auth0 user identifier, e.g. `auth0|abc123`, `google-oauth2|...`.
    pub user_id: String,
    /// Email. Users without an email are skipped with a warning.
    #[serde(default)]
    pub email: Option<String>,
    /// Whether Auth0 considered the email verified.
    #[serde(default)]
    pub email_verified: bool,
    /// Whether the account is blocked in Auth0.
    #[serde(default)]
    pub blocked: bool,
    /// Given name (first name).
    #[serde(default)]
    pub given_name: Option<String>,
    /// Family name (last name).
    #[serde(default)]
    pub family_name: Option<String>,
    /// Full display name — may be set even when given/family are absent.
    #[serde(default)]
    pub name: Option<String>,
    /// Nickname — fallback display-name source when other fields are empty.
    #[serde(default)]
    pub nickname: Option<String>,
    /// Auth0 bulk-import-shape credential, when exported.
    #[serde(default)]
    pub custom_password_hash: Option<Auth0PasswordHash>,
    /// RFC3339 creation timestamp, when exported.
    #[serde(default)]
    pub created_at: Option<String>,
}

/// Auth0 password hash envelope (matches the bulk-import schema).
#[derive(Debug, Deserialize)]
pub struct Auth0PasswordHash {
    /// Operator-declared algorithm name. Informative only — the PHC prefix
    /// on `hash.value` is the source of truth inside the parser.
    pub algorithm: String,
    /// The actual hash payload.
    pub hash: Auth0PasswordHashValue,
}

/// Inner `{ value: ... }` envelope for an Auth0 password hash.
#[derive(Debug, Deserialize)]
pub struct Auth0PasswordHashValue {
    /// PHC string for supported algorithms; raw value for unsupported.
    pub value: String,
}

/// Auth0 client (application) record.
#[derive(Debug, Deserialize)]
pub struct Auth0Client {
    /// Opaque Auth0 client identifier (base64url — never a UUID).
    pub client_id: String,
    /// Human-readable name.
    #[serde(default)]
    pub name: Option<String>,
    /// Plaintext client secret, when the bundler was granted
    /// `read:client_keys`. Hashed by Hearth on import.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Allowed redirect URIs.
    #[serde(default)]
    pub callbacks: Vec<String>,
    /// OAuth 2.0 grant types.
    #[serde(default)]
    pub grant_types: Vec<String>,
    /// Auth0 application type (`spa`, `native`, `regular_web`,
    /// `non_interactive`). `spa`/`native` are treated as public clients.
    #[serde(default)]
    pub app_type: Option<String>,
}

/// Auth0 organization record + member roster.
#[derive(Debug, Deserialize)]
pub struct Auth0Organization {
    /// Opaque Auth0 organization identifier.
    pub id: String,
    /// Short name. Becomes the Hearth slug (slugified if invalid).
    pub name: String,
    /// Human-readable name.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Member roster (bundler is expected to flatten this from
    /// `/api/v2/organizations/{id}/members`).
    #[serde(default)]
    pub members: Vec<Auth0OrganizationMember>,
}

/// An organization membership entry.
#[derive(Debug, Deserialize)]
pub struct Auth0OrganizationMember {
    /// Auth0 `user_id` of the member.
    pub user_id: String,
    /// Organization-scoped role names (`"admin"`, `"owner"`, arbitrary).
    #[serde(default)]
    pub roles: Vec<String>,
}

/// Auth0 role definition + assignment roster.
#[derive(Debug, Deserialize)]
pub struct Auth0Role {
    /// Opaque Auth0 role id.
    #[serde(default)]
    pub id: Option<String>,
    /// Role name (becomes the RBAC role name).
    pub name: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Auth0 `user_id` values assigned this role (bundler flattens
    /// `/api/v2/roles/{id}/users`).
    #[serde(default)]
    pub assignments: Vec<String>,
}

// ===== Importer =====

/// Options controlling how an Auth0 import executes.
#[derive(Debug, Clone, Default)]
pub struct Auth0ImportOptions {
    /// If `true`, no mutations are performed — the importer validates the
    /// bundle and returns a report with what *would* be written.
    pub dry_run: bool,
}

/// Orchestrates an Auth0 bundle import against a pair of engines.
pub struct Auth0Importer {
    identity: Arc<dyn IdentityEngine>,
    rbac: Arc<dyn RbacEngine>,
}

impl Auth0Importer {
    /// Creates a new importer bound to the given engines.
    pub fn new(identity: Arc<dyn IdentityEngine>, rbac: Arc<dyn RbacEngine>) -> Self {
        Self { identity, rbac }
    }

    /// Parses a bundle from JSON bytes.
    pub fn parse(bytes: &[u8]) -> Result<Auth0Bundle, MigrationError> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// Imports a bundle.
    ///
    /// Returns a [`MigrationReport`] describing what was written and any
    /// non-fatal warnings (e.g. users whose credentials used an
    /// unsupported algorithm). Per-item failures are recorded as warnings
    /// and the import continues; engine-level failures (I/O, storage,
    /// RBAC write) abort with `Err`.
    pub fn import_bundle(
        &self,
        bundle: &Auth0Bundle,
        requested_realm: Option<RealmId>,
        options: &Auth0ImportOptions,
    ) -> Result<MigrationReport, MigrationError> {
        let mut report = MigrationReport::default();

        let realm_id_hint = requested_realm.or_else(|| {
            bundle
                .tenant
                .id
                .as_deref()
                .and_then(|s| uuid::Uuid::parse_str(s).ok())
                .map(RealmId::new)
        });

        if options.dry_run {
            report.realm_id = realm_id_hint;
            report.users_imported = bundle.users.len();
            report.clients_imported = bundle.clients.len();
            report.role_assignments_written =
                bundle.roles.iter().map(|r| r.assignments.len()).sum();
            report.warnings.push(format!(
                "dry-run: no changes written to storage (tenant='{}')",
                bundle.tenant.name
            ));
            return Ok(report);
        }

        // 1. Create the realm.
        let realm_request = CreateRealmRequest {
            name: bundle.tenant.name.clone(),
            config: None,
        };
        let realm = self.identity.import_realm(&realm_request, realm_id_hint)?;
        let realm_id = realm.id().clone();
        report.realm_id = Some(realm_id.clone());

        // 2. Users — build the Auth0-id → Hearth UserId map along the way.
        let mut user_map: HashMap<String, UserId> = HashMap::new();
        for (idx, au) in bundle.users.iter().enumerate() {
            match self.import_single_user(&realm_id, au) {
                Ok(outcome) => {
                    report.users_imported += 1;
                    if outcome.credential_skipped {
                        report.users_with_skipped_credentials += 1;
                    }
                    for w in outcome.warnings {
                        report.warnings.push(w);
                    }
                    user_map.insert(au.user_id.clone(), outcome.user_id);
                }
                Err(e) => {
                    report.warnings.push(format!(
                        "failed to import user #{idx} ({}): {e}",
                        au.user_id
                    ));
                }
            }
        }

        // 3. Clients.
        for (idx, ac) in bundle.clients.iter().enumerate() {
            match self.import_single_client(&realm_id, ac) {
                Ok(()) => report.clients_imported += 1,
                Err(e) => {
                    report.warnings.push(format!(
                        "failed to import client #{idx} ('{}'): {e}",
                        ac.client_id
                    ));
                }
            }
        }

        // 4. Organizations.
        for (idx, ao) in bundle.organizations.iter().enumerate() {
            if let Err(e) = self.import_single_organization(&realm_id, ao, &user_map, &mut report) {
                report.warnings.push(format!(
                    "failed to import organization #{idx} ({}): {e}",
                    ao.name
                ));
            }
        }

        // 5. Realm-level role assignments.
        self.emit_role_assignments(&realm_id, &bundle.roles, &user_map, &mut report)?;

        Ok(report)
    }

    fn import_single_user(
        &self,
        realm_id: &RealmId,
        au: &Auth0User,
    ) -> Result<UserOutcome, MigrationError> {
        let email = au
            .email
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| MigrationError::ParseError {
                reason: format!("user {} has no email address", au.user_id),
            })?
            .to_string();

        let (first_name, last_name, display_name) = resolve_names(au, &email);

        let id = parse_user_uuid(&au.user_id);
        let status = auth0_user_status(au.blocked, au.email_verified);

        let mut warnings = Vec::new();
        let mut credential_skipped = false;
        let credential = match au.custom_password_hash.as_ref() {
            Some(raw) => match parse_auth0_credential(raw) {
                Ok(parsed) => Some(RawCredential {
                    phc_string: parsed.phc_string,
                    created_at_micros: None,
                }),
                Err(MigrationError::UnsupportedAlgorithm { algorithm }) => {
                    credential_skipped = true;
                    warnings.push(format!(
                        "user {email}: credential skipped (unsupported algorithm '{algorithm}')"
                    ));
                    None
                }
                Err(MigrationError::ParseError { reason }) => {
                    credential_skipped = true;
                    warnings.push(format!(
                        "user {email}: credential skipped (parse error: {reason})"
                    ));
                    None
                }
                Err(e) => return Err(e),
            },
            None => None,
        };

        let request = ImportUserRequest {
            id,
            email,
            display_name,
            first_name,
            last_name,
            status,
            credential,
        };

        let user = self.identity.import_user(realm_id, &request)?;
        Ok(UserOutcome {
            user_id: user.id().clone(),
            credential_skipped,
            warnings,
        })
    }

    fn import_single_client(
        &self,
        realm_id: &RealmId,
        ac: &Auth0Client,
    ) -> Result<(), MigrationError> {
        // Auth0 client_ids are opaque base64url — never UUIDs. Generate a
        // fresh ClientId so Hearth can address this client, and leave the
        // original Auth0 id in the name/description context (operator can
        // correlate via the bundle).
        let id: Option<ClientId> = None;

        let client_name = ac
            .name
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| ac.client_id.clone());

        // `spa` and `native` app types are public clients — no secret.
        let is_public = matches!(ac.app_type.as_deref(), Some("spa" | "native"));
        let client_secret = if is_public {
            None
        } else {
            ac.client_secret.clone().filter(|s| !s.is_empty())
        };

        let grant_types = if ac.grant_types.is_empty() {
            vec!["authorization_code".to_string()]
        } else {
            ac.grant_types.clone()
        };

        let request = ImportClientRequest {
            id,
            client_name,
            redirect_uris: ac.callbacks.clone(),
            client_secret,
            grant_types,
        };
        self.identity.import_client(realm_id, &request)?;
        Ok(())
    }

    fn import_single_organization(
        &self,
        realm_id: &RealmId,
        ao: &Auth0Organization,
        user_map: &HashMap<String, UserId>,
        report: &mut MigrationReport,
    ) -> Result<(), MigrationError> {
        let slug = slugify(&ao.name);
        let org_name = ao
            .display_name
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| ao.name.clone());

        if slug != ao.name {
            report.warnings.push(format!(
                "organization '{}': slug rewritten to '{slug}'",
                ao.name
            ));
        }

        let request = CreateOrganizationRequest {
            name: org_name,
            slug: slug.clone(),
            description: None,
            config: None,
        };
        let org = self.identity.create_organization(realm_id, &request)?;
        let org_id: OrganizationId = org.id().clone();

        for m in &ao.members {
            let Some(user_id) = user_map.get(&m.user_id) else {
                report.warnings.push(format!(
                    "organization '{slug}': member {} not found in user map; skipped",
                    m.user_id
                ));
                continue;
            };
            let role = map_org_role(&m.roles);
            if role.is_none() && !m.roles.is_empty() {
                report.warnings.push(format!(
                    "organization '{slug}': unknown role(s) {:?} for user {}, defaulting to Member",
                    m.roles, m.user_id
                ));
            }
            let role = role.unwrap_or(OrganizationRole::Member);
            if let Err(e) = self.identity.add_member(realm_id, &org_id, user_id, role) {
                report.warnings.push(format!(
                    "organization '{slug}': failed to add member {}: {e}",
                    m.user_id
                ));
            }
        }

        Ok(())
    }

    fn emit_role_assignments(
        &self,
        realm_id: &RealmId,
        roles: &[Auth0Role],
        user_map: &HashMap<String, UserId>,
        report: &mut MigrationReport,
    ) -> Result<(), MigrationError> {
        // Ensure every role exists in RBAC, caching IDs.
        let mut role_ids: StdHashMap<String, RoleId> = StdHashMap::new();
        for role in roles {
            let id = match self.rbac.get_role_by_name(realm_id, &role.name)? {
                Some(r) => r.id,
                None => {
                    let created = self.rbac.create_role(
                        realm_id,
                        &CreateRoleRequest {
                            name: role.name.clone(),
                            description: role.description.clone(),
                            permissions: Vec::new(),
                            parent_roles: Vec::new(),
                        },
                    )?;
                    created.id
                }
            };
            role_ids.insert(role.name.clone(), id);
        }

        let mut seen: HashSet<(String, String)> = HashSet::new();
        let mut written = 0usize;

        for role in roles {
            let Some(role_id) = role_ids.get(&role.name) else {
                continue;
            };
            for assignment in &role.assignments {
                let Some(user_id) = user_map.get(assignment) else {
                    report.warnings.push(format!(
                        "role '{}': assignment for unknown user {assignment} skipped",
                        role.name
                    ));
                    continue;
                };
                let dedup = (role.name.clone(), user_id.as_uuid().to_string());
                if !seen.insert(dedup) {
                    continue;
                }
                match self.rbac.assign_role(
                    realm_id,
                    &AssignRoleRequest {
                        subject: Subject::User(user_id.clone()),
                        role_id: role_id.clone(),
                        scope: Scope::Realm,
                        assigned_by: None,
                    },
                ) {
                    Ok(_) => written += 1,
                    Err(e) => {
                        report.warnings.push(format!(
                            "failed to assign role '{}' to user {user_id}: {e}",
                            role.name
                        ));
                    }
                }
            }
        }
        report.role_assignments_written = written;
        Ok(())
    }
}

/// Per-user result passed back from `import_single_user`.
struct UserOutcome {
    user_id: UserId,
    credential_skipped: bool,
    warnings: Vec<String>,
}

/// Strips a single Auth0 provider prefix (`auth0|`, `google-oauth2|`,
/// `samlp|`, …). Returns the suffix without the `|`.
fn strip_auth0_prefix(raw: &str) -> &str {
    match raw.split_once('|') {
        Some((_, rest)) => rest,
        None => raw,
    }
}

/// If the stripped suffix parses as a UUID, returns it as a `UserId`.
/// Otherwise returns `None` so `import_user` generates a fresh one.
fn parse_user_uuid(raw: &str) -> Option<UserId> {
    let suffix = strip_auth0_prefix(raw);
    uuid::Uuid::parse_str(suffix).ok().map(UserId::new)
}

/// Resolves `(first_name, last_name, display_name)` for an Auth0 user.
///
/// Precedence:
/// 1. `given_name` / `family_name` → first/last directly.
/// 2. `name` is treated as display name unless given/family are missing,
///    in which case it's split on the last space for first/last.
/// 3. `nickname` → display name fallback.
/// 4. Email local-part → final display-name fallback. First/last remain
///    empty strings (allowed by the engine).
fn resolve_names(au: &Auth0User, email: &str) -> (String, String, String) {
    let given = au.given_name.clone().unwrap_or_default();
    let family = au.family_name.clone().unwrap_or_default();

    let (first_name, last_name) = match (!given.is_empty(), !family.is_empty()) {
        (true, _) | (_, true) => (given.clone(), family.clone()),
        _ => split_name_fallback(au.name.as_deref()),
    };

    let display_name = au
        .name
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| match (first_name.is_empty(), last_name.is_empty()) {
            (false, false) => Some(format!("{first_name} {last_name}")),
            (false, true) => Some(first_name.clone()),
            (true, false) => Some(last_name.clone()),
            _ => None,
        })
        .or_else(|| au.nickname.clone())
        .unwrap_or_else(|| email.split('@').next().unwrap_or("user").to_string());

    (first_name, last_name, display_name)
}

/// Splits a full name on the last space, returning `(first, last)`.
/// Used only when `given_name` / `family_name` are both absent.
fn split_name_fallback(name: Option<&str>) -> (String, String) {
    let Some(name) = name.map(str::trim).filter(|s| !s.is_empty()) else {
        return (String::new(), String::new());
    };
    match name.rsplit_once(' ') {
        Some((first, last)) => (first.trim().to_string(), last.trim().to_string()),
        None => (name.to_string(), String::new()),
    }
}

/// Maps Auth0's user status flags to Hearth's `UserStatus`.
///
/// Precedence: blocked > `email_verified`. A blocked account stays disabled
/// regardless of verification state so the migration preserves the
/// security posture.
fn auth0_user_status(blocked: bool, email_verified: bool) -> UserStatus {
    if blocked {
        UserStatus::Disabled
    } else if email_verified {
        UserStatus::Active
    } else {
        UserStatus::PendingVerification
    }
}

/// Produces a best-effort slug from an arbitrary name. Returns a string
/// that satisfies Hearth's slug rules (3-63 lowercase alphanumeric+hyphens,
/// no leading/trailing hyphens, no consecutive hyphens).
fn slugify(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut last_was_hyphen = true; // suppress leading hyphen
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            last_was_hyphen = false;
        } else if !last_was_hyphen {
            out.push('-');
            last_was_hyphen = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    // Minimum length — pad with a stable marker so the engine accepts it.
    if out.len() < 3 {
        let mut padded = out;
        while padded.len() < 3 {
            padded.push('x');
        }
        padded
    } else if out.len() > 63 {
        out.truncate(63);
        while out.ends_with('-') {
            out.pop();
        }
        out
    } else {
        out
    }
}

/// Maps a list of Auth0 role strings to a single `OrganizationRole`.
///
/// Precedence: any `owner` → Owner; any `admin` → Admin; otherwise
/// Member. Returns `None` when the list is non-empty but no role name
/// maps — caller records a warning.
fn map_org_role(roles: &[String]) -> Option<OrganizationRole> {
    if roles.is_empty() {
        return Some(OrganizationRole::Member);
    }
    let lowered: Vec<String> = roles.iter().map(|r| r.to_ascii_lowercase()).collect();
    if lowered.iter().any(|r| r == "owner") {
        return Some(OrganizationRole::Owner);
    }
    if lowered.iter().any(|r| r == "admin") {
        return Some(OrganizationRole::Admin);
    }
    if lowered.iter().any(|r| r == "member") {
        return Some(OrganizationRole::Member);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_bundle() {
        let json = br#"{
            "tenant": { "name": "acme" },
            "users": [{"user_id": "auth0|abc", "email": "a@b.test"}]
        }"#;
        let bundle = Auth0Importer::parse(json).expect("parse");
        assert_eq!(bundle.tenant.name, "acme");
        assert_eq!(bundle.users.len(), 1);
        assert!(bundle.clients.is_empty());
        assert!(bundle.organizations.is_empty());
        assert!(bundle.roles.is_empty());
    }

    #[test]
    fn parses_bundle_with_all_top_level_keys() {
        let json = br#"{
            "tenant": { "name": "acme", "id": "550e8400-e29b-41d4-a716-446655440000" },
            "users": [],
            "clients": [],
            "organizations": [],
            "roles": []
        }"#;
        let bundle = Auth0Importer::parse(json).expect("parse");
        assert_eq!(
            bundle.tenant.id.as_deref(),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
    }

    #[test]
    fn ignores_unknown_fields() {
        let json = br#"{
            "tenant": { "name": "acme", "unknown": 42 },
            "extra_top_level": ["ignored"]
        }"#;
        let bundle = Auth0Importer::parse(json).expect("parse");
        assert_eq!(bundle.tenant.name, "acme");
    }

    #[test]
    fn strip_prefix_handles_bare_and_prefixed() {
        assert_eq!(strip_auth0_prefix("auth0|abc123"), "abc123");
        assert_eq!(strip_auth0_prefix("google-oauth2|117xxx"), "117xxx");
        assert_eq!(strip_auth0_prefix("samlp|azure|foo"), "azure|foo"); // only strips first
        assert_eq!(strip_auth0_prefix("no-separator"), "no-separator");
    }

    #[test]
    fn parse_user_uuid_preserves_uuid_suffix() {
        let id = parse_user_uuid("auth0|a1111111-1111-4111-8111-111111111111");
        assert!(id.is_some());
    }

    #[test]
    fn parse_user_uuid_returns_none_for_opaque_suffix() {
        assert!(parse_user_uuid("auth0|abc123").is_none());
        assert!(parse_user_uuid("google-oauth2|117123456789").is_none());
    }

    #[test]
    fn auth0_user_status_prioritises_blocked_over_verified() {
        assert_eq!(auth0_user_status(true, true), UserStatus::Disabled);
        assert_eq!(auth0_user_status(true, false), UserStatus::Disabled);
        assert_eq!(auth0_user_status(false, true), UserStatus::Active);
        assert_eq!(
            auth0_user_status(false, false),
            UserStatus::PendingVerification
        );
    }

    #[test]
    fn slugify_normalises_common_org_names() {
        assert_eq!(slugify("Acme Engineering"), "acme-engineering");
        assert_eq!(slugify("acme-eng"), "acme-eng");
        assert_eq!(slugify("  Leading and Trailing  "), "leading-and-trailing");
        assert_eq!(slugify("ACME_CORP!!!"), "acme-corp");
        assert_eq!(slugify("ACME"), "acme");
    }

    #[test]
    fn slugify_pads_short_slugs() {
        assert!(slugify("A").len() >= 3);
        assert_eq!(slugify("").len(), 3);
    }

    #[test]
    fn slugify_truncates_overlong_slugs() {
        let long = "a".repeat(200);
        assert!(slugify(&long).len() <= 63);
    }

    #[test]
    fn map_org_role_prefers_owner_over_admin() {
        assert_eq!(
            map_org_role(&["admin".to_string(), "owner".to_string()]),
            Some(OrganizationRole::Owner)
        );
    }

    #[test]
    fn map_org_role_recognises_case_insensitive() {
        assert_eq!(
            map_org_role(&["Admin".to_string()]),
            Some(OrganizationRole::Admin)
        );
        assert_eq!(
            map_org_role(&["OWNER".to_string()]),
            Some(OrganizationRole::Owner)
        );
    }

    #[test]
    fn map_org_role_empty_list_is_member() {
        assert_eq!(map_org_role(&[]), Some(OrganizationRole::Member));
    }

    #[test]
    fn map_org_role_unknown_names_returns_none() {
        assert_eq!(map_org_role(&["custom-role".to_string()]), None);
    }

    #[test]
    fn resolve_names_uses_given_and_family_when_present() {
        let au = Auth0User {
            user_id: "auth0|a".to_string(),
            email: None,
            email_verified: false,
            blocked: false,
            given_name: Some("Alice".to_string()),
            family_name: Some("Anderson".to_string()),
            name: None,
            nickname: None,
            custom_password_hash: None,
            created_at: None,
        };
        let (f, l, d) = resolve_names(&au, "alice@x");
        assert_eq!(f, "Alice");
        assert_eq!(l, "Anderson");
        assert_eq!(d, "Alice Anderson");
    }

    #[test]
    fn resolve_names_splits_full_name_when_given_family_absent() {
        let au = Auth0User {
            user_id: "auth0|a".to_string(),
            email: None,
            email_verified: false,
            blocked: false,
            given_name: None,
            family_name: None,
            name: Some("Grace Hopper".to_string()),
            nickname: None,
            custom_password_hash: None,
            created_at: None,
        };
        let (f, l, d) = resolve_names(&au, "gh@x");
        assert_eq!(f, "Grace");
        assert_eq!(l, "Hopper");
        assert_eq!(d, "Grace Hopper");
    }

    #[test]
    fn resolve_names_falls_back_to_email_local_part() {
        let au = Auth0User {
            user_id: "auth0|a".to_string(),
            email: None,
            email_verified: false,
            blocked: false,
            given_name: None,
            family_name: None,
            name: None,
            nickname: None,
            custom_password_hash: None,
            created_at: None,
        };
        let (f, l, d) = resolve_names(&au, "alice@acme.test");
        assert_eq!(f, "");
        assert_eq!(l, "");
        assert_eq!(d, "alice");
    }
}
