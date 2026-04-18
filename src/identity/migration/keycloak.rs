//! Keycloak realm-export importer.
//!
//! Parses a Keycloak "realm export" JSON file and imports its tenant,
//! users, OAuth clients, and realm roles into Hearth via the
//! `IdentityEngine` and `AuthzEngine` traits.
//!
//! # Mapping
//!
//! | Keycloak                         | Hearth                                |
//! |----------------------------------|---------------------------------------|
//! | realm (`id`, `realm`)            | tenant                                |
//! | user (`id`, `email`, …)          | user (id preserved when a valid UUID) |
//! | user → realmRoles                | authz tuple `realm:<tid>#<role>@user:<uid>` |
//! | client                           | `OAuthClient`                         |
//! | password credential (pbkdf2-s256)| PHC string, verifies natively         |
//!
//! # Out of scope
//!
//! - Groups and composite roles
//! - Client roles (only realm roles are mapped)
//! - Federated identity providers
//! - Required actions (email verification prompts, etc.)

use std::sync::Arc;

use serde::Deserialize;

use crate::authz::{AuthorizationEngine, ObjectRef, RelationshipTuple, SubjectRef, TupleWrite};
use crate::core::{ClientId, TenantId, UserId};
use crate::identity::migration::credentials::{parse_keycloak_credential, KeycloakCredential};
use crate::identity::migration::error::MigrationError;
use crate::identity::{
    CreateTenantRequest, IdentityEngine, ImportClientRequest, ImportUserRequest, MigrationReport,
    RawCredential, UserStatus,
};

/// A minimal deserialization of the subset of a Keycloak realm export
/// that this importer consumes. Unknown fields are silently ignored.
#[derive(Debug, Deserialize)]
pub struct KeycloakRealmExport {
    /// Realm UUID, used as the Hearth tenant ID when it parses cleanly.
    pub id: Option<String>,
    /// Realm identifier (short name), used as the tenant display name.
    pub realm: String,
    /// Users in the realm. Defaults to empty if absent.
    #[serde(default)]
    pub users: Vec<KeycloakUser>,
    /// OAuth/OIDC clients in the realm. Defaults to empty if absent.
    #[serde(default)]
    pub clients: Vec<KeycloakClient>,
    /// Realm-scoped roles. `roles.realm` is the array we care about;
    /// `roles.client` is ignored for now.
    #[serde(default)]
    pub roles: KeycloakRoles,
}

/// A Keycloak user record.
#[derive(Debug, Deserialize)]
pub struct KeycloakUser {
    /// User UUID as assigned by Keycloak.
    pub id: Option<String>,
    /// Email address. Keycloak does not strictly require this, but Hearth
    /// does; users without an email are skipped with a warning.
    pub email: Option<String>,
    /// First name — concatenated with `last_name` to form a display name.
    #[serde(default, rename = "firstName")]
    pub first_name: Option<String>,
    /// Last name — concatenated with `first_name` to form a display name.
    #[serde(default, rename = "lastName")]
    pub last_name: Option<String>,
    /// Optional username fallback for display purposes.
    #[serde(default)]
    pub username: Option<String>,
    /// Whether the account is enabled. Maps to `UserStatus::Active` vs
    /// `Disabled`.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Attached credentials (only `password` is imported).
    #[serde(default)]
    pub credentials: Vec<KeycloakCredential>,
    /// Realm-scoped role assignments.
    #[serde(default, rename = "realmRoles")]
    pub realm_roles: Vec<String>,
}

fn default_enabled() -> bool {
    true
}

/// A Keycloak client registration.
#[derive(Debug, Deserialize)]
pub struct KeycloakClient {
    /// Internal Keycloak UUID for the client registration.
    pub id: Option<String>,
    /// OAuth `client_id` (human-visible short identifier).
    #[serde(rename = "clientId")]
    pub client_id: String,
    /// Human-readable display name.
    #[serde(default)]
    pub name: Option<String>,
    /// Plaintext client secret (Keycloak stores these in the clear in
    /// realm exports).
    #[serde(default)]
    pub secret: Option<String>,
    /// Allowed redirect URIs.
    #[serde(default, rename = "redirectUris")]
    pub redirect_uris: Vec<String>,
    /// Whether the client is public (no secret required).
    #[serde(default, rename = "publicClient")]
    pub public_client: bool,
    /// Enabled flag. Disabled clients are skipped entirely.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

/// Realm and client role collections.
#[derive(Debug, Default, Deserialize)]
pub struct KeycloakRoles {
    /// Realm-scoped roles (the only kind imported).
    #[serde(default)]
    pub realm: Vec<KeycloakRole>,
}

/// A Keycloak role definition.
#[derive(Debug, Deserialize)]
pub struct KeycloakRole {
    /// Role name — used verbatim as the Zanzibar relation name.
    pub name: String,
    /// Optional human-readable description.
    #[serde(default)]
    pub description: Option<String>,
}

/// Options controlling how an import executes.
#[derive(Debug, Clone, Default)]
pub struct ImportOptions {
    /// If `true`, no mutations are performed — the importer validates the
    /// export and returns a report with what *would* be written.
    pub dry_run: bool,
}

/// Orchestrates a Keycloak realm import against a pair of engines.
///
/// The importer holds `Arc<dyn ...>` handles so the CLI can construct it
/// once at startup and re-use it across invocations.
pub struct KeycloakImporter {
    identity: Arc<dyn IdentityEngine>,
    authz: Arc<dyn AuthorizationEngine>,
}

impl KeycloakImporter {
    /// Creates a new importer bound to the given engines.
    pub fn new(identity: Arc<dyn IdentityEngine>, authz: Arc<dyn AuthorizationEngine>) -> Self {
        Self { identity, authz }
    }

    /// Parses a Keycloak realm export from JSON bytes.
    pub fn parse(bytes: &[u8]) -> Result<KeycloakRealmExport, MigrationError> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// Imports a realm export.
    ///
    /// Returns a [`MigrationReport`] describing what was written and any
    /// non-fatal warnings (e.g. users whose credentials used an
    /// unsupported KDF). Per-item errors on users/clients/tuples are
    /// recorded as warnings and the import continues; engine-level
    /// failures (I/O, storage, etc.) abort with `Err`.
    pub fn import_realm(
        &self,
        export: &KeycloakRealmExport,
        requested_tenant: Option<TenantId>,
        options: &ImportOptions,
    ) -> Result<MigrationReport, MigrationError> {
        let mut report = MigrationReport::default();

        // 1. Resolve/create the tenant. Keycloak's realm `id` is a UUID
        //    in newer exports; fall back to generating one if the field
        //    is absent or malformed. This lets older realm dumps still
        //    import successfully.
        let tenant_id_hint = requested_tenant.or_else(|| {
            export
                .id
                .as_deref()
                .and_then(|s| uuid::Uuid::parse_str(s).ok())
                .map(TenantId::new)
        });

        if options.dry_run {
            report.tenant_id = tenant_id_hint;
            report.users_imported = export.users.len();
            // Only enabled clients would actually be written; a
            // disabled confidential client is simply skipped in the
            // live path.
            report.clients_imported = export.clients.iter().filter(|c| c.enabled).count();
            report.tuples_written = export.users.iter().map(|u| u.realm_roles.len()).sum();
            report.warnings.push(format!(
                "dry-run: no changes written to storage (realm='{}')",
                export.realm
            ));
            return Ok(report);
        }

        let tenant_request = CreateTenantRequest {
            name: export.realm.clone(),
            config: None,
        };
        let tenant = self
            .identity
            .import_tenant(&tenant_request, tenant_id_hint)?;
        let tenant_id = tenant.id().clone();
        report.tenant_id = Some(tenant_id.clone());

        // 2. Import users and remember their Hearth IDs so we can emit
        //    role tuples keyed by the *Hearth* user_id (which may be
        //    different from the Keycloak id when parsing failed).
        let mut user_ids_by_keycloak_key: std::collections::HashMap<String, UserId> =
            std::collections::HashMap::new();

        for (idx, ku) in export.users.iter().enumerate() {
            match self.import_single_user(&tenant_id, ku) {
                Ok(outcome) => {
                    report.users_imported += 1;
                    if outcome.credential_skipped {
                        report.users_with_skipped_credentials += 1;
                    }
                    for w in outcome.warnings {
                        report.warnings.push(w);
                    }
                    // Index by the Keycloak id if present, otherwise by
                    // a synthetic "index:N" key so we can still correlate
                    // role assignments below.
                    let key = ku.id.clone().unwrap_or_else(|| format!("__idx:{idx}"));
                    user_ids_by_keycloak_key.insert(key, outcome.user_id);
                }
                Err(e) => {
                    report
                        .warnings
                        .push(format!("failed to import user #{idx}: {e}"));
                }
            }
        }

        // 3. Import clients.
        for (idx, kc) in export.clients.iter().enumerate() {
            if !kc.enabled {
                report
                    .warnings
                    .push(format!("skipped disabled client '{}'", kc.client_id));
                continue;
            }
            match self.import_single_client(&tenant_id, kc) {
                Ok(()) => report.clients_imported += 1,
                Err(e) => {
                    report.warnings.push(format!(
                        "failed to import client #{idx} ('{}'): {e}",
                        kc.client_id
                    ));
                }
            }
        }

        // 4. Emit role tuples and surface reconciliation warnings.
        self.emit_role_tuples(&tenant_id, export, &user_ids_by_keycloak_key, &mut report)?;
        warn_undeclared_roles(export, &mut report);

        Ok(report)
    }

    /// Converts each user's `realmRoles` list into Zanzibar tuples of the
    /// form `realm:<tid> <role> user:<uid>` and writes them in a single
    /// batched `write_tuples` call. Per-tuple validation failures are
    /// recorded as warnings rather than aborting the import.
    fn emit_role_tuples(
        &self,
        tenant_id: &TenantId,
        export: &KeycloakRealmExport,
        user_ids_by_keycloak_key: &std::collections::HashMap<String, UserId>,
        report: &mut MigrationReport,
    ) -> Result<(), MigrationError> {
        let realm_object_id = tenant_id.as_uuid().to_string();
        let mut tuple_writes: Vec<TupleWrite> = Vec::new();

        for (idx, ku) in export.users.iter().enumerate() {
            let key = ku.id.clone().unwrap_or_else(|| format!("__idx:{idx}"));
            let Some(user_id) = user_ids_by_keycloak_key.get(&key) else {
                continue; // user import failed above; already warned
            };

            for role_name in &ku.realm_roles {
                match build_role_tuple(&realm_object_id, role_name, user_id) {
                    Ok(w) => tuple_writes.push(w),
                    Err(e) => {
                        report
                            .warnings
                            .push(format!("skipped role tuple {role_name}@{user_id}: {e}"));
                    }
                }
            }
        }

        if !tuple_writes.is_empty() {
            self.authz.write_tuples(tenant_id, &tuple_writes)?;
            report.tuples_written = tuple_writes.len();
        }
        Ok(())
    }

    fn import_single_user(
        &self,
        tenant_id: &TenantId,
        ku: &KeycloakUser,
    ) -> Result<UserOutcome, MigrationError> {
        let email = ku
            .email
            .as_deref()
            .ok_or_else(|| MigrationError::ParseError {
                reason: format!(
                    "user {} has no email address",
                    ku.id.as_deref().unwrap_or("<unknown>")
                ),
            })?
            .to_string();

        let display_name = match (ku.first_name.as_deref(), ku.last_name.as_deref()) {
            (Some(f), Some(l)) if !f.is_empty() && !l.is_empty() => format!("{f} {l}"),
            (Some(f), _) if !f.is_empty() => f.to_string(),
            (_, Some(l)) if !l.is_empty() => l.to_string(),
            _ => ku
                .username
                .clone()
                .unwrap_or_else(|| email.split('@').next().unwrap_or("user").to_string()),
        };

        let id = ku
            .id
            .as_deref()
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .map(UserId::new);

        let status = if ku.enabled {
            UserStatus::Active
        } else {
            UserStatus::Disabled
        };

        let mut warnings = Vec::new();
        let mut credential_skipped = false;
        let credential = match ku.credentials.iter().find(|c| c.kind == "password") {
            Some(password_cred) => match parse_keycloak_credential(password_cred) {
                Ok(parsed) => Some(RawCredential {
                    phc_string: parsed.phc_string,
                    created_at_micros: password_cred.created_date.map(|ms| ms * 1_000),
                }),
                Err(MigrationError::UnsupportedAlgorithm { algorithm }) => {
                    credential_skipped = true;
                    warnings.push(format!(
                        "user {email}: credential skipped (unsupported algorithm '{algorithm}')"
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
            status,
            credential,
        };

        let user = self.identity.import_user(tenant_id, &request)?;
        Ok(UserOutcome {
            user_id: user.id().clone(),
            credential_skipped,
            warnings,
        })
    }

    fn import_single_client(
        &self,
        tenant_id: &TenantId,
        kc: &KeycloakClient,
    ) -> Result<(), MigrationError> {
        let id = kc
            .id
            .as_deref()
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .map(ClientId::new);

        let client_name = kc.name.clone().unwrap_or_else(|| kc.client_id.clone());

        let client_secret = if kc.public_client {
            None
        } else {
            kc.secret.clone()
        };

        // Keycloak realm exports don't always list every grant type;
        // default to authorization_code for confidential + public flows.
        // Additional grant types can be added post-import via the admin
        // API.
        let grant_types = vec!["authorization_code".to_string()];

        let request = ImportClientRequest {
            id,
            client_name,
            redirect_uris: kc.redirect_uris.clone(),
            client_secret,
            grant_types,
        };

        self.identity.import_client(tenant_id, &request)?;
        Ok(())
    }
}

/// Per-user result passed back from `import_single_user`.
struct UserOutcome {
    user_id: UserId,
    credential_skipped: bool,
    warnings: Vec<String>,
}

/// Emits a report warning for each role name that appears in a user's
/// `realmRoles` list without being declared in `roles.realm`. Keycloak
/// itself tolerates this state (role tuples can exist without a matching
/// role definition) but it's worth surfacing so operators can reconcile.
fn warn_undeclared_roles(export: &KeycloakRealmExport, report: &mut MigrationReport) {
    let known: std::collections::HashSet<&str> =
        export.roles.realm.iter().map(|r| r.name.as_str()).collect();
    let used: std::collections::HashSet<&str> = export
        .users
        .iter()
        .flat_map(|u| u.realm_roles.iter().map(String::as_str))
        .collect();
    for undeclared in used.difference(&known) {
        report.warnings.push(format!(
            "role '{undeclared}' is used but not declared in realm.roles.realm"
        ));
    }
}

/// Builds a `realm:<tid> <role> user:<uid>` tuple write.
fn build_role_tuple(
    realm_id: &str,
    role_name: &str,
    user_id: &UserId,
) -> Result<TupleWrite, MigrationError> {
    let object = ObjectRef::new("realm", realm_id)?;
    let subject = SubjectRef::direct("user", &user_id.as_uuid().to_string())?;
    let tuple = RelationshipTuple::new(object, role_name, subject)?;
    Ok(TupleWrite::Touch(tuple))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_realm_export() {
        let json = br#"{
            "id": "b0000000-0000-0000-0000-000000000001",
            "realm": "acme",
            "users": [
                {
                    "id": "a1111111-1111-1111-1111-111111111111",
                    "email": "alice@example.com",
                    "firstName": "Alice",
                    "lastName": "Smith",
                    "enabled": true,
                    "credentials": [],
                    "realmRoles": ["admin"]
                }
            ],
            "clients": [
                {
                    "clientId": "my-app",
                    "enabled": true,
                    "redirectUris": ["https://example.com/callback"],
                    "publicClient": false,
                    "secret": "s3cret"
                }
            ],
            "roles": {
                "realm": [
                    {"name": "admin"}
                ]
            }
        }"#;

        let export = KeycloakImporter::parse(json).expect("parse");
        assert_eq!(export.realm, "acme");
        assert_eq!(export.users.len(), 1);
        assert_eq!(export.users[0].email.as_deref(), Some("alice@example.com"));
        assert_eq!(export.users[0].realm_roles, vec!["admin".to_string()]);
        assert_eq!(export.clients.len(), 1);
        assert_eq!(export.clients[0].client_id, "my-app");
        assert_eq!(export.clients[0].secret.as_deref(), Some("s3cret"));
        assert_eq!(export.roles.realm.len(), 1);
    }

    #[test]
    fn ignores_unknown_top_level_fields() {
        let json = br#"{
            "realm": "acme",
            "somethingElse": {"deeply": "nested"},
            "requiredActions": ["VERIFY_EMAIL"]
        }"#;

        let export = KeycloakImporter::parse(json).expect("parse");
        assert_eq!(export.realm, "acme");
        assert!(export.users.is_empty());
    }

    #[test]
    fn build_role_tuple_rejects_invalid_role() {
        // A role name containing forbidden characters is rejected by
        // the authz layer rather than silently persisted.
        let res = build_role_tuple(
            "00000000-0000-0000-0000-000000000001",
            "", // empty relation is invalid
            &UserId::generate(),
        );
        assert!(res.is_err());
    }
}
