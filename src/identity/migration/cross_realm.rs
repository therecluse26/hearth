//! Cross-realm user migration.
//!
//! Implements the `migrate_from` / `copy_from` feature: moves (or copies)
//! user records, credentials, org memberships, and RBAC role assignments from
//! one realm to another at server startup.
//!
//! # Key-prefix inventory (per user, realm-scoped)
//!
//! Copied:
//! - `usr:id:{user_uuid}` — primary user record
//! - `usr:email:{email}` — email-to-user index entry
//! - `cred:user:{user_uuid}` — credential (argon2id / pbkdf2 / bcrypt hash)
//! - `cred:history:{user_uuid}` — password history (for reuse enforcement)
//! - `mfa:totp:{user_uuid}` — TOTP state
//! - `webauthn:cred:{user_uuid}:{cred_id}` — WebAuthn credential records
//! - `webauthn:disc:{cred_id}` — discoverable-key index (derived from cred values)
//! - org membership keys (conditional on `opts.orgs`)
//!
//! Skipped (ephemeral / realm-specific):
//! - `ses:id:*`, `ses:user:*` — sessions
//! - `magic:link:*` — magic links
//! - `email:verify:*` — email verification tokens
//! - `rst:token:*` — password reset tokens
//! - `fed:ext_fwd:*`, `fed:ext:*` — federated identity links
//! - `scim:ext_user_fwd:*` — SCIM external IDs
//!
//! RBAC assignments are migrated via the `RbacEngine` trait: roles are
//! translated by **name** from source to destination realm. Assignments
//! referencing roles that don't exist in the destination, and org-scoped
//! assignments when `opts.orgs == false`, are skipped with a warning.

use tracing::{info, warn};

use crate::config::MigrateConflictPolicy;
use crate::core::{RealmId, UserId};
use crate::identity::keys;
use crate::identity::{IdentityEngine, IdentityError};
use crate::rbac::{AssignRoleRequest, RbacEngine, Scope, Subject};
use crate::storage::StorageEngine;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Options for a cross-realm migration run.
#[derive(Debug, Clone)]
pub struct CrossRealmMigrateOptions {
    /// `true` = move semantics (source data deleted after copy).
    /// `false` = copy semantics (source left intact).
    pub move_semantics: bool,
    /// Whether to migrate user records and credentials. Default: `true`.
    pub users: bool,
    /// Whether to migrate org memberships. Default: `true`.
    pub orgs: bool,
    /// Conflict policy when the destination already has a user with the same
    /// email.
    pub on_conflict: MigrateConflictPolicy,
}

impl Default for CrossRealmMigrateOptions {
    fn default() -> Self {
        Self {
            move_semantics: true,
            users: true,
            orgs: true,
            on_conflict: MigrateConflictPolicy::default(),
        }
    }
}

/// Outcome of a cross-realm migration run.
#[derive(Debug, Default)]
pub struct CrossRealmMigrationReport {
    /// Number of users successfully moved/copied to the destination.
    pub migrated: u64,
    /// Number of users skipped (only set when `on_conflict: skip`).
    pub skipped: u64,
    /// Emails of users that conflict with existing destination users.
    /// Non-empty only when `on_conflict: error`.
    pub conflicts: Vec<String>,
    /// Number of RBAC role assignments translated and written.
    pub role_assignments_translated: u64,
    /// Number of role assignments skipped (role not found in destination).
    pub role_assignments_skipped: u64,
}

/// Error returned when `on_conflict: error` and one or more conflicts exist.
#[derive(Debug)]
pub struct MigrationConflictError {
    /// Email addresses that already exist in the destination realm.
    pub emails: Vec<String>,
}

impl std::fmt::Display for MigrationConflictError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cross-realm migration aborted: {} user(s) already exist in destination realm: {}",
            self.emails.len(),
            self.emails.join(", ")
        )
    }
}

impl From<MigrationConflictError> for IdentityError {
    fn from(e: MigrationConflictError) -> Self {
        IdentityError::ConfigInvalid {
            realm_name: "<cross-realm-migration>".to_string(),
            errors: e
                .emails
                .iter()
                .map(|email| crate::rbac::RegistryError::InvalidPermissionName {
                    name: email.clone(),
                    reason: "email already exists in destination realm".to_string(),
                })
                .collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Executes a cross-realm user migration.
///
/// Migrates all users from `src_realm_id` to `dst_realm_id` according to
/// `opts`. Progress is tracked per-user in the system realm so a crash during
/// migration can be resumed idempotently on the next startup.
///
/// Returns `Err` only when `on_conflict = error` **and** conflicts were found.
/// All other errors (I/O, RBAC) are logged as warnings and the migration
/// continues.
#[allow(clippy::too_many_lines)]
pub fn execute_cross_realm_migration(
    engine: &dyn IdentityEngine,
    rbac: &dyn RbacEngine,
    storage: &dyn StorageEngine,
    src_realm_id: &RealmId,
    dst_realm_id: &RealmId,
    src_slug: &str,
    opts: &CrossRealmMigrateOptions,
) -> Result<CrossRealmMigrationReport, MigrationConflictError> {
    let sys = keys::system_realm_id();
    let mut report = CrossRealmMigrationReport::default();

    // 1. Check for "completed" marker — entire migration already finished.
    let completed_key = keys::config_migration_completed_key(src_slug);
    if storage.get(&sys, &completed_key).unwrap_or(None).is_some() {
        info!(src_slug, "cross-realm migration already completed; skipping");
        return Ok(report);
    }

    info!(
        src_slug,
        dst_realm = %dst_realm_id.as_uuid(),
        move_semantics = opts.move_semantics,
        "starting cross-realm user migration"
    );

    // 2. Enumerate all users in the source realm (full pagination).
    let mut user_ids: Vec<UserId> = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = match engine.list_users(src_realm_id, cursor.as_deref(), 200) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, src_slug, "failed to list source users; aborting migration");
                return Ok(report);
            }
        };
        for user in &page.items {
            user_ids.push(user.id().clone());
        }
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }

    if user_ids.is_empty() {
        // Source realm has no users — write completed marker and return.
        let _ = storage.put(&sys, &completed_key, b"done");
        return Ok(report);
    }

    // 3. Pre-flight conflict check for `on_conflict: error`.
    //    Collect ALL conflicts before migrating any user so operators see
    //    the full list in one startup failure.
    if opts.on_conflict == MigrateConflictPolicy::Error {
        for user_id in &user_ids {
            // Skip users already successfully migrated.
            let progress_key = keys::config_migration_progress_key(src_slug, user_id);
            if storage.get(&sys, &progress_key).unwrap_or(None).is_some() {
                continue;
            }

            let user = match engine.get_user(src_realm_id, user_id) {
                Ok(Some(u)) => u,
                _ => continue,
            };
            // Check if this email already exists in the destination realm.
            let email_key = keys::encode_user_email(user.email());
            if storage
                .get(dst_realm_id, &email_key)
                .unwrap_or(None)
                .is_some()
            {
                report.conflicts.push(user.email().to_string());
            }
        }
        if !report.conflicts.is_empty() {
            return Err(MigrationConflictError {
                emails: report.conflicts.clone(),
            });
        }
    }

    // 4. Per-user migration.
    for user_id in &user_ids {
        let progress_key = keys::config_migration_progress_key(src_slug, user_id);

        // Skip if already migrated (crash-safe resume).
        if storage.get(&sys, &progress_key).unwrap_or(None).is_some() {
            report.migrated += 1;
            continue;
        }

        let user = match engine.get_user(src_realm_id, user_id) {
            Ok(Some(u)) => u,
            Ok(None) => continue, // Vanished between listing and migration.
            Err(e) => {
                warn!(error = %e, user_uuid = %user_id.as_uuid(), "failed to load user; skipping");
                continue;
            }
        };

        // Conflict check for `on_conflict: skip`.
        if opts.on_conflict == MigrateConflictPolicy::Skip {
            let email_key = keys::encode_user_email(user.email());
            if storage
                .get(dst_realm_id, &email_key)
                .unwrap_or(None)
                .is_some()
            {
                warn!(
                    email = user.email(),
                    src_slug,
                    "skipping user: already exists in destination realm"
                );
                report.skipped += 1;
                continue;
            }
        }

        // Build and write the credential batch to the destination realm.
        let batch = match build_user_batch(user_id, user.email(), src_realm_id, storage) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, user_uuid = %user_id.as_uuid(), "failed to build migration batch; skipping");
                continue;
            }
        };

        if batch.is_empty() {
            // Source data already gone (partial prior run). Mark done.
            let _ = storage.put(&sys, &progress_key, b"done");
            report.migrated += 1;
            continue;
        }

        if let Err(e) = storage.put_batch(dst_realm_id, &batch) {
            warn!(error = %e, user_uuid = %user_id.as_uuid(), "failed to write user batch to destination; skipping");
            continue;
        }

        // Translate RBAC assignments via the engine trait.
        let (translated, rbac_skipped) =
            migrate_rbac_assignments(rbac, src_realm_id, dst_realm_id, user_id, opts);
        report.role_assignments_translated += translated;
        report.role_assignments_skipped += rbac_skipped;

        // Migrate org memberships if requested.
        if opts.orgs {
            migrate_org_memberships(engine, src_realm_id, dst_realm_id, user_id);
        }

        // Delete source data (move semantics only).
        if opts.move_semantics {
            delete_source_user(user_id, user.email(), src_realm_id, storage);
        }

        // Write per-user "done" marker. From this point, restarts skip this user.
        let _ = storage.put(&sys, &progress_key, b"done");
        report.migrated += 1;

        info!(
            user_uuid = %user_id.as_uuid(),
            email = user.email(),
            src_slug,
            "user migrated"
        );
    }

    // 5. Write the "completed" marker so subsequent restarts skip this migration.
    let _ = storage.put(&sys, &completed_key, b"done");

    info!(
        src_slug,
        migrated = report.migrated,
        skipped = report.skipped,
        role_assignments_translated = report.role_assignments_translated,
        "cross-realm migration finished"
    );

    Ok(report)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Collects all per-user key-value pairs from the source realm for a single
/// user, ready to be written to the destination realm via `put_batch`.
///
/// Includes: user record, email index, credential, credential history, TOTP,
/// WebAuthn credentials, and WebAuthn discoverable index entries.
///
/// Sessions, magic links, email-verification tokens, and password-reset tokens
/// are intentionally excluded (all ephemeral).
fn build_user_batch(
    user_id: &UserId,
    email: &str,
    src_realm_id: &RealmId,
    storage: &dyn StorageEngine,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
    let mut batch: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    let scalar_keys: Vec<Vec<u8>> = vec![
        keys::encode_user_id(user_id),
        keys::encode_user_email(email),
        keys::encode_credential_key(user_id),
        keys::encode_credential_history_key(user_id),
        keys::encode_mfa_totp_key(user_id),
    ];

    for key in scalar_keys {
        if let Some(bytes) = storage
            .get(src_realm_id, &key)
            .map_err(|e| e.to_string())?
        {
            batch.push((key, bytes));
        }
    }

    // WebAuthn credentials (`webauthn:cred:{user_uuid}:{cred_id}`).
    let webauthn_prefix = keys::encode_webauthn_credentials_prefix(user_id);
    let webauthn_end = keys::prefix_end(&webauthn_prefix);
    let webauthn_entries = storage
        .scan(src_realm_id, &webauthn_prefix, &webauthn_end)
        .map_err(|e| e.to_string())?;

    for entry in &webauthn_entries {
        batch.push((entry.key.clone(), entry.value.clone()));

        // Also copy the discoverable index entry if applicable.
        if let Ok(stored) = serde_json::from_slice::<serde_json::Value>(&entry.value) {
            let is_discoverable = stored
                .get("discoverable")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if is_discoverable {
                if let Some(cred_id_b64) = stored
                    .get("credential_id_b64")
                    .and_then(serde_json::Value::as_str)
                {
                    let disc_key = keys::encode_webauthn_discoverable(cred_id_b64);
                    if let Some(disc_bytes) =
                        storage.get(src_realm_id, &disc_key).unwrap_or(None)
                    {
                        batch.push((disc_key, disc_bytes));
                    }
                }
            }
        }
    }

    Ok(batch)
}

/// Translates and re-creates RBAC role assignments for a user in the
/// destination realm.
///
/// Roles are looked up by name in the destination realm. Assignments for
/// unknown roles and org-scoped assignments when `orgs == false` are skipped.
///
/// Returns `(translated, skipped)` counts.
fn migrate_rbac_assignments(
    rbac: &dyn RbacEngine,
    src_realm_id: &RealmId,
    dst_realm_id: &RealmId,
    user_id: &UserId,
    opts: &CrossRealmMigrateOptions,
) -> (u64, u64) {
    let assignments = match rbac.list_user_assignments(src_realm_id, user_id) {
        Ok(a) => a,
        Err(e) => {
            warn!(error = %e, user_uuid = %user_id.as_uuid(), "failed to list user RBAC assignments; skipping RBAC migration");
            return (0, 0);
        }
    };

    let mut translated: u64 = 0;
    let mut skipped: u64 = 0;

    for assignment in &assignments {
        // Strip org-scoped assignments when orgs are not being migrated.
        if !opts.orgs {
            if let Scope::Org { .. } = &assignment.scope {
                skipped += 1;
                continue;
            }
        }

        // Translate role ID → role name in source, then look up in destination.
        let src_role = match rbac.get_role(src_realm_id, &assignment.role_id) {
            Ok(Some(r)) => r,
            Ok(None) => {
                warn!(role_id = %assignment.role_id.as_uuid(), "source role not found; skipping assignment");
                skipped += 1;
                continue;
            }
            Err(e) => {
                warn!(error = %e, "failed to load source role; skipping assignment");
                skipped += 1;
                continue;
            }
        };

        let dst_role = match rbac.get_role_by_name(dst_realm_id, &src_role.name) {
            Ok(Some(r)) => r,
            Ok(None) => {
                warn!(role_name = src_role.name, "no matching role in destination; skipping assignment");
                skipped += 1;
                continue;
            }
            Err(e) => {
                warn!(error = %e, "failed to look up destination role; skipping assignment");
                skipped += 1;
                continue;
            }
        };

        let req = AssignRoleRequest {
            role_id: dst_role.id,
            subject: Subject::User(user_id.clone()),
            scope: assignment.scope.clone(),
            assigned_by: None,
        };
        match rbac.assign_role(dst_realm_id, &req) {
            Ok(_) => translated += 1,
            Err(e) => {
                warn!(error = %e, "failed to assign role in destination; skipping");
                skipped += 1;
            }
        }
    }

    (translated, skipped)
}

/// Migrates org memberships for a user from source to destination realm.
///
/// Matches organizations by **slug**. Memberships for orgs without a slug
/// match in the destination realm are silently skipped.
fn migrate_org_memberships(
    engine: &dyn IdentityEngine,
    src_realm_id: &RealmId,
    dst_realm_id: &RealmId,
    user_id: &UserId,
) {
    let mut cursor: Option<String> = None;
    loop {
        let page = match engine.list_user_organizations(src_realm_id, user_id, cursor.as_deref(), 100) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, user_uuid = %user_id.as_uuid(), "failed to list user org memberships");
                break;
            }
        };

        for membership in &page.items {
            let src_org = match engine.get_organization(src_realm_id, membership.org_id()) {
                Ok(Some(o)) => o,
                _ => continue,
            };

            let dst_org = match engine.get_organization_by_slug(dst_realm_id, src_org.slug()) {
                Ok(Some(o)) => o,
                Ok(None) => continue, // Org not in destination — skip.
                Err(e) => {
                    warn!(error = %e, org_slug = src_org.slug(), "destination org lookup failed; skipping membership");
                    continue;
                }
            };

            if let Err(e) =
                engine.add_member(dst_realm_id, dst_org.id(), user_id, membership.role())
            {
                warn!(
                    error = %e,
                    org_slug = src_org.slug(),
                    user_uuid = %user_id.as_uuid(),
                    "failed to add user to destination org"
                );
            }
        }

        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
}

/// Deletes all per-user credential/identity data from the source realm.
///
/// Mirrors the keys copied by [`build_user_batch`]. Errors are logged
/// but do not abort the operation (best-effort cleanup).
fn delete_source_user(
    user_id: &UserId,
    email: &str,
    src_realm_id: &RealmId,
    storage: &dyn StorageEngine,
) {
    let scalar_keys: Vec<Vec<u8>> = vec![
        keys::encode_user_id(user_id),
        keys::encode_user_email(email),
        keys::encode_credential_key(user_id),
        keys::encode_credential_history_key(user_id),
        keys::encode_mfa_totp_key(user_id),
    ];

    for key in &scalar_keys {
        if let Err(e) = storage.delete(src_realm_id, key) {
            warn!(error = %e, "failed to delete source user key during move");
        }
    }

    // WebAuthn credentials + discoverable index entries.
    let webauthn_prefix = keys::encode_webauthn_credentials_prefix(user_id);
    let webauthn_end = keys::prefix_end(&webauthn_prefix);
    if let Ok(entries) = storage.scan(src_realm_id, &webauthn_prefix, &webauthn_end) {
        for entry in &entries {
            // Remove discoverable index entry if applicable.
            if let Ok(stored) = serde_json::from_slice::<serde_json::Value>(&entry.value) {
                let is_discoverable = stored
                    .get("discoverable")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                if is_discoverable {
                    if let Some(cred_id_b64) = stored
                        .get("credential_id_b64")
                        .and_then(serde_json::Value::as_str)
                    {
                        let disc_key = keys::encode_webauthn_discoverable(cred_id_b64);
                        let _ = storage.delete(src_realm_id, &disc_key);
                    }
                }
            }
            let _ = storage.delete(src_realm_id, &entry.key);
        }
    }
}
