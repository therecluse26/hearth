//! Realm reconciliation: syncs YAML-declared realms with storage.
//!
//! Called once at startup. Compares the `realms:` map in `hearth.yaml`
//! against the realm records in storage and creates, updates, or
//! archives realms to match the declared state.
//!
//! # Rules
//!
//! 1. `config.realms == None` AND no realms in storage → create "default"
//! 2. `config.realms == None` AND realms exist → skip (backward compat)
//! 3. `config.realms == Some(map)` →
//!    - YAML entry not in storage → create
//!    - YAML entry in storage → update config if changed, un-archive if Archived
//!    - Storage realm not in YAML → set status to Archived

use std::collections::HashMap;

use tracing::{info, trace, warn};
use uuid::Uuid;

use crate::config::{
    ApplicationYamlConfig, AuthConfig, Config, ConfigDiff, ConfigSnapshot, FederationProviderYaml,
    FederationYamlConfig, OrganizationYamlConfig, RealmYamlConfig,
};
use crate::core::{ClientId, RealmId, Timestamp};
use crate::identity::error::IdentityError;
use crate::identity::keys::{
    config_migration_history_key, config_migration_history_scan_prefix, config_orphan_key,
    config_orphan_scan_prefix, config_snapshot_key, prefix_end,
};
use crate::identity::oidc::{ApplicationStatus, UpdateClientRequest};
use crate::identity::{
    CreateOrganizationRequest, CreateRealmRequest, IdentityEngine, ImportClientRequest,
    OrganizationConfig, OrganizationStatus, RealmConfig, RealmStatus, UpdateOrganizationRequest,
    UpdateRealmRequest,
};
use crate::rbac::{Group, GroupId, Permission, ProtectedResource, RbacEngine, ScopeBundle};
use crate::storage::{StorageEngine, StorageError};

/// Metadata about an archived realm that has live users but no declared
/// migration destination or `archive_drop` resolution.
///
/// Serialised to JSON and written under `config:orphan:{slug}` in the system
/// realm.  Deleted when the orphan condition is resolved (users drained,
/// `migrate_from` added to a destination realm, or `archive_drop: true` added
/// to the slug's YAML entry).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OrphanRecord {
    /// Slug (name) of the archived realm.
    pub realm_slug: String,
    /// RFC 3339 timestamp when this orphan was first detected.
    pub detected_at: String,
    /// Number of users in the archived realm at detection time.
    pub user_count: u64,
    /// Number of organizations in the archived realm at detection time.
    pub org_count: u64,
}

/// Outcome status of a recorded cross-realm migration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationHistoryStatus {
    /// All users moved or copied without conflicts.
    Completed,
    /// Completed but some users were skipped due to email conflicts.
    CompletedWithSkips,
    /// Aborted due to email conflicts (on_conflict: error policy).
    Failed,
}

impl MigrationHistoryStatus {
    /// Human-readable label for the status badge.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Completed => "Completed",
            Self::CompletedWithSkips => "Completed (with skips)",
            Self::Failed => "Failed",
        }
    }

    /// CSS colour token class for the status badge.
    #[must_use]
    pub fn badge_class(&self) -> &'static str {
        match self {
            Self::Completed => "text-success-fg bg-success/20",
            Self::CompletedWithSkips => "text-warning-fg bg-warning/20",
            Self::Failed => "text-error-fg bg-error/20",
        }
    }
}

/// Durable record of a completed or failed cross-realm migration run.
///
/// Serialised to JSON and written under `config:migration:hist:{source_slug}`
/// in the system realm. Overwritten on each run so the record reflects the
/// most recent attempt.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MigrationHistoryRecord {
    /// Slug (name) of the source realm.
    pub source_slug: String,
    /// Slug (name) of the destination realm.
    pub destination_slug: String,
    /// `true` = move semantics (source data deleted after copy).
    pub move_semantics: bool,
    /// Number of users successfully moved/copied.
    pub users_migrated: u64,
    /// Number of users skipped due to email conflicts.
    pub users_skipped: u64,
    /// Number of RBAC role assignments translated.
    pub role_assignments_translated: u64,
    /// RFC 3339 timestamp when the run finished.
    pub completed_at: String,
    /// Final status of the migration.
    pub status: MigrationHistoryStatus,
    /// Conflict emails (non-empty only when status = `Failed`).
    pub conflict_emails: Vec<String>,
}

/// Formats a Unix timestamp (seconds since epoch) as an RFC 3339 UTC string.
///
/// Public so that binary crates (`main.rs`) can timestamp migration history
/// records without depending on `chrono` or accessing the private
/// `config::diff` helper.
#[must_use]
pub fn format_unix_secs_rfc3339(secs: u64) -> String {
    let days = secs / 86_400;
    let time_of_day = secs % 86_400;
    let hour = time_of_day / 3_600;
    let min = (time_of_day % 3_600) / 60;
    let sec = time_of_day % 60;
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Writes a migration history record to the system realm.
///
/// Silently swallows serialisation/storage errors — history is best-effort;
/// it MUST NOT block startup.
pub fn write_migration_history(storage: &dyn StorageEngine, record: &MigrationHistoryRecord) {
    let Ok(json) = serde_json::to_vec(record) else {
        return;
    };
    let sys = crate::identity::keys::system_realm_id();
    let key = config_migration_history_key(&record.source_slug);
    let _ = storage.put(&sys, &key, &json);
}

/// Loads all migration history records from the system realm.
///
/// Returns an empty `Vec` on any error. Records are sorted newest-first by
/// `completed_at` (lexicographic on RFC 3339 strings, which is chronological).
#[must_use]
pub fn load_migration_records(storage: &dyn StorageEngine) -> Vec<MigrationHistoryRecord> {
    let sys = crate::identity::keys::system_realm_id();
    let prefix = config_migration_history_scan_prefix();
    let end = prefix_end(&prefix);
    let entries = match storage.scan(&sys, &prefix, &end) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut records: Vec<MigrationHistoryRecord> = entries
        .iter()
        .filter_map(|e| serde_json::from_slice(&e.value).ok())
        .collect();
    // Sort newest-first.
    records.sort_by(|a, b| b.completed_at.cmp(&a.completed_at));
    records
}

/// Report of what realm reconciliation did.
#[derive(Debug, Default)]
pub struct ReconcileReport {
    /// Names of realms created from YAML.
    pub created: Vec<String>,
    /// Names of realms whose config was updated from YAML.
    pub updated: Vec<String>,
    /// Names of realms archived (removed from YAML).
    pub archived: Vec<String>,
    /// Names of realms un-archived (reappeared in YAML).
    pub unarchived: Vec<String>,
    /// Application reconciliation results per realm.
    pub applications: Vec<AppReconcileEntry>,
    /// Organization reconciliation results per realm.
    pub organizations: Vec<OrgReconcileEntry>,
}

/// Reconciliation result for a single application.
#[derive(Debug)]
pub struct AppReconcileEntry {
    /// Realm name.
    pub realm: String,
    /// Application YAML key.
    pub app_key: String,
    /// What happened.
    pub action: AppReconcileAction,
}

/// What happened to a reconciled application.
#[derive(Debug, PartialEq, Eq)]
pub enum AppReconcileAction {
    /// Application was created.
    Created,
    /// Application config was updated.
    Updated,
    /// Application was archived (removed from YAML); soft-delete, not hard.
    Archived,
    /// Application was restored (reappeared in YAML after being archived).
    Restored,
}

/// Reconciliation result for a single organization.
#[derive(Debug)]
pub struct OrgReconcileEntry {
    /// Realm name.
    pub realm: String,
    /// Organization slug (YAML key).
    pub slug: String,
    /// What happened.
    pub action: OrgReconcileAction,
}

/// What happened to a reconciled organization.
#[derive(Debug, PartialEq, Eq)]
pub enum OrgReconcileAction {
    /// Organization was created.
    Created,
    /// Organization config was updated.
    Updated,
    /// Organization was archived (slug removed from YAML); soft-delete.
    Archived,
    /// Organization was restored (slug reappeared in YAML after archiving).
    Restored,
}

/// Reconciles YAML-declared realms with storage.
///
/// # Errors
///
/// Returns `Err` if any storage operation fails. Partial reconciliation
/// (some realms created before a failure) is not rolled back — the
/// caller should retry on next startup.
pub fn reconcile_realms(
    engine: &dyn IdentityEngine,
    rbac: &dyn RbacEngine,
    config: &Config,
) -> Result<ReconcileReport, IdentityError> {
    let mut report = ReconcileReport::default();

    match &config.realms {
        None => {
            // Check if any realms exist
            let page = engine.list_realms(None, 1)?;
            if page.items.is_empty() {
                // No realms and no YAML config → create "default"
                let realm_config = default_realm_config(&config.auth, config);
                let realm = engine.create_realm(&CreateRealmRequest {
                    name: "default".to_string(),
                    config: Some(realm_config),
                })?;
                seed_realm_or_log(rbac, realm.id(), "default");
                report.created.push("default".to_string());
            }
            // If realms exist, skip reconciliation (backward compat)
        }
        Some(yaml_realms) => {
            reconcile_declared_realms(engine, rbac, yaml_realms, config, &mut report)?;
        }
    }

    Ok(report)
}

/// Scans every realm in storage and re-seeds RBAC defaults for any that are
/// missing them (e.g. API-created realms whose original seed failed).
///
/// Runs once at startup after `reconcile_realms`. `seed_realm` is idempotent,
/// so re-running it on healthy realms is safe. Errors are logged but do not
/// abort startup — one broken realm must not prevent others from serving.
pub fn reconcile_rbac_seeds(engine: &dyn IdentityEngine, rbac: &dyn RbacEngine) {
    const PAGE: usize = 100;
    let mut cursor: Option<String> = None;
    loop {
        let page = match engine.list_realms(cursor.as_deref(), PAGE) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "reconcile_rbac_seeds: failed to list realms");
                return;
            }
        };
        for realm in &page.items {
            seed_realm_or_log(rbac, realm.id(), realm.name());
        }
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
}

/// Seeds default roles, permissions, and scopes on a freshly created realm,
/// logging (but not failing) if the seed errors. The realm record is already
/// durable at this point; a missing seed is recoverable (seed_realm is
/// idempotent), so we prefer a log over aborting reconciliation mid-run.
fn seed_realm_or_log(rbac: &dyn RbacEngine, realm_id: &RealmId, realm_name: &str) {
    if let Err(e) = rbac.seed_realm(realm_id) {
        tracing::warn!(
            realm = realm_name,
            error = %e,
            "failed to seed RBAC defaults on new realm"
        );
    }
}

/// Persists YAML-declared permissions, roles, and scope bundles into the
/// realm's RBAC storage. Idempotent: each underlying engine method upserts
/// by name. Logs (does not raise) on individual failures so one bad block
/// doesn't abort reconciliation of subsequent realms or other concerns
/// (organizations, federation, etc.).
fn reconcile_rbac_for_realm(
    rbac: &dyn RbacEngine,
    realm_id: &RealmId,
    realm_name: &str,
    yaml_cfg: &RealmYamlConfig,
) {
    let perm_count = yaml_cfg.permissions.as_ref().map_or(0, Vec::len);
    let role_count = yaml_cfg.roles.as_ref().map_or(0, Vec::len);
    let scope_count = yaml_cfg.scopes.as_ref().map_or(0, Vec::len);
    tracing::info!(
        realm = realm_name,
        permissions = perm_count,
        roles = role_count,
        scopes = scope_count,
        "reconciling YAML RBAC"
    );

    // --- Permissions: upsert declared, then archive removed ---
    let yaml_perm_names: std::collections::HashSet<String> = yaml_cfg
        .permissions
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|p| p.name.clone())
        .collect();

    if let Some(perms) = yaml_cfg.permissions.as_ref() {
        let names: Vec<String> = perms.iter().map(|p| p.name.clone()).collect();
        if let Err(e) = rbac.reconcile_permissions(realm_id, &names) {
            tracing::warn!(
                realm = realm_name,
                error = %e,
                "failed to reconcile YAML permissions"
            );
        }
    }

    // Only run the archive sweep when the YAML has an explicit `permissions:` block.
    // When the block is absent, we treat all permissions as unmanaged.
    if yaml_cfg.permissions.is_some() {
        if let Err(e) = rbac.archive_removed_permissions(realm_id, &yaml_perm_names) {
            tracing::warn!(
                realm = realm_name,
                error = %e,
                "failed to archive removed permissions"
            );
        }
    }

    // --- Roles: upsert declared, then archive removed ---
    let yaml_role_names: std::collections::HashSet<String> = yaml_cfg
        .roles
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|r| r.name.clone())
        .collect();

    if let Some(roles) = yaml_cfg.roles.as_ref() {
        let specs: Vec<crate::rbac::RoleSpec> = roles
            .iter()
            .map(|r| crate::rbac::RoleSpec {
                name: r.name.clone(),
                description: r.description.clone(),
                permissions: r.permissions.clone(),
                parent_names: r.parents.clone(),
                scope_kind: match r.scope_kind.as_deref() {
                    Some("organization") => crate::rbac::RoleScopeKind::Organization,
                    Some("any") => crate::rbac::RoleScopeKind::Any,
                    _ => crate::rbac::RoleScopeKind::Realm,
                },
            })
            .collect();
        for spec in &specs {
            if let Err(e) = rbac.reconcile_roles(realm_id, std::slice::from_ref(spec)) {
                tracing::warn!(
                    realm = realm_name,
                    role = %spec.name,
                    error = %e,
                    "failed to reconcile YAML role"
                );
            }
        }
    }

    // Only run the archive sweep when the YAML has an explicit `roles:` block.
    if yaml_cfg.roles.is_some() {
        if let Err(e) = rbac.archive_removed_roles(realm_id, &yaml_role_names) {
            tracing::warn!(
                realm = realm_name,
                error = %e,
                "failed to archive removed roles"
            );
        }
    }

    if let Some(scopes) = yaml_cfg.scopes.as_ref() {
        let specs: Vec<crate::rbac::ScopeSpec> = scopes
            .iter()
            .map(|s| crate::rbac::ScopeSpec {
                name: s.name.clone(),
                permissions: Some(s.permissions.clone()),
            })
            .collect();
        if let Err(e) = rbac.reconcile_scopes(realm_id, &specs) {
            tracing::warn!(
                realm = realm_name,
                error = %e,
                "failed to reconcile YAML scope bundles"
            );
        }
    }

    if let Some(resources) = yaml_cfg.protected_resources.as_ref() {
        let domain_resources: Vec<ProtectedResource> = resources
            .iter()
            .map(|r| ProtectedResource {
                resource_uri: r.resource_uri.clone(),
                display_name: r.display_name.clone(),
                scopes: r
                    .scopes
                    .iter()
                    .map(|b| ScopeBundle {
                        name: b.name.clone(),
                        display_name: b.display_name.clone(),
                        description: b.description.clone(),
                        permissions: b
                            .permissions
                            .iter()
                            .filter_map(|p| Permission::new(p.clone()).ok())
                            .collect(),
                    })
                    .collect(),
            })
            .collect();
        if !domain_resources.is_empty() {
            if let Err(e) = rbac.reconcile_protected_resources(realm_id, &domain_resources) {
                tracing::warn!(
                    realm = realm_name,
                    error = %e,
                    "failed to reconcile YAML protected resources"
                );
            }
        }
    }

    if let Some(groups) = yaml_cfg.groups.as_ref() {
        let domain_groups: Vec<Group> = groups
            .iter()
            .map(|g| Group {
                id: GroupId::generate(),
                realm_id: realm_id.clone(),
                name: g.name.clone(),
                slug: g.slug.clone().unwrap_or_else(|| {
                    let mut slug = g.name.to_lowercase().replace(' ', "-");
                    slug.truncate(63);
                    slug
                }),
                description: g.description.clone(),
                created_at: Timestamp::from_micros(0),
                updated_at: Timestamp::from_micros(0),
            })
            .collect();
        if let Err(e) = rbac.reconcile_groups(realm_id, &domain_groups) {
            tracing::warn!(
                realm = realm_name,
                error = %e,
                "failed to reconcile YAML groups"
            );
        }
    }
}

/// Reconciles a declared `realms:` map.
fn reconcile_declared_realms(
    engine: &dyn IdentityEngine,
    rbac: &dyn RbacEngine,
    yaml_realms: &HashMap<String, RealmYamlConfig>,
    config: &Config,
    report: &mut ReconcileReport,
) -> Result<(), IdentityError> {
    // Defense in depth: the YAML parser rejects `realms.system` before
    // we get here, but guarding again ensures the reconciler can never
    // accidentally touch the admin realm if the parse-time check is
    // ever bypassed (e.g. a future alternate config loader).
    if yaml_realms.contains_key("system") {
        return Err(IdentityError::SystemRealmProtected {
            operation: "reconcile_realms",
        });
    }

    // Build a set of YAML realm names for archive detection
    let yaml_names: std::collections::HashSet<&str> =
        yaml_realms.keys().map(String::as_str).collect();

    // Process each YAML entry
    for (name, yaml_cfg) in yaml_realms {
        // `archive_drop: true` is a tombstone marker — the operator is
        // intentionally discarding the archived realm.  Skip all
        // reconciliation for this entry so it stays archived (or stays
        // non-existent if it was never created).  The orphan-detection
        // pass treats this slug as resolved.
        if yaml_cfg.archive_drop.unwrap_or(false) {
            trace!(
                realm = name,
                "reconcile_realms: skipping archive_drop entry"
            );
            continue;
        }

        let realm_config = yaml_cfg
            .to_realm_config(&config.auth, config.email.branding.as_ref())
            .map_err(|errors| IdentityError::ConfigInvalid {
                realm_name: name.clone(),
                errors,
            })?;

        let realm_id = match engine.get_realm_by_name(name)? {
            None => {
                // Create new realm
                let realm = engine.create_realm(&CreateRealmRequest {
                    name: name.clone(),
                    config: Some(realm_config),
                })?;
                seed_realm_or_log(rbac, realm.id(), name);
                report.created.push(name.clone());
                realm.id().clone()
            }
            Some(existing) => {
                // Update if config changed or status needs un-archiving
                let needs_config_update = existing.config() != &realm_config;
                let needs_unarchive = existing.status() == RealmStatus::Archived;

                if needs_config_update || needs_unarchive {
                    let mut update = UpdateRealmRequest::default();
                    if needs_config_update {
                        update.config = Some(realm_config);
                    }
                    if needs_unarchive {
                        update.status = Some(RealmStatus::Active);
                        report.unarchived.push(name.clone());
                    }
                    engine.update_realm(existing.id(), &update)?;
                    if needs_config_update && !needs_unarchive {
                        report.updated.push(name.clone());
                    }
                }
                // Re-run seed on existing realms too. `seed_realm` is
                // idempotent: it skips already-correct records and rewrites
                // only roles whose `scope_kind` drifted from the spec (e.g.
                // legacy `org.*` roles seeded before the field existed, which
                // deserialize as `Realm` by default).
                seed_realm_or_log(rbac, existing.id(), name);
                existing.id().clone()
            }
        };

        // Reconcile YAML-declared RBAC: permissions before roles before
        // scopes, mirroring the seed order so name references resolve.
        // Errors are logged (not fatal) so a bad RBAC block doesn't abort
        // reconciliation of other realms.
        reconcile_rbac_for_realm(rbac, &realm_id, name, yaml_cfg);

        // Reconcile managed OAuth clients declared under this realm.
        if let Some(apps) = yaml_cfg
            .oauth_clients
            .as_ref()
            .or(yaml_cfg.applications.as_ref())
        {
            reconcile_applications(engine, &realm_id, name, apps, report)?;
        }

        // Reconcile organizations declared under this realm
        if let Some(orgs) = &yaml_cfg.organizations {
            reconcile_organizations(engine, &realm_id, name, orgs, report)?;
        }

        // Reconcile federation connectors declared under this realm.
        if let Some(fed) = &yaml_cfg.federation {
            reconcile_federation_for_realm(engine, &realm_id, name, fed, report)?;
        }

        // Reconcile SAML Service Provider registrations (Hearth as IdP).
        if let Some(sps) = &yaml_cfg.saml_service_providers {
            reconcile_saml_sps_for_realm(engine, &realm_id, name, sps, report)?;
        }
    }

    // Archive storage realms not in YAML
    let mut cursor = None;
    loop {
        let page = engine.list_realms(cursor.as_deref(), 100)?;
        for realm in &page.items {
            if !yaml_names.contains(realm.name()) && realm.status() != RealmStatus::Archived {
                engine.update_realm(
                    realm.id(),
                    &UpdateRealmRequest {
                        status: Some(RealmStatus::Archived),
                        ..Default::default()
                    },
                )?;
                report.archived.push(realm.name().to_string());
            }
        }
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }

    Ok(())
}

/// Builds a `RealmConfig` from global auth defaults (used for the auto-created "default" realm).
///
/// Uses a default (empty) `RealmYamlConfig`, so validation always succeeds.
fn default_realm_config(auth: &AuthConfig, config: &Config) -> RealmConfig {
    let yaml = RealmYamlConfig::default();
    yaml.to_realm_config(auth, config.email.branding.as_ref())
        .expect("default RealmYamlConfig must always pass validation")
}

/// UUID v5 namespace for deterministic application client IDs.
///
/// Generated once from `uuid::Uuid::new_v5(NAMESPACE_URL, b"hearth-app")`.
/// This is a stable constant — changing it would break all existing
/// deterministic client IDs.
const APP_NAMESPACE: Uuid = Uuid::from_bytes([
    0x8b, 0x07, 0x4e, 0x8c, 0x3e, 0x6a, 0x5a, 0x8e, 0x96, 0x1d, 0x8f, 0x2b, 0xaa, 0xe7, 0x1b, 0xf4,
]);

/// Generates a deterministic `ClientId` from realm name and application key.
///
/// Uses UUID v5 (SHA-1 + namespace) so the same `(realm, app)` pair always
/// produces the same ID across server restarts.
fn deterministic_client_id(realm_name: &str, app_key: &str) -> ClientId {
    let input = format!("{realm_name}/{app_key}");
    let id = Uuid::new_v5(&APP_NAMESPACE, input.as_bytes());
    ClientId::new(id)
}

/// Returns `true` if the `ClientId` looks like it was generated by
/// [`deterministic_client_id`] (UUID version 5).
///
/// All reconciliation-managed clients have v5 UUIDs, while manually-
/// registered clients use v4 (random). This heuristic prevents
/// reconciliation from deleting legacy hand-created clients.
fn is_deterministic_id(_realm_name: &str, client_id: &ClientId) -> bool {
    client_id.as_uuid().get_version_num() == 5
}

/// Reconciles application declarations for a single realm.
///
/// Called after the realm itself has been reconciled (so `realm_id` is valid).
#[allow(clippy::too_many_lines)]
pub(crate) fn reconcile_applications(
    engine: &dyn IdentityEngine,
    realm_id: &RealmId,
    realm_name: &str,
    apps: &HashMap<String, ApplicationYamlConfig>,
    report: &mut ReconcileReport,
) -> Result<(), IdentityError> {
    // Process each YAML application
    for (app_key, app_cfg) in apps {
        let client_id = deterministic_client_id(realm_name, app_key);
        let grant_types = app_cfg
            .grant_types
            .clone()
            .unwrap_or_else(|| vec!["authorization_code".to_string()]);
        let redirect_uris = app_cfg.redirect_uris.clone().unwrap_or_default();

        let cfg_require_consent = app_cfg.require_consent.unwrap_or(true);
        let cfg_logo = app_cfg.client_logo_url.clone();

        match engine.get_client(realm_id, &client_id) {
            Ok(Some(existing)) => {
                // Client exists — restore if archived, then update if changed.
                let was_archived = existing.status() == ApplicationStatus::Archived;
                let name_changed = existing.client_name() != app_cfg.name;
                let uris_changed = existing.redirect_uris() != redirect_uris;
                let grants_changed = existing.grant_types() != grant_types;
                let consent_changed = existing.require_consent() != cfg_require_consent;
                let logo_changed = existing.client_logo_url() != cfg_logo.as_deref();

                if was_archived
                    || name_changed
                    || uris_changed
                    || grants_changed
                    || consent_changed
                    || logo_changed
                {
                    engine.update_client(
                        realm_id,
                        &client_id,
                        &UpdateClientRequest {
                            client_name: if name_changed {
                                Some(app_cfg.name.clone())
                            } else {
                                None
                            },
                            redirect_uris: if uris_changed {
                                Some(redirect_uris)
                            } else {
                                None
                            },
                            grant_types: if grants_changed {
                                Some(grant_types)
                            } else {
                                None
                            },
                            require_consent: if consent_changed {
                                Some(cfg_require_consent)
                            } else {
                                None
                            },
                            client_logo_url: if logo_changed {
                                Some(cfg_logo.clone())
                            } else {
                                None
                            },
                            slug: app_cfg.slug.clone(),
                            trust_level: app_cfg.trust_level,
                            declared_scopes: app_cfg.declared_scopes.clone(),
                            consent_spans_orgs: app_cfg.consent_spans_orgs,
                            // Restore to Active if previously archived.
                            status: if was_archived {
                                Some(ApplicationStatus::Active)
                            } else {
                                None
                            },
                            ..Default::default()
                        },
                    )?;
                    if was_archived {
                        info!(
                            realm = realm_name,
                            app = app_key,
                            "restored archived application from YAML"
                        );
                        report.applications.push(AppReconcileEntry {
                            realm: realm_name.to_string(),
                            app_key: app_key.clone(),
                            action: AppReconcileAction::Restored,
                        });
                    } else {
                        info!(
                            realm = realm_name,
                            app = app_key,
                            "updated application from YAML"
                        );
                        report.applications.push(AppReconcileEntry {
                            realm: realm_name.to_string(),
                            app_key: app_key.clone(),
                            action: AppReconcileAction::Updated,
                        });
                    }
                }
            }
            Ok(None) => {
                // Client does not exist — create via import (deterministic ID)
                let secret = if app_cfg.confidential.unwrap_or(false) {
                    app_cfg.client_secret.clone()
                } else {
                    None
                };

                engine.import_client(
                    realm_id,
                    &ImportClientRequest {
                        id: Some(client_id.clone()),
                        client_name: app_cfg.name.clone(),
                        redirect_uris,
                        client_secret: secret,
                        grant_types,
                        slug: app_cfg.slug.clone(),
                        trust_level: app_cfg
                            .trust_level
                            .unwrap_or(crate::identity::ClientTrustLevel::FirstParty),
                        declared_scopes: app_cfg.declared_scopes.clone().unwrap_or_default(),
                        consent_spans_orgs: app_cfg.consent_spans_orgs.unwrap_or(false),
                    },
                )?;
                // Apply consent-policy fields: the import path doesn't
                // carry them, so a follow-up update_client puts the client
                // in the intended state.
                if !cfg_require_consent || cfg_logo.is_some() {
                    engine.update_client(
                        realm_id,
                        &client_id,
                        &UpdateClientRequest {
                            client_name: None,
                            redirect_uris: None,
                            grant_types: None,
                            require_consent: Some(cfg_require_consent),
                            client_logo_url: Some(cfg_logo.clone()),
                            slug: app_cfg.slug.clone(),
                            trust_level: app_cfg.trust_level,
                            declared_scopes: app_cfg.declared_scopes.clone(),
                            consent_spans_orgs: app_cfg.consent_spans_orgs,
                            ..Default::default()
                        },
                    )?;
                }
                info!(
                    realm = realm_name,
                    app = app_key,
                    "created application from YAML"
                );
                report.applications.push(AppReconcileEntry {
                    realm: realm_name.to_string(),
                    app_key: app_key.clone(),
                    action: AppReconcileAction::Created,
                });
            }
            Err(e) => return Err(e),
        }
    }

    // Delete applications that exist in storage but are no longer declared in
    // Soft-archive applications that were removed from YAML. Only acts on
    // clients whose ID matches the deterministic UUID v5 pattern (i.e., was
    // created by reconciliation). Manually-created clients with random UUIDs
    // are left untouched. Already-archived clients are skipped.
    let yaml_client_ids: std::collections::HashSet<ClientId> = apps
        .keys()
        .map(|k| deterministic_client_id(realm_name, k))
        .collect();

    let mut cursor = None;
    loop {
        let page = engine.list_clients(realm_id, cursor.as_deref(), 100)?;
        for client in &page.items {
            let cid = client.client_id().clone();
            if yaml_client_ids.contains(&cid)
                || !is_deterministic_id(realm_name, &cid)
                || client.status() == ApplicationStatus::Archived
            {
                continue;
            }
            engine.update_client(
                realm_id,
                &cid,
                &UpdateClientRequest {
                    status: Some(ApplicationStatus::Archived),
                    ..Default::default()
                },
            )?;
            info!(
                realm = realm_name,
                client_id = %cid.as_uuid(),
                name = client.client_name(),
                "archived application removed from YAML"
            );
            report.applications.push(AppReconcileEntry {
                realm: realm_name.to_string(),
                app_key: client.client_name().to_string(),
                action: AppReconcileAction::Archived,
            });
        }
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }

    Ok(())
}

/// Reconciles organization declarations for a single realm.
///
/// The YAML key is used as the slug. Organizations are created if missing or
/// updated if their name, description, or config have changed. Members and
/// invitations are runtime-only and not managed by reconciliation.
pub(crate) fn reconcile_organizations(
    engine: &dyn IdentityEngine,
    realm_id: &RealmId,
    realm_name: &str,
    orgs: &HashMap<String, OrganizationYamlConfig>,
    report: &mut ReconcileReport,
) -> Result<(), IdentityError> {
    for (slug, org_cfg) in orgs {
        let yaml_config = OrganizationConfig {
            max_members: org_cfg.config.as_ref().and_then(|c| c.max_members),
        };
        let description = org_cfg.description.clone().unwrap_or_default();

        if let Some(existing) = engine.get_organization_by_slug(realm_id, slug)? {
            // Restore if previously archived; update if config drifted.
            let was_archived = existing.status() == OrganizationStatus::Archived;
            let name_changed = existing.name() != org_cfg.name;
            let desc_changed = existing.description() != description;
            let config_changed = existing.config() != &yaml_config;

            if was_archived || name_changed || desc_changed || config_changed {
                engine.update_organization(
                    realm_id,
                    existing.id(),
                    &UpdateOrganizationRequest {
                        name: if name_changed {
                            Some(org_cfg.name.clone())
                        } else {
                            None
                        },
                        description: if desc_changed {
                            Some(description)
                        } else {
                            None
                        },
                        config: if config_changed {
                            Some(yaml_config)
                        } else {
                            None
                        },
                        status: if was_archived {
                            Some(OrganizationStatus::Active)
                        } else {
                            None
                        },
                    },
                )?;
                if was_archived {
                    info!(
                        realm = realm_name,
                        org = slug,
                        "restored archived organization from YAML"
                    );
                    report.organizations.push(OrgReconcileEntry {
                        realm: realm_name.to_string(),
                        slug: slug.clone(),
                        action: OrgReconcileAction::Restored,
                    });
                } else {
                    info!(
                        realm = realm_name,
                        org = slug,
                        "updated organization from YAML"
                    );
                    report.organizations.push(OrgReconcileEntry {
                        realm: realm_name.to_string(),
                        slug: slug.clone(),
                        action: OrgReconcileAction::Updated,
                    });
                }
            }
        } else {
            // Create new organization
            engine.create_organization(
                realm_id,
                &CreateOrganizationRequest {
                    name: org_cfg.name.clone(),
                    slug: slug.clone(),
                    description: Some(description),
                    config: Some(yaml_config),
                },
            )?;
            info!(
                realm = realm_name,
                org = slug,
                "created organization from YAML"
            );
            report.organizations.push(OrgReconcileEntry {
                realm: realm_name.to_string(),
                slug: slug.clone(),
                action: OrgReconcileAction::Created,
            });
        }
    }

    // Archive organizations whose slugs are no longer declared in YAML.
    // Scan all active orgs and archive those absent from the current YAML set.
    let yaml_slugs: std::collections::HashSet<&str> = orgs.keys().map(String::as_str).collect();
    let mut cursor = None;
    loop {
        let page = engine.list_organizations(realm_id, cursor.as_deref(), 100)?;
        for org in &page.items {
            if org.status() == OrganizationStatus::Archived {
                continue;
            }
            if !yaml_slugs.contains(org.slug()) {
                engine.update_organization(
                    realm_id,
                    org.id(),
                    &UpdateOrganizationRequest {
                        status: Some(OrganizationStatus::Archived),
                        ..UpdateOrganizationRequest::default()
                    },
                )?;
                info!(
                    realm = realm_name,
                    org = org.slug(),
                    "archived organization removed from YAML"
                );
                report.organizations.push(OrgReconcileEntry {
                    realm: realm_name.to_string(),
                    slug: org.slug().to_string(),
                    action: OrgReconcileAction::Archived,
                });
            }
        }
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }

    Ok(())
}

/// Reconciles the `realms.{name}.federation.providers` block against
/// storage. Idempotent:
///
/// - YAML connector absent in storage → create via `register_idp`.
/// - YAML connector present → upsert (`register_idp` replaces fields).
/// - Storage connector not in YAML → remove (`delete_idp` severs links).
///
/// The connector's stable `IdpId` is derived deterministically from
/// `(realm_name, idp_name)` so config edits don't orphan existing
/// external-identity links.
pub(crate) fn reconcile_federation_for_realm(
    engine: &dyn IdentityEngine,
    realm_id: &RealmId,
    realm_name: &str,
    fed: &FederationYamlConfig,
    _report: &mut ReconcileReport,
) -> Result<(), IdentityError> {
    use crate::core::IdpId;

    // Deterministic UUID namespace for federation connector IDs —
    // ensures `realms.acme.federation.providers.google` always resolves
    // to the same `IdpId` across restarts and reconciles.
    let ns = Uuid::new_v5(&Uuid::NAMESPACE_OID, b"hearth.federation.connector.id");
    let mut yaml_ids: std::collections::HashSet<IdpId> = std::collections::HashSet::new();

    for (idp_name, provider) in &fed.providers {
        let seed = format!("{realm_name}:{idp_name}");
        let idp_id = IdpId::new(Uuid::new_v5(&ns, seed.as_bytes()));
        yaml_ids.insert(idp_id.clone());

        let cfg = build_idp_config(realm_id, &idp_id, idp_name, provider)?;
        engine.register_idp(&cfg)?;
        info!(realm = %realm_name, idp = %idp_name, "reconciled federation connector");
    }

    // Remove storage connectors not in YAML.
    let storage_idps = engine.list_idps(realm_id)?;
    for cfg in &storage_idps {
        if !yaml_ids.contains(&cfg.id) {
            engine.delete_idp(realm_id, &cfg.id)?;
            info!(realm = %realm_name, idp = %cfg.name, "removed federation connector no longer in YAML");
        }
    }

    Ok(())
}

fn build_idp_config(
    realm_id: &RealmId,
    idp_id: &crate::core::IdpId,
    idp_name: &str,
    provider: &FederationProviderYaml,
) -> Result<crate::identity::federation::IdpConfig, IdentityError> {
    use crate::core::Timestamp;
    use crate::identity::federation::{preset_lookup, FederationSecret, IdpConfig, IdpKind};

    // SAML is stored through the same IdpConfig shape but with fields
    // re-mapped: entity_id→issuer, sso_url→authorization_endpoint,
    // slo_url→userinfo_endpoint, idp_certificate_pem→client_secret.
    if provider.kind == "saml" {
        return build_saml_idp_config(realm_id, idp_id, idp_name, provider);
    }

    // Resolve the preset (if any) and derive defaults, letting explicit
    // YAML fields override.
    let preset = preset_lookup(&provider.kind);
    let kind = match provider.kind.as_str() {
        "oidc" => IdpKind::Oidc,
        "google" | "microsoft" | "apple" => IdpKind::Oidc,
        "github" => IdpKind::GitHub,
        other => {
            return Err(IdentityError::InvalidInput {
                reason: format!(
                    "unknown federation provider type '{other}' \
                     (expected: oidc|google|microsoft|apple|github|saml)"
                ),
            });
        }
    };

    let display_name = provider
        .display_name
        .clone()
        .or_else(|| preset.map(|p| p.display_name.to_string()))
        .unwrap_or_else(|| idp_name.to_string());

    let issuer = provider
        .issuer
        .clone()
        .or_else(|| preset.map(|p| p.issuer.to_string()))
        .ok_or_else(|| IdentityError::InvalidInput {
            reason: format!("federation connector '{idp_name}' is missing `issuer`"),
        })?;
    let authorization_endpoint = provider
        .authorization_endpoint
        .clone()
        .or_else(|| preset.map(|p| p.authorization_endpoint.to_string()))
        .ok_or_else(|| IdentityError::InvalidInput {
            reason: format!(
                "federation connector '{idp_name}' is missing `authorization_endpoint`"
            ),
        })?;
    let token_endpoint = provider
        .token_endpoint
        .clone()
        .or_else(|| preset.map(|p| p.token_endpoint.to_string()))
        .ok_or_else(|| IdentityError::InvalidInput {
            reason: format!("federation connector '{idp_name}' is missing `token_endpoint`"),
        })?;
    let userinfo_endpoint = provider
        .userinfo_endpoint
        .clone()
        .or_else(|| preset.and_then(|p| p.userinfo_endpoint.map(str::to_string)));
    let jwks_uri = provider
        .jwks_uri
        .clone()
        .or_else(|| preset.and_then(|p| p.jwks_uri.map(str::to_string)));

    let scopes = provider
        .scopes
        .clone()
        .or_else(|| preset.map(|p| p.default_scopes.iter().map(|s| (*s).to_string()).collect()))
        .unwrap_or_else(|| {
            vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ]
        });

    let now = Timestamp::from_micros(0); // engine persists as-is; reconcile uses epoch

    Ok(IdpConfig {
        id: idp_id.clone(),
        realm_id: realm_id.clone(),
        name: idp_name.to_string(),
        kind,
        display_name,
        issuer,
        authorization_endpoint,
        token_endpoint,
        userinfo_endpoint,
        jwks_uri,
        scopes,
        client_id: provider.client_id.clone().unwrap_or_default(),
        client_secret: FederationSecret::new(provider.client_secret.clone().unwrap_or_default()),
        claim_mappings: provider.claim_mappings.clone().unwrap_or_default(),
        created_at: now,
        updated_at: now,
    })
}

fn build_saml_idp_config(
    realm_id: &RealmId,
    idp_id: &crate::core::IdpId,
    idp_name: &str,
    provider: &FederationProviderYaml,
) -> Result<crate::identity::federation::IdpConfig, IdentityError> {
    use crate::core::Timestamp;
    use crate::identity::federation::{FederationSecret, IdpConfig, IdpKind};

    let entity_id = provider
        .entity_id
        .clone()
        .ok_or_else(|| IdentityError::InvalidInput {
            reason: format!("SAML federation connector '{idp_name}' missing `entity_id`"),
        })?;
    let sso_url = provider
        .sso_url
        .clone()
        .ok_or_else(|| IdentityError::InvalidInput {
            reason: format!("SAML federation connector '{idp_name}' missing `sso_url`"),
        })?;
    let cert = provider
        .idp_certificate_pem
        .clone()
        .ok_or_else(|| IdentityError::InvalidInput {
            reason: format!("SAML federation connector '{idp_name}' missing `idp_certificate_pem`"),
        })?;

    let display_name = provider
        .display_name
        .clone()
        .unwrap_or_else(|| idp_name.to_string());
    let attribute_map = provider.attribute_map.clone().unwrap_or_default();

    let now = Timestamp::from_micros(0);
    Ok(IdpConfig {
        id: idp_id.clone(),
        realm_id: realm_id.clone(),
        name: idp_name.to_string(),
        kind: IdpKind::Saml,
        display_name,
        issuer: entity_id,
        authorization_endpoint: sso_url,
        token_endpoint: String::new(),
        userinfo_endpoint: provider.slo_url.clone(),
        jwks_uri: None,
        scopes: Vec::new(),
        client_id: String::new(),
        client_secret: FederationSecret::new(cert),
        claim_mappings: attribute_map,
        created_at: now,
        updated_at: now,
    })
}

/// Reconciles SAML Service Providers (Hearth-as-IdP side) declared in
/// `realms.{name}.saml_service_providers`.
pub(crate) fn reconcile_saml_sps_for_realm(
    engine: &dyn IdentityEngine,
    realm_id: &RealmId,
    realm_name: &str,
    sps: &std::collections::HashMap<String, crate::config::SamlServiceProviderYaml>,
    _report: &mut ReconcileReport,
) -> Result<(), IdentityError> {
    use crate::identity::federation::saml::{SamlNameIdFormat, SamlServiceProvider};

    let mut yaml_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (sp_key, yaml) in sps {
        yaml_keys.insert(sp_key.clone());
        let nameid_format = match yaml.nameid_format.as_deref().unwrap_or("emailAddress") {
            "persistent" => SamlNameIdFormat::Persistent,
            "transient" => SamlNameIdFormat::Transient,
            "unspecified" => SamlNameIdFormat::Unspecified,
            _ => SamlNameIdFormat::EmailAddress,
        };
        let attribute_map = yaml.attribute_map.clone().unwrap_or_default();

        let sp = SamlServiceProvider {
            sp_key: sp_key.clone(),
            entity_id: yaml.entity_id.clone(),
            acs_url: yaml.acs_url.clone(),
            slo_url: yaml.slo_url.clone(),
            sp_certificate_pem: yaml.sp_certificate_pem.clone(),
            sign_assertions: yaml.sign_assertions.unwrap_or(true),
            sign_responses: yaml.sign_responses.unwrap_or(true),
            want_authn_requests_signed: yaml.want_authn_requests_signed.unwrap_or(false),
            nameid_format,
            attribute_map,
        };
        engine.register_saml_sp(realm_id, &sp)?;
        info!(realm = %realm_name, sp_key = %sp_key, "reconciled SAML SP");
    }

    // Remove SPs no longer in YAML.
    for existing in engine.list_saml_sps(realm_id)? {
        if !yaml_keys.contains(&existing.sp_key) {
            engine.delete_saml_sp(realm_id, &existing.sp_key)?;
            info!(realm = %realm_name, sp_key = %existing.sp_key, "removed SAML SP no longer in YAML");
        }
    }

    Ok(())
}

// ── Config snapshot I/O ────────────────────────────────────────────────────────

/// Loads the configuration snapshot from the system realm, if one exists.
///
/// Returns `None` on first startup (no snapshot written yet). A deserialization
/// failure is treated as a missing snapshot — it is logged as a warning and the
/// caller should proceed as if it were a first startup.
///
/// # Errors
///
/// Returns `Err` only on hard storage I/O failures (not on missing or corrupt
/// snapshot bytes — those are logged and return `Ok(None)`).
pub fn load_snapshot(storage: &dyn StorageEngine) -> Result<Option<ConfigSnapshot>, StorageError> {
    let sys = crate::identity::keys::system_realm_id();
    let key = config_snapshot_key();
    match storage.get(&sys, &key)? {
        None => Ok(None),
        Some(bytes) => match ConfigSnapshot::from_json(&bytes) {
            Ok(snap) => Ok(Some(snap)),
            Err(e) => {
                warn!(error = %e, "config snapshot is unreadable; treating as first startup");
                Ok(None)
            }
        },
    }
}

/// Persists the configuration snapshot to the system realm via `put_batch`.
///
/// The write is atomic (WAL CRC framing): a crash mid-write leaves the
/// previous snapshot intact.
///
/// # Errors
///
/// Returns `Err` on serialisation failure or storage I/O error.
pub fn save_snapshot(
    storage: &dyn StorageEngine,
    snapshot: &ConfigSnapshot,
) -> Result<(), StorageError> {
    let sys = crate::identity::keys::system_realm_id();
    let key = config_snapshot_key();
    let bytes = snapshot
        .to_canonical_json()
        .map_err(|e| StorageError::DeserializationFailed {
            reason: format!("config snapshot serialisation: {e}"),
        })?;
    storage.put_batch(&sys, &[(key, bytes)])
}

// ── Diff application ───────────────────────────────────────────────────────────

/// Applies a slice of [`ConfigDiff`] entries against the running identity
/// and RBAC engines.
///
/// The match arm is exhaustive — adding a new [`ConfigDiff`] variant without
/// a handler here is a compile error.
///
/// **Config-only variants** (email transport, token issuer/audience, OIDC issuer)
/// require no data-layer action; they are enforced at login time and logged here.
///
/// **Data variants** (org, application, role, group membership changes) call the
/// targeted reconcile function for the affected realm. Both add and remove are
/// idempotent: re-running produces the same result.
///
/// `reconcile_realms` is called after this function as a catch-all; any diff that
/// `apply_diff` successfully handles will simply be a no-op in that subsequent pass.
///
/// # Errors
///
/// Returns `Err` on storage I/O failures from data-action handlers.
/// Returns a list of realm names whose `rotate_signing_key` flag was consumed.
/// The caller should clear those flags in the config snapshot before saving so
/// subsequent restarts with the flag still in YAML do not re-rotate.
pub fn apply_diff(
    diffs: &[ConfigDiff],
    config: &Config,
    engine: &dyn IdentityEngine,
    rbac: &dyn RbacEngine,
) -> Result<Vec<String>, IdentityError> {
    let mut consumed_rotations: Vec<String> = Vec::new();
    for diff in diffs {
        match diff {
            // ── Realm lifecycle (handled by reconcile_realms) ──────────────────
            ConfigDiff::RealmAdded(name) => {
                info!(realm = %name, "config diff: realm added; reconcile_realms will create it");
            }
            ConfigDiff::RealmRemoved(name) => {
                info!(realm = %name, "config diff: realm removed; reconcile_realms will archive it");
            }

            // ── Config-only: no data action required ───────────────────────────
            ConfigDiff::EmailTransportChanged { old, new } => {
                info!(
                    old,
                    new, "config diff: email transport changed; no data migration needed"
                );
            }
            ConfigDiff::SmtpPasswordRotated => {
                info!("config diff: SMTP credentials rotated; no data migration needed");
            }
            ConfigDiff::TokenIssuerChanged { old, new } => {
                info!(
                    old = ?old,
                    new = ?new,
                    "config diff: token.issuer changed; existing tokens will fail iss validation"
                );
            }
            ConfigDiff::TokenAudienceChanged { old, new } => {
                info!(
                    old = ?old,
                    new = ?new,
                    "config diff: token.audience changed; no data migration needed"
                );
            }
            ConfigDiff::OidcIssuerChanged { old, new } => {
                info!(
                    old = ?old,
                    new = ?new,
                    "config diff: oidc.issuer changed; OIDC discovery metadata updated on next request"
                );
            }
            ConfigDiff::StorageDataDirChanged { old, new } => {
                warn!(
                    old,
                    new,
                    "config diff: storage data_dir changed between startups — \
                     this is likely a misconfiguration"
                );
            }

            // ── Realm settings: reconcile_realms calls update_realm ────────────
            ConfigDiff::RealmSettingsChanged { realm } => {
                info!(
                    realm,
                    "config diff: realm settings changed (session TTL / MFA / theme / token TTLs); \
                     reconcile_realms will call update_realm"
                );
            }

            // ── Org changes: reconcile the full org set for the realm ──────────
            ConfigDiff::OrgAdded { realm, slug } => {
                info!(
                    realm,
                    slug, "config diff: org added; reconciling organizations"
                );
                apply_org_changes(config, engine, realm);
            }
            ConfigDiff::OrgRemoved { realm, slug } => {
                info!(
                    realm,
                    slug, "config diff: org removed; archiving via org reconciliation"
                );
                apply_org_changes(config, engine, realm);
            }

            // ── Application changes: reconcile the full app set for the realm ──
            ConfigDiff::ApplicationAdded { realm, key } => {
                info!(
                    realm,
                    key, "config diff: application added; reconciling applications"
                );
                apply_app_changes(config, engine, realm)?;
            }
            ConfigDiff::ApplicationRemoved { realm, key } => {
                info!(
                    realm,
                    key, "config diff: application removed; archiving via app reconciliation"
                );
                apply_app_changes(config, engine, realm)?;
            }

            // ── Role changes: reconcile RBAC for the realm ────────────────────
            ConfigDiff::RoleAdded { realm, name } => {
                info!(realm, name, "config diff: role added; reconciling RBAC");
                apply_rbac_changes(config, engine, rbac, realm);
            }
            ConfigDiff::RoleRemoved { realm, name } => {
                info!(
                    realm,
                    name, "config diff: role removed; archiving via RBAC reconciliation"
                );
                apply_rbac_changes(config, engine, rbac, realm);
            }

            // ── Group changes: reconcile RBAC (groups) for the realm ──────────
            ConfigDiff::GroupAdded { realm, name } => {
                info!(realm, name, "config diff: group added; reconciling groups");
                apply_rbac_changes(config, engine, rbac, realm);
            }
            ConfigDiff::GroupRemoved { realm, name } => {
                info!(
                    realm,
                    name, "config diff: group removed; archiving via group reconciliation"
                );
                apply_rbac_changes(config, engine, rbac, realm);
            }

            // ── Signing key rotation ──────────────────────────────────────────
            ConfigDiff::RealmSigningKeyRotationRequested { realm } => {
                info!(realm, "config diff: signing key rotation requested");
                match apply_signing_key_rotation(config, engine, realm) {
                    Ok(()) => {
                        consumed_rotations.push(realm.clone());
                    }
                    Err(e) => {
                        warn!(realm, error = %e, "config diff: signing key rotation failed");
                    }
                }
            }
        }
    }
    Ok(consumed_rotations)
}

/// Looks up a realm by name and rotates its Ed25519 signing key.
///
/// Returns `Ok(())` on success. The caller is responsible for recording the
/// consumed realm name so the snapshot's `rotate_signing_key` flag can be
/// cleared before it is saved.
fn apply_signing_key_rotation(
    config: &Config,
    engine: &dyn IdentityEngine,
    realm_name: &str,
) -> Result<(), IdentityError> {
    let realm = match engine.get_realm_by_name(realm_name) {
        Ok(Some(r)) => r,
        Ok(None) => {
            trace!(
                realm = realm_name,
                "apply_diff: realm not yet in storage; key rotation skipped"
            );
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let grace_period_secs = config
        .token
        .signing_key_rotation_grace_period
        .as_deref()
        .and_then(|s| crate::config::parse_duration_to_micros(s).ok())
        .map(|micros| (micros / 1_000_000) as u64)
        .unwrap_or(86_400); // default: 24 hours
    engine.rotate_realm_signing_key(realm.id(), grace_period_secs)
}

/// Looks up a realm by name and reconciles its organization set from config.
///
/// Logs a warning and returns if the realm is not found (it may not yet exist
/// if the realm itself is being created in this same startup).
fn apply_org_changes(config: &Config, engine: &dyn IdentityEngine, realm_name: &str) {
    let realm_yaml = match config.realms.as_ref().and_then(|r| r.get(realm_name)) {
        Some(y) => y,
        None => {
            trace!(
                realm = realm_name,
                "apply_diff: org change for realm not in config; skipping"
            );
            return;
        }
    };
    let realm = match engine.get_realm_by_name(realm_name) {
        Ok(Some(r)) => r,
        Ok(None) => {
            trace!(
                realm = realm_name,
                "apply_diff: realm not yet in storage; reconcile_realms will handle"
            );
            return;
        }
        Err(e) => {
            warn!(realm = realm_name, error = %e, "apply_diff: realm lookup failed during org reconciliation");
            return;
        }
    };
    let empty = HashMap::new();
    let orgs = realm_yaml.organizations.as_ref().unwrap_or(&empty);
    let mut report = ReconcileReport::default();
    if let Err(e) = reconcile_organizations(engine, realm.id(), realm_name, orgs, &mut report) {
        warn!(realm = realm_name, error = %e, "apply_diff: org reconciliation failed");
    }
}

/// Looks up a realm by name and reconciles its application set from config.
///
/// # Errors
///
/// Returns `Err` on storage I/O failures from the underlying reconcile call.
fn apply_app_changes(
    config: &Config,
    engine: &dyn IdentityEngine,
    realm_name: &str,
) -> Result<(), IdentityError> {
    let realm_yaml = match config.realms.as_ref().and_then(|r| r.get(realm_name)) {
        Some(y) => y,
        None => {
            trace!(
                realm = realm_name,
                "apply_diff: app change for realm not in config; skipping"
            );
            return Ok(());
        }
    };
    let realm = match engine.get_realm_by_name(realm_name)? {
        Some(r) => r,
        None => {
            trace!(
                realm = realm_name,
                "apply_diff: realm not yet in storage; reconcile_realms will handle"
            );
            return Ok(());
        }
    };
    // Merge `applications` and `oauth_clients` aliases.
    let apps = realm_yaml
        .applications
        .as_ref()
        .or(realm_yaml.oauth_clients.as_ref());
    if let Some(apps) = apps {
        let mut report = ReconcileReport::default();
        reconcile_applications(engine, realm.id(), realm_name, apps, &mut report)?;
    }
    Ok(())
}

/// Looks up a realm by name and reconciles RBAC (roles + groups) from config.
///
/// Failures are logged rather than propagated so one bad RBAC block does not
/// block other diff handlers.
fn apply_rbac_changes(
    config: &Config,
    engine: &dyn IdentityEngine,
    rbac: &dyn RbacEngine,
    realm_name: &str,
) {
    let realm_yaml = match config.realms.as_ref().and_then(|r| r.get(realm_name)) {
        Some(y) => y,
        None => {
            trace!(
                realm = realm_name,
                "apply_diff: RBAC change for realm not in config; skipping"
            );
            return;
        }
    };
    let realm = match engine.get_realm_by_name(realm_name) {
        Ok(Some(r)) => r,
        Ok(None) => {
            trace!(
                realm = realm_name,
                "apply_diff: realm not yet in storage; reconcile_realms will handle"
            );
            return;
        }
        Err(e) => {
            warn!(realm = realm_name, error = %e, "apply_diff: realm lookup failed during RBAC reconciliation");
            return;
        }
    };
    reconcile_rbac_for_realm(rbac, realm.id(), realm_name, realm_yaml);
}

// ── Orphaned-realm detection ───────────────────────────────────────────────

/// Scans for archived realms that still contain users but have no declared
/// resolution (`migrate_from` on a destination realm, or `archive_drop: true`
/// on the slug's own YAML entry).
///
/// For each newly detected orphan:
/// - emits a structured `warn!` with slug, user count, and org count
/// - writes a `config:orphan:{slug}` record to the system realm in storage
///
/// For each previously detected orphan that is now resolved:
/// - deletes the `config:orphan:{slug}` key from storage
///
/// Returns the full current set of orphan records (empty when all resolved).
///
/// Non-fatal: all I/O errors are logged rather than returned so startup
/// continues even when the check encounters storage problems.
pub fn detect_orphaned_realms(
    engine: &dyn IdentityEngine,
    config: &Config,
    storage: &dyn StorageEngine,
) -> Vec<OrphanRecord> {
    use std::collections::{HashMap, HashSet};
    use std::time::{SystemTime, UNIX_EPOCH};

    // Build the set of slugs that are considered resolved:
    //   - a destination realm with `migrate_from: slug` resolves `slug`
    //   - a YAML entry with `archive_drop: true` resolves its own slug
    let mut resolved_slugs: HashSet<String> = HashSet::new();
    if let Some(yaml_realms) = config.realms.as_ref() {
        for (slug, yaml_cfg) in yaml_realms {
            if let Some(src) = yaml_cfg.migrate_from.as_deref() {
                resolved_slugs.insert(src.to_string());
            }
            if yaml_cfg.archive_drop.unwrap_or(false) {
                resolved_slugs.insert(slug.clone());
            }
        }
    }

    let sys = crate::identity::keys::system_realm_id();

    // Load existing orphan records so we can preserve `detected_at` and
    // detect newly resolved orphans.
    let orphan_prefix = config_orphan_scan_prefix();
    let orphan_end = prefix_end(&orphan_prefix);
    let existing: HashMap<String, OrphanRecord> = storage
        .scan(&sys, &orphan_prefix, &orphan_end)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| {
            let slug = std::str::from_utf8(&entry.key[orphan_prefix.len()..])
                .ok()?
                .to_string();
            let record: OrphanRecord = serde_json::from_slice(&entry.value).ok()?;
            Some((slug, record))
        })
        .collect();

    // Walk all realms in storage; collect orphan candidates.
    let mut current: HashMap<String, OrphanRecord> = HashMap::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = match engine.list_realms(cursor.as_deref(), 100) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "orphan detection: failed to list realms; skipping");
                break;
            }
        };
        for realm in &page.items {
            if realm.status() != RealmStatus::Archived {
                continue;
            }
            let slug = realm.name().to_string();
            if resolved_slugs.contains(&slug) {
                continue;
            }

            // Count users in the archived realm (full pagination).
            let mut user_count: u64 = 0;
            let mut ucursor: Option<String> = None;
            while let Ok(up) = engine.list_users(realm.id(), ucursor.as_deref(), 1_000) {
                user_count += up.items.len() as u64;
                match up.next_cursor {
                    Some(c) => ucursor = Some(c),
                    None => break,
                }
            }
            if user_count == 0 {
                continue; // Empty archived realm is not an orphan risk.
            }

            // Count organizations.
            let mut org_count: u64 = 0;
            let mut ocursor: Option<String> = None;
            while let Ok(op) = engine.list_organizations(realm.id(), ocursor.as_deref(), 1_000) {
                org_count += op.items.len() as u64;
                match op.next_cursor {
                    Some(c) => ocursor = Some(c),
                    None => break,
                }
            }

            // Preserve the original `detected_at` if this orphan was already known.
            let detected_at = existing
                .get(&slug)
                .map(|r| r.detected_at.clone())
                .unwrap_or_else(|| {
                    let secs = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    crate::config::diff::format_unix_secs_as_rfc3339(secs)
                });

            current.insert(
                slug.clone(),
                OrphanRecord {
                    realm_slug: slug,
                    detected_at,
                    user_count,
                    org_count,
                },
            );
        }
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }

    // Emit warnings and persist new orphan records.
    for (slug, record) in &current {
        if !existing.contains_key(slug) {
            warn!(
                realm = slug,
                user_count = record.user_count,
                org_count = record.org_count,
                "orphaned realm detected: archived realm still contains users \
                 with no migration destination. \
                 Add `migrate_from: {slug}` to a destination realm in hearth.yaml, \
                 or add `archive_drop: true` to suppress this warning.",
            );
        }
        match serde_json::to_vec(record) {
            Ok(bytes) => {
                if let Err(e) = storage.put(&sys, &config_orphan_key(slug), &bytes) {
                    warn!(realm = slug, error = %e, "orphan detection: failed to write orphan record");
                }
            }
            Err(e) => {
                warn!(realm = slug, error = %e, "orphan detection: failed to serialise orphan record");
            }
        }
    }

    // Clear resolved orphan records.
    for slug in existing.keys() {
        if !current.contains_key(slug) {
            if let Err(e) = storage.delete(&sys, &config_orphan_key(slug)) {
                warn!(realm = slug, error = %e, "orphan detection: failed to delete resolved orphan record");
            } else {
                info!(
                    realm = slug,
                    "orphaned realm resolved: config:orphan key cleared"
                );
            }
        }
    }

    current.into_values().collect()
}

/// Loads the current set of orphan records from storage without running
/// detection.  Used by the web layer to populate the admin dashboard banner.
///
/// Returns an empty `Vec` on any storage error (non-fatal).
pub fn load_orphaned_realms(storage: &dyn StorageEngine) -> Vec<OrphanRecord> {
    let sys = crate::identity::keys::system_realm_id();
    let prefix = config_orphan_scan_prefix();
    let end = prefix_end(&prefix);
    storage
        .scan(&sys, &prefix, &end)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| serde_json::from_slice(&entry.value).ok())
        .collect()
}
