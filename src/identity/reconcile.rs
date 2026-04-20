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

use tracing::info;
use uuid::Uuid;

use crate::config::{
    ApplicationYamlConfig, AuthConfig, Config, OrganizationYamlConfig, RealmYamlConfig,
};
use crate::core::{ClientId, RealmId};
use crate::identity::error::IdentityError;
use crate::identity::oidc::UpdateClientRequest;
use crate::identity::{
    CreateOrganizationRequest, CreateRealmRequest, IdentityEngine, ImportClientRequest,
    OrganizationConfig, RealmConfig, RealmStatus, UpdateOrganizationRequest, UpdateRealmRequest,
};

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
    /// Application was deleted (removed from YAML).
    Deleted,
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
                engine.create_realm(&CreateRealmRequest {
                    name: "default".to_string(),
                    config: Some(realm_config),
                })?;
                report.created.push("default".to_string());
            }
            // If realms exist, skip reconciliation (backward compat)
        }
        Some(yaml_realms) => {
            reconcile_declared_realms(engine, yaml_realms, config, &mut report)?;
        }
    }

    Ok(report)
}

/// Reconciles a declared `realms:` map.
fn reconcile_declared_realms(
    engine: &dyn IdentityEngine,
    yaml_realms: &HashMap<String, RealmYamlConfig>,
    config: &Config,
    report: &mut ReconcileReport,
) -> Result<(), IdentityError> {
    // Build a set of YAML realm names for archive detection
    let yaml_names: std::collections::HashSet<&str> =
        yaml_realms.keys().map(String::as_str).collect();

    // Process each YAML entry
    for (name, yaml_cfg) in yaml_realms {
        let realm_config = yaml_cfg.to_realm_config(&config.auth, config.email.branding.as_ref());

        let realm_id = match engine.get_realm_by_name(name)? {
            None => {
                // Create new realm
                let realm = engine.create_realm(&CreateRealmRequest {
                    name: name.clone(),
                    config: Some(realm_config),
                })?;
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
                existing.id().clone()
            }
        };

        // Reconcile applications declared under this realm
        if let Some(apps) = &yaml_cfg.applications {
            reconcile_applications(engine, &realm_id, name, apps, report)?;
        }

        // Reconcile organizations declared under this realm
        if let Some(orgs) = &yaml_cfg.organizations {
            reconcile_organizations(engine, &realm_id, name, orgs, report)?;
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
fn default_realm_config(auth: &AuthConfig, config: &Config) -> RealmConfig {
    let yaml = RealmYamlConfig::default();
    yaml.to_realm_config(auth, config.email.branding.as_ref())
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

/// Reconciles application declarations for a single realm.
///
/// Called after the realm itself has been reconciled (so `realm_id` is valid).
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

        match engine.get_client(realm_id, &client_id) {
            Ok(Some(existing)) => {
                // Client exists — update if changed
                let name_changed = existing.client_name() != app_cfg.name;
                let uris_changed = existing.redirect_uris() != redirect_uris;
                let grants_changed = existing.grant_types() != grant_types;

                if name_changed || uris_changed || grants_changed {
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
                        },
                    )?;
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
                        id: Some(client_id),
                        client_name: app_cfg.name.clone(),
                        redirect_uris,
                        client_secret: secret,
                        grant_types,
                    },
                )?;
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

    // Note: unlike realms, applications removed from YAML are NOT
    // automatically deleted. Deterministic UUIDs prevent us from reliably
    // distinguishing reconciliation-managed clients from manually-created
    // ones. Admins can delete orphaned clients via the Admin UI.

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
            // Update if name, description, or config changed
            let name_changed = existing.name() != org_cfg.name;
            let desc_changed = existing.description() != description;
            let config_changed = existing.config() != &yaml_config;

            if name_changed || desc_changed || config_changed {
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
                        ..UpdateOrganizationRequest::default()
                    },
                )?;
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

    Ok(())
}
