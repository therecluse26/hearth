//! Tenant reconciliation: syncs YAML-declared tenants with storage.
//!
//! Called once at startup. Compares the `tenants:` map in `hearth.yaml`
//! against the tenant records in storage and creates, updates, or
//! archives tenants to match the declared state.
//!
//! # Rules
//!
//! 1. `config.tenants == None` AND no tenants in storage → create "default"
//! 2. `config.tenants == None` AND tenants exist → skip (backward compat)
//! 3. `config.tenants == Some(map)` →
//!    - YAML entry not in storage → create
//!    - YAML entry in storage → update config if changed, un-archive if Archived
//!    - Storage tenant not in YAML → set status to Archived

use std::collections::HashMap;

use tracing::info;
use uuid::Uuid;

use crate::config::{ApplicationYamlConfig, AuthConfig, Config, OrganizationYamlConfig, TenantYamlConfig};
use crate::core::{ClientId, TenantId};
use crate::identity::error::IdentityError;
use crate::identity::oidc::UpdateClientRequest;
use crate::identity::{
    CreateOrganizationRequest, CreateTenantRequest, IdentityEngine, ImportClientRequest,
    OrganizationConfig, TenantConfig, TenantStatus, UpdateOrganizationRequest, UpdateTenantRequest,
};

/// Report of what tenant reconciliation did.
#[derive(Debug, Default)]
pub struct ReconcileReport {
    /// Names of tenants created from YAML.
    pub created: Vec<String>,
    /// Names of tenants whose config was updated from YAML.
    pub updated: Vec<String>,
    /// Names of tenants archived (removed from YAML).
    pub archived: Vec<String>,
    /// Names of tenants un-archived (reappeared in YAML).
    pub unarchived: Vec<String>,
    /// Application reconciliation results per tenant.
    pub applications: Vec<AppReconcileEntry>,
    /// Organization reconciliation results per tenant.
    pub organizations: Vec<OrgReconcileEntry>,
}

/// Reconciliation result for a single application.
#[derive(Debug)]
pub struct AppReconcileEntry {
    /// Tenant name.
    pub tenant: String,
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
    /// Tenant name.
    pub tenant: String,
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

/// Reconciles YAML-declared tenants with storage.
///
/// # Errors
///
/// Returns `Err` if any storage operation fails. Partial reconciliation
/// (some tenants created before a failure) is not rolled back — the
/// caller should retry on next startup.
pub fn reconcile_tenants(
    engine: &dyn IdentityEngine,
    config: &Config,
) -> Result<ReconcileReport, IdentityError> {
    let mut report = ReconcileReport::default();

    match &config.tenants {
        None => {
            // Check if any tenants exist
            let page = engine.list_tenants(None, 1)?;
            if page.items.is_empty() {
                // No tenants and no YAML config → create "default"
                let tenant_config = default_tenant_config(&config.auth, config);
                engine.create_tenant(&CreateTenantRequest {
                    name: "default".to_string(),
                    config: Some(tenant_config),
                })?;
                report.created.push("default".to_string());
            }
            // If tenants exist, skip reconciliation (backward compat)
        }
        Some(yaml_tenants) => {
            reconcile_declared_tenants(engine, yaml_tenants, config, &mut report)?;
        }
    }

    Ok(report)
}

/// Reconciles a declared `tenants:` map.
fn reconcile_declared_tenants(
    engine: &dyn IdentityEngine,
    yaml_tenants: &HashMap<String, TenantYamlConfig>,
    config: &Config,
    report: &mut ReconcileReport,
) -> Result<(), IdentityError> {
    // Build a set of YAML tenant names for archive detection
    let yaml_names: std::collections::HashSet<&str> =
        yaml_tenants.keys().map(String::as_str).collect();

    // Process each YAML entry
    for (name, yaml_cfg) in yaml_tenants {
        let tenant_config = yaml_cfg.to_tenant_config(&config.auth, config.email.branding.as_ref());

        let tenant_id = match engine.get_tenant_by_name(name)? {
            None => {
                // Create new tenant
                let tenant = engine.create_tenant(&CreateTenantRequest {
                    name: name.clone(),
                    config: Some(tenant_config),
                })?;
                report.created.push(name.clone());
                tenant.id().clone()
            }
            Some(existing) => {
                // Update if config changed or status needs un-archiving
                let needs_config_update = existing.config() != &tenant_config;
                let needs_unarchive = existing.status() == TenantStatus::Archived;

                if needs_config_update || needs_unarchive {
                    let mut update = UpdateTenantRequest::default();
                    if needs_config_update {
                        update.config = Some(tenant_config);
                    }
                    if needs_unarchive {
                        update.status = Some(TenantStatus::Active);
                        report.unarchived.push(name.clone());
                    }
                    engine.update_tenant(existing.id(), &update)?;
                    if needs_config_update && !needs_unarchive {
                        report.updated.push(name.clone());
                    }
                }
                existing.id().clone()
            }
        };

        // Reconcile applications declared under this tenant
        if let Some(apps) = &yaml_cfg.applications {
            reconcile_applications(engine, &tenant_id, name, apps, report)?;
        }

        // Reconcile organizations declared under this tenant
        if let Some(orgs) = &yaml_cfg.organizations {
            reconcile_organizations(engine, &tenant_id, name, orgs, report)?;
        }
    }

    // Archive storage tenants not in YAML
    let mut cursor = None;
    loop {
        let page = engine.list_tenants(cursor.as_deref(), 100)?;
        for tenant in &page.items {
            if !yaml_names.contains(tenant.name()) && tenant.status() != TenantStatus::Archived {
                engine.update_tenant(
                    tenant.id(),
                    &UpdateTenantRequest {
                        status: Some(TenantStatus::Archived),
                        ..Default::default()
                    },
                )?;
                report.archived.push(tenant.name().to_string());
            }
        }
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }

    Ok(())
}

/// Builds a `TenantConfig` from global auth defaults (used for the auto-created "default" tenant).
fn default_tenant_config(auth: &AuthConfig, config: &Config) -> TenantConfig {
    let yaml = TenantYamlConfig::default();
    yaml.to_tenant_config(auth, config.email.branding.as_ref())
}

/// UUID v5 namespace for deterministic application client IDs.
///
/// Generated once from `uuid::Uuid::new_v5(NAMESPACE_URL, b"hearth-app")`.
/// This is a stable constant — changing it would break all existing
/// deterministic client IDs.
const APP_NAMESPACE: Uuid = Uuid::from_bytes([
    0x8b, 0x07, 0x4e, 0x8c, 0x3e, 0x6a, 0x5a, 0x8e, 0x96, 0x1d, 0x8f, 0x2b, 0xaa, 0xe7, 0x1b,
    0xf4,
]);

/// Generates a deterministic `ClientId` from tenant name and application key.
///
/// Uses UUID v5 (SHA-1 + namespace) so the same `(tenant, app)` pair always
/// produces the same ID across server restarts.
fn deterministic_client_id(tenant_name: &str, app_key: &str) -> ClientId {
    let input = format!("{tenant_name}/{app_key}");
    let id = Uuid::new_v5(&APP_NAMESPACE, input.as_bytes());
    ClientId::new(id)
}

/// Reconciles application declarations for a single tenant.
///
/// Called after the tenant itself has been reconciled (so `tenant_id` is valid).
pub(crate) fn reconcile_applications(
    engine: &dyn IdentityEngine,
    tenant_id: &TenantId,
    tenant_name: &str,
    apps: &HashMap<String, ApplicationYamlConfig>,
    report: &mut ReconcileReport,
) -> Result<(), IdentityError> {
    // Process each YAML application
    for (app_key, app_cfg) in apps {
        let client_id = deterministic_client_id(tenant_name, app_key);
        let grant_types = app_cfg
            .grant_types
            .clone()
            .unwrap_or_else(|| vec!["authorization_code".to_string()]);
        let redirect_uris = app_cfg.redirect_uris.clone().unwrap_or_default();

        match engine.get_client(tenant_id, &client_id) {
            Ok(Some(existing)) => {
                // Client exists — update if changed
                let name_changed = existing.client_name() != app_cfg.name;
                let uris_changed = existing.redirect_uris() != redirect_uris;
                let grants_changed = existing.grant_types() != grant_types;

                if name_changed || uris_changed || grants_changed {
                    engine.update_client(
                        tenant_id,
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
                        tenant = tenant_name,
                        app = app_key,
                        "updated application from YAML"
                    );
                    report.applications.push(AppReconcileEntry {
                        tenant: tenant_name.to_string(),
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
                    tenant_id,
                    &ImportClientRequest {
                        id: Some(client_id),
                        client_name: app_cfg.name.clone(),
                        redirect_uris,
                        client_secret: secret,
                        grant_types,
                    },
                )?;
                info!(
                    tenant = tenant_name,
                    app = app_key,
                    "created application from YAML"
                );
                report.applications.push(AppReconcileEntry {
                    tenant: tenant_name.to_string(),
                    app_key: app_key.clone(),
                    action: AppReconcileAction::Created,
                });
            }
            Err(e) => return Err(e),
        }
    }

    // Note: unlike tenants, applications removed from YAML are NOT
    // automatically deleted. Deterministic UUIDs prevent us from reliably
    // distinguishing reconciliation-managed clients from manually-created
    // ones. Admins can delete orphaned clients via the Admin UI.

    Ok(())
}

/// Reconciles organization declarations for a single tenant.
///
/// The YAML key is used as the slug. Organizations are created if missing or
/// updated if their name, description, or config have changed. Members and
/// invitations are runtime-only and not managed by reconciliation.
pub(crate) fn reconcile_organizations(
    engine: &dyn IdentityEngine,
    tenant_id: &TenantId,
    tenant_name: &str,
    orgs: &HashMap<String, OrganizationYamlConfig>,
    report: &mut ReconcileReport,
) -> Result<(), IdentityError> {
    for (slug, org_cfg) in orgs {
        let yaml_config = OrganizationConfig {
            max_members: org_cfg.config.as_ref().and_then(|c| c.max_members),
        };
        let description = org_cfg.description.clone().unwrap_or_default();

        if let Some(existing) = engine.get_organization_by_slug(tenant_id, slug)? {
            // Update if name, description, or config changed
            let name_changed = existing.name() != org_cfg.name;
            let desc_changed = existing.description() != description;
            let config_changed = existing.config() != &yaml_config;

            if name_changed || desc_changed || config_changed {
                engine.update_organization(
                    tenant_id,
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
                    tenant = tenant_name,
                    org = slug,
                    "updated organization from YAML"
                );
                report.organizations.push(OrgReconcileEntry {
                    tenant: tenant_name.to_string(),
                    slug: slug.clone(),
                    action: OrgReconcileAction::Updated,
                });
            }
        } else {
            // Create new organization
            engine.create_organization(
                tenant_id,
                &CreateOrganizationRequest {
                    name: org_cfg.name.clone(),
                    slug: slug.clone(),
                    description: Some(description),
                    config: Some(yaml_config),
                },
            )?;
            info!(
                tenant = tenant_name,
                org = slug,
                "created organization from YAML"
            );
            report.organizations.push(OrgReconcileEntry {
                tenant: tenant_name.to_string(),
                slug: slug.clone(),
                action: OrgReconcileAction::Created,
            });
        }
    }

    Ok(())
}
