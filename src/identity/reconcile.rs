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

use crate::config::{AuthConfig, Config, TenantYamlConfig};
use crate::identity::error::IdentityError;
use crate::identity::{
    CreateTenantRequest, IdentityEngine, TenantConfig, TenantStatus, UpdateTenantRequest,
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

        match engine.get_tenant_by_name(name)? {
            None => {
                // Create new tenant
                engine.create_tenant(&CreateTenantRequest {
                    name: name.clone(),
                    config: Some(tenant_config),
                })?;
                report.created.push(name.clone());
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
            }
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
