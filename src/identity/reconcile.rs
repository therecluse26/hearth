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

use crate::authz::AuthorizationEngine;
use crate::config::{
    ApplicationYamlConfig, AuthConfig, Config, FederationProviderYaml, FederationYamlConfig,
    OrganizationYamlConfig, RealmYamlConfig,
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
    authz: &dyn AuthorizationEngine,
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
                install_preset_or_log(authz, realm.id(), "default");
                report.created.push("default".to_string());
            }
            // If realms exist, skip reconciliation (backward compat)
        }
        Some(yaml_realms) => {
            reconcile_declared_realms(engine, authz, yaml_realms, config, &mut report)?;
        }
    }

    Ok(report)
}

/// Installs the Roles & Permissions preset namespace on a freshly created
/// realm, logging (but not failing) if the install errors. The realm record
/// is already durable at this point; a missing namespace is recoverable
/// (the next visit to the Roles UI would install it), so we prefer a log
/// over aborting reconciliation mid-run.
fn install_preset_or_log(authz: &dyn AuthorizationEngine, realm_id: &RealmId, realm_name: &str) {
    if let Err(e) = crate::authz::ensure_preset_namespace(authz, realm_id) {
        tracing::warn!(
            realm = realm_name,
            error = %e,
            "failed to install preset authz namespace on new realm"
        );
    }
}

/// Reconciles a declared `realms:` map.
fn reconcile_declared_realms(
    engine: &dyn IdentityEngine,
    authz: &dyn AuthorizationEngine,
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
        let realm_config = yaml_cfg.to_realm_config(&config.auth, config.email.branding.as_ref());

        let realm_id = match engine.get_realm_by_name(name)? {
            None => {
                // Create new realm
                let realm = engine.create_realm(&CreateRealmRequest {
                    name: name.clone(),
                    config: Some(realm_config),
                })?;
                install_preset_or_log(authz, realm.id(), name);
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
                // Client exists — update if changed
                let name_changed = existing.client_name() != app_cfg.name;
                let uris_changed = existing.redirect_uris() != redirect_uris;
                let grants_changed = existing.grant_types() != grant_types;
                let consent_changed = existing.require_consent() != cfg_require_consent;
                let logo_changed = existing.client_logo_url() != cfg_logo.as_deref();

                if name_changed || uris_changed || grants_changed || consent_changed || logo_changed
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
                        id: Some(client_id.clone()),
                        client_name: app_cfg.name.clone(),
                        redirect_uris,
                        client_secret: secret,
                        grant_types,
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
    // YAML. Only removes clients whose ID matches the deterministic UUID v5
    // pattern (i.e., was created by reconciliation). Manually-created legacy
    // clients with random UUIDs are left untouched.
    let yaml_client_ids: std::collections::HashSet<ClientId> = apps
        .keys()
        .map(|k| deterministic_client_id(realm_name, k))
        .collect();

    let mut cursor = None;
    loop {
        let page = engine.list_clients(realm_id, cursor.as_deref(), 100)?;
        for client in &page.items {
            let cid = client.client_id().clone();
            // Only consider clients with deterministic IDs (reconciliation-managed).
            // If the ID matches what we'd generate for ANY app key in this realm,
            // but isn't in the current YAML set, it was removed — delete it.
            if !yaml_client_ids.contains(&cid) && is_deterministic_id(realm_name, &cid) {
                engine.delete_client(realm_id, &cid)?;
                info!(
                    realm = realm_name,
                    client_id = %cid.as_uuid(),
                    name = client.client_name(),
                    "deleted application removed from YAML"
                );
                report.applications.push(AppReconcileEntry {
                    realm: realm_name.to_string(),
                    app_key: client.client_name().to_string(),
                    action: AppReconcileAction::Deleted,
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
        claim_mappings: std::collections::BTreeMap::new(),
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
