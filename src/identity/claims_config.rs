//! Declarative claim-profile configuration.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::core::Timestamp;
use crate::identity::oidc::{ClientTrustLevel, OAuthClient};
use crate::identity::User;

/// Closed set of canonical user fields exposed to claim mappers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalUserField {
    Email,
    DisplayName,
    FirstName,
    LastName,
    PreferredUsername,
    Nickname,
    Picture,
    Website,
    Gender,
    Birthdate,
    Locale,
    Zoneinfo,
    PhoneNumber,
    Address,
    UpdatedAt,
}

/// Source from which a claim value is produced.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum ClaimSource {
    RolesFromAssignments,
    GroupsFromMemberships,
    EffectivePermissions,
    OrgContext,
    CanonicalUserField { field: CanonicalUserField },
    UserAttribute { attribute: String },
    RoleSubset { prefix: String },
    Constant { value: Value },
    Omit,
}

/// A single declarative claim mapping.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClaimMapping {
    pub claim: String,
    pub source: ClaimSource,
    #[serde(default = "default_true")]
    pub include_in_access_token: bool,
    #[serde(default = "default_true")]
    pub include_in_id_token: bool,
    #[serde(default)]
    pub include_in_userinfo: bool,
    #[serde(default)]
    pub first_party_only: bool,
    #[serde(default)]
    pub required_scopes: Option<Vec<String>>,
    #[serde(default)]
    pub allowed_clients: Option<Vec<String>>,
}

const fn default_true() -> bool {
    true
}

/// Realm claim profile metadata.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClaimProfile {
    #[serde(default)]
    pub mappings: Vec<ClaimMapping>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<Timestamp>,
}

/// Token target for per-surface claim evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClaimTarget {
    AccessToken,
    IdToken,
    UserInfo,
}

/// Inputs required to evaluate a claim mapping.
#[derive(Clone, Debug)]
pub struct ClaimEvaluationContext<'a> {
    pub user: &'a User,
    pub client: &'a OAuthClient,
    pub roles: &'a [String],
    pub groups: &'a [String],
    pub permissions: &'a [String],
    pub granted_scopes: &'a BTreeSet<String>,
    pub oid: Option<&'a str>,
}

impl ClaimMapping {
    /// Returns true if this mapping is configured for `target`.
    pub fn includes_target(&self, target: ClaimTarget) -> bool {
        match target {
            ClaimTarget::AccessToken => self.include_in_access_token,
            ClaimTarget::IdToken => self.include_in_id_token,
            ClaimTarget::UserInfo => self.include_in_userinfo,
        }
    }

    /// Whether all release gates pass.
    pub fn gates_pass(&self, client: &OAuthClient, granted_scopes: &BTreeSet<String>) -> bool {
        if self.first_party_only && client.trust_level() != ClientTrustLevel::FirstParty {
            return false;
        }
        if let Some(required_scopes) = &self.required_scopes {
            if !required_scopes
                .iter()
                .any(|scope| granted_scopes.contains(scope))
            {
                return false;
            }
        }
        if let Some(allowed_clients) = &self.allowed_clients {
            if !allowed_clients.iter().any(|slug| slug == client.slug()) {
                return false;
            }
        }
        true
    }

    /// Evaluates the mapping into a JSON value. `None` means omit.
    pub fn evaluate(&self, ctx: &ClaimEvaluationContext<'_>) -> Option<Value> {
        match &self.source {
            ClaimSource::RolesFromAssignments => Some(Value::Array(
                ctx.roles.iter().cloned().map(Value::String).collect(),
            )),
            ClaimSource::GroupsFromMemberships => Some(Value::Array(
                ctx.groups.iter().cloned().map(Value::String).collect(),
            )),
            ClaimSource::EffectivePermissions => Some(Value::Array(
                ctx.permissions.iter().cloned().map(Value::String).collect(),
            )),
            ClaimSource::OrgContext => ctx.oid.map(|oid| Value::String(oid.to_string())),
            ClaimSource::CanonicalUserField { field } => canonical_field_value(ctx.user, field),
            ClaimSource::UserAttribute { attribute } => ctx
                .user
                .attributes()
                .get(attribute)
                .cloned()
                .map(Value::String),
            ClaimSource::RoleSubset { prefix } => {
                let roles: Vec<Value> = ctx
                    .roles
                    .iter()
                    .filter(|role| role.starts_with(prefix))
                    .cloned()
                    .map(Value::String)
                    .collect();
                Some(Value::Array(roles))
            }
            ClaimSource::Constant { value } => Some(value.clone()),
            ClaimSource::Omit => None,
        }
    }
}

fn canonical_field_value(user: &User, field: &CanonicalUserField) -> Option<Value> {
    match field {
        CanonicalUserField::Email => Some(Value::String(user.email().to_string())),
        CanonicalUserField::DisplayName => Some(Value::String(user.display_name().to_string())),
        CanonicalUserField::FirstName => Some(Value::String(user.first_name().to_string())),
        CanonicalUserField::LastName => Some(Value::String(user.last_name().to_string())),
        CanonicalUserField::PreferredUsername => Some(Value::String(user.email().to_string())),
        CanonicalUserField::Nickname => None,
        CanonicalUserField::Picture => None,
        CanonicalUserField::Website => None,
        CanonicalUserField::Gender => None,
        CanonicalUserField::Birthdate => None,
        CanonicalUserField::Locale => None,
        CanonicalUserField::Zoneinfo => None,
        CanonicalUserField::PhoneNumber => None,
        CanonicalUserField::Address => None,
        CanonicalUserField::UpdatedAt => Some(Value::Number(serde_json::Number::from(
            user.updated_at().as_micros() / 1_000_000,
        ))),
    }
}

/// Default built-in mappings.
pub fn default_claim_profile() -> Vec<ClaimMapping> {
    vec![
        ClaimMapping {
            claim: "roles".to_string(),
            source: ClaimSource::RolesFromAssignments,
            include_in_access_token: true,
            include_in_id_token: true,
            include_in_userinfo: false,
            first_party_only: true,
            required_scopes: None,
            allowed_clients: None,
        },
        ClaimMapping {
            claim: "groups".to_string(),
            source: ClaimSource::GroupsFromMemberships,
            include_in_access_token: true,
            include_in_id_token: true,
            include_in_userinfo: false,
            first_party_only: true,
            required_scopes: None,
            allowed_clients: None,
        },
        ClaimMapping {
            claim: "permissions".to_string(),
            source: ClaimSource::EffectivePermissions,
            include_in_access_token: true,
            include_in_id_token: false,
            include_in_userinfo: false,
            first_party_only: true,
            required_scopes: None,
            allowed_clients: None,
        },
        ClaimMapping {
            claim: "email".to_string(),
            source: ClaimSource::CanonicalUserField {
                field: CanonicalUserField::Email,
            },
            include_in_access_token: false,
            include_in_id_token: true,
            include_in_userinfo: true,
            first_party_only: false,
            required_scopes: Some(vec!["email".to_string()]),
            allowed_clients: None,
        },
        ClaimMapping {
            claim: "name".to_string(),
            source: ClaimSource::CanonicalUserField {
                field: CanonicalUserField::DisplayName,
            },
            include_in_access_token: false,
            include_in_id_token: true,
            include_in_userinfo: true,
            first_party_only: false,
            required_scopes: Some(vec!["profile".to_string()]),
            allowed_clients: None,
        },
        ClaimMapping {
            claim: "given_name".to_string(),
            source: ClaimSource::CanonicalUserField {
                field: CanonicalUserField::FirstName,
            },
            include_in_access_token: false,
            include_in_id_token: true,
            include_in_userinfo: true,
            first_party_only: false,
            required_scopes: Some(vec!["profile".to_string()]),
            allowed_clients: None,
        },
        ClaimMapping {
            claim: "family_name".to_string(),
            source: ClaimSource::CanonicalUserField {
                field: CanonicalUserField::LastName,
            },
            include_in_access_token: false,
            include_in_id_token: true,
            include_in_userinfo: true,
            first_party_only: false,
            required_scopes: Some(vec!["profile".to_string()]),
            allowed_clients: None,
        },
        ClaimMapping {
            claim: "picture".to_string(),
            source: ClaimSource::CanonicalUserField {
                field: CanonicalUserField::Picture,
            },
            include_in_access_token: false,
            include_in_id_token: true,
            include_in_userinfo: true,
            first_party_only: false,
            required_scopes: Some(vec!["profile".to_string()]),
            allowed_clients: None,
        },
        ClaimMapping {
            claim: "locale".to_string(),
            source: ClaimSource::CanonicalUserField {
                field: CanonicalUserField::Locale,
            },
            include_in_access_token: false,
            include_in_id_token: true,
            include_in_userinfo: true,
            first_party_only: false,
            required_scopes: Some(vec!["profile".to_string()]),
            allowed_clients: None,
        },
        ClaimMapping {
            claim: "zoneinfo".to_string(),
            source: ClaimSource::CanonicalUserField {
                field: CanonicalUserField::Zoneinfo,
            },
            include_in_access_token: false,
            include_in_id_token: true,
            include_in_userinfo: true,
            first_party_only: false,
            required_scopes: Some(vec!["profile".to_string()]),
            allowed_clients: None,
        },
        ClaimMapping {
            claim: "phone_number".to_string(),
            source: ClaimSource::CanonicalUserField {
                field: CanonicalUserField::PhoneNumber,
            },
            include_in_access_token: false,
            include_in_id_token: true,
            include_in_userinfo: true,
            first_party_only: false,
            required_scopes: Some(vec!["phone".to_string()]),
            allowed_clients: None,
        },
        ClaimMapping {
            claim: "address".to_string(),
            source: ClaimSource::CanonicalUserField {
                field: CanonicalUserField::Address,
            },
            include_in_access_token: false,
            include_in_id_token: true,
            include_in_userinfo: true,
            first_party_only: false,
            required_scopes: Some(vec!["address".to_string()]),
            allowed_clients: None,
        },
    ]
}

/// Merges defaults and overrides using the layered fallback model.
pub fn resolve_claims_for_target(
    target: ClaimTarget,
    overrides: &[ClaimMapping],
    ctx: &ClaimEvaluationContext<'_>,
) -> BTreeMap<String, Value> {
    let mut by_claim: BTreeMap<String, Vec<ClaimMapping>> = BTreeMap::new();
    for mapping in default_claim_profile()
        .into_iter()
        .chain(overrides.iter().cloned())
    {
        if mapping.includes_target(target) {
            by_claim
                .entry(mapping.claim.clone())
                .or_default()
                .push(mapping);
        }
    }

    let mut out = BTreeMap::new();
    for (claim, mappings) in by_claim {
        let winner = mappings
            .iter()
            .rev()
            .find(|mapping| mapping.gates_pass(ctx.client, ctx.granted_scopes));
        if let Some(mapping) = winner {
            if let Some(value) = mapping.evaluate(ctx) {
                out.insert(claim, value);
            }
        }
    }
    out
}

/// Computes the set of emitted `(claim, target)` tuples for consent digests.
pub fn emitted_claim_targets(
    overrides: &[ClaimMapping],
    ctx: &ClaimEvaluationContext<'_>,
) -> BTreeSet<(String, ClaimTarget)> {
    let mut out = BTreeSet::new();
    for target in [
        ClaimTarget::AccessToken,
        ClaimTarget::IdToken,
        ClaimTarget::UserInfo,
    ] {
        for (claim, _) in resolve_claims_for_target(target, overrides, ctx) {
            out.insert((claim, target));
        }
    }
    out
}

/// Converts a resolved claim map into a top-level JSON object.
pub fn to_json_object(claims: BTreeMap<String, Value>) -> Map<String, Value> {
    claims.into_iter().collect()
}
