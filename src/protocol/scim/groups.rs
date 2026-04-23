//! SCIM 2.0 `/Groups` handlers. Maps SCIM Groups onto Hearth
//! Organizations + `OrganizationMembership`.
//!
//! **Role:** all SCIM-managed members are provisioned with role
//! `Member`. SCIM has no concept of roles beyond membership, and Hearth
//! already prevents last-owner removal so there's no risk of locking
//! operators out of organizations they created out-of-band.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::audit::{AuditAction, CreateAuditEvent};
use crate::core::{OrganizationId, UserId};
use crate::identity::{
    CreateOrganizationRequest, Organization, OrganizationRole, UpdateOrganizationRequest,
};
use crate::protocol::http::{extract_admin_auth, AdminAuth, AppState};
use crate::protocol::scim::error::{from_identity_error, ScimError};
use crate::protocol::scim::filter::{self, FilterExpr};
use crate::protocol::scim::patch_apply::apply_group_patch;
use crate::protocol::scim::types::{
    ListResponse, Meta, PatchRequest, ScimGroup, ScimMember, GROUP_SCHEMA,
};

fn authenticate(headers: &HeaderMap, state: &AppState) -> Result<AdminAuth, ScimError> {
    extract_admin_auth(headers, state).map_err(|(status, body)| {
        let detail = body
            .0
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("authentication failed")
            .to_string();
        ScimError::new(status, detail)
    })
}

fn iso8601(micros: i64) -> String {
    let nanos = i128::from(micros) * 1_000;
    time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .ok()
        .and_then(|dt| {
            dt.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

/// Derives a URL-safe slug from an arbitrary display name. If the base
/// result collides with an existing org, the caller should retry with a
/// uuid-suffixed version.
fn slugify(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_hyphen = true;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            last_hyphen = false;
        } else if !last_hyphen {
            out.push('-');
            last_hyphen = true;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.len() < 3 {
        format!("{}-grp", trimmed)
    } else if trimmed.len() > 63 {
        trimmed[..63].to_string()
    } else {
        trimmed
    }
}

fn group_to_scim(
    org: &Organization,
    members: &[ScimMember],
    external_id: Option<String>,
) -> ScimGroup {
    let location = format!("/scim/v2/Groups/{}", org.id().as_uuid());
    let version = format!("W/\"{}\"", org.updated_at().as_micros());
    ScimGroup {
        schemas: vec![GROUP_SCHEMA.to_string()],
        id: Some(org.id().as_uuid().to_string()),
        external_id,
        display_name: org.name().to_string(),
        members: members.to_vec(),
        meta: Some(Meta {
            resource_type: "Group".to_string(),
            created: iso8601(org.created_at().as_micros()),
            last_modified: iso8601(org.updated_at().as_micros()),
            location,
            version,
        }),
    }
}

fn load_members(
    state: &AppState,
    realm_id: &crate::core::RealmId,
    org_id: &OrganizationId,
) -> Vec<ScimMember> {
    match state.identity.list_members(realm_id, org_id, None, 1000) {
        Ok(p) => p
            .items
            .iter()
            .map(|m| ScimMember {
                value: m.user_id().as_uuid().to_string(),
                display: None,
                r#type: Some("User".to_string()),
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn audit(
    state: &AppState,
    auth: &AdminAuth,
    action: AuditAction,
    org_id: &OrganizationId,
    external_id: Option<&str>,
) {
    let _ = state.audit.append(&CreateAuditEvent {
        realm_id: auth.realm_id.clone(),
        actor: auth.user_id.as_uuid().to_string(),
        action,
        resource_type: "organization".to_string(),
        resource_id: org_id.as_uuid().to_string(),
        metadata: Some(json!({"via": "scim", "external_id": external_id})),
    });
}

fn reconcile_members(
    state: &AppState,
    auth: &AdminAuth,
    org_id: &OrganizationId,
    desired: &[ScimMember],
) -> Result<(), ScimError> {
    let current = state
        .identity
        .list_members(&auth.realm_id, org_id, None, 1000)
        .map_err(|e| from_identity_error(&e))?;
    let current_ids: std::collections::HashSet<UserId> =
        current.items.iter().map(|m| m.user_id().clone()).collect();

    let desired_ids: std::collections::HashSet<UserId> = desired
        .iter()
        .filter_map(|m| uuid::Uuid::parse_str(&m.value).ok().map(UserId::new))
        .collect();

    // Add missing.
    for id in desired_ids.difference(&current_ids) {
        if let Err(e) =
            state
                .identity
                .add_member(&auth.realm_id, org_id, id, OrganizationRole::Member)
        {
            // AlreadyMember is benign here; surface anything else.
            if !matches!(e, crate::identity::IdentityError::AlreadyMember) {
                return Err(from_identity_error(&e));
            }
        }
    }

    // Remove stale (but skip if the member is an Owner — last-owner
    // protection in the engine would fail anyway).
    for id in current_ids.difference(&desired_ids) {
        // Skip non-Member roles so SCIM reconciliation doesn't demote
        // operator-assigned Owners/Admins who were created out-of-band.
        let role = current
            .items
            .iter()
            .find(|m| m.user_id() == id)
            .map(crate::identity::OrganizationMembership::role);
        if role == Some(OrganizationRole::Owner) || role == Some(OrganizationRole::Admin) {
            continue;
        }
        let _ = state.identity.remove_member(&auth.realm_id, org_id, id);
    }
    Ok(())
}

// ================== Handlers ==================

/// `POST /scim/v2/Groups`
pub async fn create_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ScimGroup>,
) -> Response {
    let auth = match authenticate(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    if let Some(ext) = &body.external_id {
        if let Ok(Some(_)) = state
            .identity
            .find_group_by_scim_external_id(&auth.realm_id, ext)
        {
            return ScimError::uniqueness("externalId already provisioned").into_response();
        }
    }

    let mut slug = slugify(&body.display_name);
    // Retry with uuid suffix on conflict (up to 3 tries).
    for _ in 0..3 {
        let exists = state
            .identity
            .get_organization_by_slug(&auth.realm_id, &slug)
            .map(|o| o.is_some())
            .unwrap_or(false);
        if !exists {
            break;
        }
        let tail = uuid::Uuid::new_v4().to_string();
        slug = format!("{}-{}", slug, &tail[..6]);
    }

    let req = CreateOrganizationRequest {
        name: body.display_name.clone(),
        slug,
        description: None,
        config: None,
    };
    let org = match state.identity.create_organization(&auth.realm_id, &req) {
        Ok(o) => o,
        Err(e) => return from_identity_error(&e).into_response(),
    };

    if let Some(ext) = &body.external_id {
        if let Err(e) = state
            .identity
            .set_scim_group_external_id(&auth.realm_id, org.id(), ext)
        {
            return from_identity_error(&e).into_response();
        }
    }

    if let Err(e) = reconcile_members(&state, &auth, org.id(), &body.members) {
        return e.into_response();
    }

    audit(
        &state,
        &auth,
        AuditAction::ScimGroupCreated,
        org.id(),
        body.external_id.as_deref(),
    );

    let members = load_members(&state, &auth.realm_id, org.id());
    let scim = group_to_scim(&org, &members, body.external_id.clone());
    let mut resp = (StatusCode::CREATED, Json(scim.clone())).into_response();
    resp.headers_mut().insert(
        axum::http::header::LOCATION,
        HeaderValue::from_str(&format!("/scim/v2/Groups/{}", org.id().as_uuid()))
            .unwrap_or(HeaderValue::from_static("/scim/v2/Groups")),
    );
    if let Some(m) = &scim.meta {
        if let Ok(v) = HeaderValue::from_str(&m.version) {
            resp.headers_mut().insert(axum::http::header::ETAG, v);
        }
    }
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/scim+json"),
    );
    resp
}

/// `GET /scim/v2/Groups/{id}`
pub async fn get_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let auth = match authenticate(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return ScimError::not_found("group not found").into_response();
    };
    let org_id = OrganizationId::new(uuid);
    match state.identity.get_organization(&auth.realm_id, &org_id) {
        Ok(Some(org)) => {
            let ext = state
                .identity
                .get_scim_group_external_id(&auth.realm_id, &org_id)
                .ok()
                .flatten();
            let members = load_members(&state, &auth.realm_id, &org_id);
            Json(group_to_scim(&org, &members, ext)).into_response()
        }
        Ok(None) => ScimError::not_found("group not found").into_response(),
        Err(e) => from_identity_error(&e).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default, rename = "startIndex")]
    pub start_index: Option<usize>,
    #[serde(default)]
    pub count: Option<usize>,
}

/// `GET /scim/v2/Groups`
pub async fn list_groups(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Response {
    let auth = match authenticate(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let filter_expr: Option<FilterExpr> = match q.filter.as_deref() {
        Some(f) => match filter::parse(f) {
            Ok(e) => Some(e),
            Err(e) => return e.into_response(),
        },
        None => None,
    };

    let page = match state
        .identity
        .list_organizations(&auth.realm_id, None, 1000)
    {
        Ok(p) => p,
        Err(e) => return from_identity_error(&e).into_response(),
    };
    let mut resources: Vec<ScimGroup> = Vec::with_capacity(page.items.len());
    for org in &page.items {
        let ext = state
            .identity
            .get_scim_group_external_id(&auth.realm_id, org.id())
            .ok()
            .flatten();
        let members = load_members(&state, &auth.realm_id, org.id());
        let scim = group_to_scim(org, &members, ext);
        if filter_expr
            .as_ref()
            .map_or(true, |e| filter::matches_group(e, &scim))
        {
            resources.push(scim);
        }
    }
    let total = resources.len();
    let start = q.start_index.unwrap_or(1).max(1);
    let count = q.count.unwrap_or(100).min(200);
    let start_idx0 = start.saturating_sub(1);
    let slice: Vec<ScimGroup> = resources.into_iter().skip(start_idx0).take(count).collect();
    Json(ListResponse::new(total, start, slice)).into_response()
}

/// `PUT /scim/v2/Groups/{id}`
pub async fn replace_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ScimGroup>,
) -> Response {
    let auth = match authenticate(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return ScimError::not_found("group not found").into_response();
    };
    let org_id = OrganizationId::new(uuid);

    let existing = match state.identity.get_organization(&auth.realm_id, &org_id) {
        Ok(Some(o)) => o,
        Ok(None) => return ScimError::not_found("group not found").into_response(),
        Err(e) => return from_identity_error(&e).into_response(),
    };

    let req = UpdateOrganizationRequest {
        name: Some(body.display_name.clone()),
        description: None,
        status: None,
        config: None,
    };
    if let Err(e) = state
        .identity
        .update_organization(&auth.realm_id, &org_id, &req)
    {
        return from_identity_error(&e).into_response();
    }

    match body.external_id.as_deref() {
        Some(ext) if !ext.is_empty() => {
            if let Err(e) = state
                .identity
                .set_scim_group_external_id(&auth.realm_id, &org_id, ext)
            {
                return from_identity_error(&e).into_response();
            }
        }
        _ => {
            let _ = state
                .identity
                .clear_scim_group_external_id(&auth.realm_id, &org_id);
        }
    }

    if let Err(e) = reconcile_members(&state, &auth, &org_id, &body.members) {
        return e.into_response();
    }

    audit(
        &state,
        &auth,
        AuditAction::ScimGroupUpdated,
        &org_id,
        body.external_id.as_deref(),
    );

    let refreshed = state
        .identity
        .get_organization(&auth.realm_id, &org_id)
        .ok()
        .flatten()
        .unwrap_or(existing);
    let ext = state
        .identity
        .get_scim_group_external_id(&auth.realm_id, &org_id)
        .ok()
        .flatten();
    let members = load_members(&state, &auth.realm_id, &org_id);
    Json(group_to_scim(&refreshed, &members, ext)).into_response()
}

/// `PATCH /scim/v2/Groups/{id}`
pub async fn patch_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<PatchRequest>,
) -> Response {
    let auth = match authenticate(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return ScimError::not_found("group not found").into_response();
    };
    let org_id = OrganizationId::new(uuid);

    let existing = match state.identity.get_organization(&auth.realm_id, &org_id) {
        Ok(Some(o)) => o,
        Ok(None) => return ScimError::not_found("group not found").into_response(),
        Err(e) => return from_identity_error(&e).into_response(),
    };
    let current_ext = state
        .identity
        .get_scim_group_external_id(&auth.realm_id, &org_id)
        .ok()
        .flatten();
    let members = load_members(&state, &auth.realm_id, &org_id);
    let mut scim = group_to_scim(&existing, &members, current_ext.clone());
    if let Err(e) = apply_group_patch(&mut scim, &body.operations) {
        return e.into_response();
    }

    // Apply displayName change.
    if scim.display_name != existing.name() {
        let req = UpdateOrganizationRequest {
            name: Some(scim.display_name.clone()),
            description: None,
            status: None,
            config: None,
        };
        if let Err(e) = state
            .identity
            .update_organization(&auth.realm_id, &org_id, &req)
        {
            return from_identity_error(&e).into_response();
        }
    }

    // Sync externalId.
    if scim.external_id != current_ext {
        match scim.external_id.as_deref() {
            Some(ext) if !ext.is_empty() => {
                if let Err(e) =
                    state
                        .identity
                        .set_scim_group_external_id(&auth.realm_id, &org_id, ext)
                {
                    return from_identity_error(&e).into_response();
                }
            }
            _ => {
                let _ = state
                    .identity
                    .clear_scim_group_external_id(&auth.realm_id, &org_id);
            }
        }
    }

    // Reconcile membership.
    if let Err(e) = reconcile_members(&state, &auth, &org_id, &scim.members) {
        return e.into_response();
    }

    audit(
        &state,
        &auth,
        AuditAction::ScimGroupUpdated,
        &org_id,
        scim.external_id.as_deref(),
    );

    let refreshed = state
        .identity
        .get_organization(&auth.realm_id, &org_id)
        .ok()
        .flatten()
        .unwrap_or(existing);
    let ext = state
        .identity
        .get_scim_group_external_id(&auth.realm_id, &org_id)
        .ok()
        .flatten();
    let members = load_members(&state, &auth.realm_id, &org_id);
    Json(group_to_scim(&refreshed, &members, ext)).into_response()
}

/// `DELETE /scim/v2/Groups/{id}`
pub async fn delete_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let auth = match authenticate(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return ScimError::not_found("group not found").into_response();
    };
    let org_id = OrganizationId::new(uuid);

    match state.identity.delete_organization(&auth.realm_id, &org_id) {
        Ok(()) => {
            audit(&state, &auth, AuditAction::ScimGroupDeleted, &org_id, None);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => from_identity_error(&e).into_response(),
    }
}
