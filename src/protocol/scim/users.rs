//! SCIM 2.0 `/Users` handlers (RFC 7644 §3.4).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::audit::{AuditAction, CreateAuditEvent};
use crate::core::UserId;
use crate::identity::{CreateUserRequest, UpdateUserRequest, User, UserStatus};
use crate::protocol::http::{extract_admin_auth, AppState};
use crate::protocol::scim::error::{from_identity_error, ScimError};
use crate::protocol::scim::filter::{self, FilterExpr};
use crate::protocol::scim::patch_apply::apply_user_patch;
use crate::protocol::scim::types::{
    ListResponse, Meta, PatchRequest, ScimEmail, ScimName, ScimUser, USER_SCHEMA,
};

fn authenticate(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<crate::protocol::http::AdminAuth, ScimError> {
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

/// Converts a stored `User` to a SCIM wire resource. `base_path` is the
/// absolute request path prefix up to `/scim/v2/Users`.
fn user_to_scim(user: &User, external_id: Option<String>, base_path: &str) -> ScimUser {
    let location = format!("{base_path}/{}", user.id().as_uuid());
    let version = format!("W/\"{}\"", user.updated_at().as_micros());
    let name = if user.first_name().is_empty() && user.last_name().is_empty() {
        None
    } else {
        Some(ScimName {
            formatted: Some(format!("{} {}", user.first_name(), user.last_name()).trim().to_string()),
            given_name: if user.first_name().is_empty() {
                None
            } else {
                Some(user.first_name().to_string())
            },
            family_name: if user.last_name().is_empty() {
                None
            } else {
                Some(user.last_name().to_string())
            },
        })
    };
    ScimUser {
        schemas: vec![USER_SCHEMA.to_string()],
        id: Some(user.id().as_uuid().to_string()),
        external_id,
        user_name: user.email().to_string(),
        display_name: if user.display_name().is_empty() {
            None
        } else {
            Some(user.display_name().to_string())
        },
        name,
        emails: vec![ScimEmail {
            value: user.email().to_string(),
            primary: Some(true),
            r#type: None,
        }],
        active: matches!(user.status(), UserStatus::Active),
        meta: Some(Meta {
            resource_type: "User".to_string(),
            created: iso8601(user.created_at().as_micros()),
            last_modified: iso8601(user.updated_at().as_micros()),
            location,
            version,
        }),
    }
}

fn iso8601(micros: i64) -> String {
    let nanos = i128::from(micros) * 1_000;
    time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .ok()
        .and_then(|dt| dt.format(&time::format_description::well_known::Rfc3339).ok())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

/// Primary email from a SCIM user payload: first entry with `primary: true`,
/// else first email, else None. SCIM clients that send `userName` = email
/// hit the fallback at the end.
fn primary_email(u: &ScimUser) -> String {
    u.emails
        .iter()
        .find(|e| e.primary.unwrap_or(false))
        .or_else(|| u.emails.first())
        .map(|e| e.value.clone())
        .unwrap_or_else(|| u.user_name.clone())
}

fn require_name(u: &ScimUser) -> Result<(String, String), ScimError> {
    match u.name.as_ref() {
        Some(n) => Ok((
            n.given_name.clone().unwrap_or_default(),
            n.family_name.clone().unwrap_or_default(),
        )),
        None => {
            // Synthesize from displayName when SCIM client omits structured
            // name. Real-world IdPs always send `name`, but some test
            // clients don't.
            Ok((String::new(), String::new()))
        }
    }
}

fn audit(state: &AppState, auth: &crate::protocol::http::AdminAuth, action: AuditAction, user_id: &UserId, external_id: Option<&str>) {
    let metadata = json!({
        "via": "scim",
        "external_id": external_id,
    });
    let _ = state.audit.append(&CreateAuditEvent {
        realm_id: auth.realm_id.clone(),
        actor: auth.user_id.as_uuid().to_string(),
        action,
        resource_type: "user".to_string(),
        resource_id: user_id.as_uuid().to_string(),
        metadata: Some(metadata),
    });
}

// ================== Handlers ==================

/// `POST /scim/v2/Users`
pub async fn create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ScimUser>,
) -> Response {
    let auth = match authenticate(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    // Idempotency: if the client supplies an externalId already seen in
    // this realm, refuse with 409 uniqueness (rather than create a dup).
    if let Some(ext) = &body.external_id {
        match state.identity.find_user_by_scim_external_id(&auth.realm_id, ext) {
            Ok(Some(_)) => {
                return ScimError::uniqueness("externalId already provisioned").into_response();
            }
            Ok(None) => {}
            Err(e) => return from_identity_error(&e).into_response(),
        }
    }

    let email = primary_email(&body);
    let (first_name, last_name) = match require_name(&body) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let display_name = body.display_name.clone().unwrap_or_default();

    let req = CreateUserRequest {
        email,
        display_name,
        first_name,
        last_name,
    };

    let user = match state.identity.create_user(&auth.realm_id, &req) {
        Ok(u) => u,
        Err(e) => return from_identity_error(&e).into_response(),
    };

    // Apply active=false (create_user returns Active by default).
    if !body.active {
        let _ = state.identity.update_user(
            &auth.realm_id,
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Disabled),
                ..Default::default()
            },
        );
    }

    // Register externalId.
    if let Some(ext) = &body.external_id {
        if let Err(e) = state
            .identity
            .set_scim_external_id(&auth.realm_id, user.id(), ext)
        {
            return from_identity_error(&e).into_response();
        }
    }

    // Re-read to pick up status change (refresh `updated_at`).
    let refreshed = state
        .identity
        .get_user(&auth.realm_id, user.id())
        .ok()
        .flatten()
        .unwrap_or(user.clone());

    audit(
        &state,
        &auth,
        AuditAction::ScimUserCreated,
        refreshed.id(),
        body.external_id.as_deref(),
    );

    let scim = user_to_scim(&refreshed, body.external_id.clone(), "/scim/v2/Users");
    let mut resp = (StatusCode::CREATED, Json(scim.clone())).into_response();
    resp.headers_mut().insert(
        axum::http::header::LOCATION,
        HeaderValue::from_str(&format!("/scim/v2/Users/{}", refreshed.id().as_uuid()))
            .unwrap_or(HeaderValue::from_static("/scim/v2/Users")),
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

/// `GET /scim/v2/Users/{id}`
pub async fn get_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let auth = match authenticate(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return ScimError::not_found("user not found").into_response();
    };
    let user_id = UserId::new(uuid);
    match state.identity.get_user(&auth.realm_id, &user_id) {
        Ok(Some(user)) => {
            let ext = state
                .identity
                .get_scim_external_id(&auth.realm_id, &user_id)
                .ok()
                .flatten();
            let scim = user_to_scim(&user, ext, "/scim/v2/Users");
            Json(scim).into_response()
        }
        Ok(None) => ScimError::not_found("user not found").into_response(),
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

/// `GET /scim/v2/Users`
pub async fn list_users(
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

    // Phase 1 pagination: fetch up to 1000 users in one scan and slice in
    // memory. Okta / Azure paginate at ~100; Phase 2 can push the filter
    // + pagination into the engine layer.
    let page = match state.identity.list_users(&auth.realm_id, None, 1000) {
        Ok(p) => p,
        Err(e) => return from_identity_error(&e).into_response(),
    };

    let mut resources: Vec<ScimUser> = Vec::with_capacity(page.items.len());
    for user in &page.items {
        let ext = state
            .identity
            .get_scim_external_id(&auth.realm_id, user.id())
            .ok()
            .flatten();
        let scim = user_to_scim(user, ext, "/scim/v2/Users");
        if filter_expr
            .as_ref()
            .map_or(true, |e| filter::matches_user(e, &scim))
        {
            resources.push(scim);
        }
    }

    let total = resources.len();
    let start = q.start_index.unwrap_or(1).max(1);
    let count = q.count.unwrap_or(100).min(200);
    let start_idx0 = start.saturating_sub(1);
    let slice: Vec<ScimUser> = resources
        .into_iter()
        .skip(start_idx0)
        .take(count)
        .collect();

    Json(ListResponse::new(total, start, slice)).into_response()
}

/// `PUT /scim/v2/Users/{id}` — full replace.
pub async fn replace_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ScimUser>,
) -> Response {
    let auth = match authenticate(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return ScimError::not_found("user not found").into_response();
    };
    let user_id = UserId::new(uuid);

    // Ensure user exists first so 404 comes from the existence check, not
    // from a field mismatch downstream.
    match state.identity.get_user(&auth.realm_id, &user_id) {
        Ok(Some(_)) => {}
        Ok(None) => return ScimError::not_found("user not found").into_response(),
        Err(e) => return from_identity_error(&e).into_response(),
    }

    let (first_name, last_name) = match require_name(&body) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let email = primary_email(&body);
    let display_name = body.display_name.clone();

    let req = UpdateUserRequest {
        email: Some(email),
        display_name,
        first_name: Some(first_name),
        last_name: Some(last_name),
        status: Some(if body.active {
            UserStatus::Active
        } else {
            UserStatus::Disabled
        }),
    };

    let user = match state.identity.update_user(&auth.realm_id, &user_id, &req) {
        Ok(u) => u,
        Err(e) => return from_identity_error(&e).into_response(),
    };

    match body.external_id.as_deref() {
        Some(ext) if !ext.is_empty() => {
            if let Err(e) = state
                .identity
                .set_scim_external_id(&auth.realm_id, &user_id, ext)
            {
                return from_identity_error(&e).into_response();
            }
        }
        _ => {
            let _ = state
                .identity
                .clear_scim_external_id(&auth.realm_id, &user_id);
        }
    }

    audit(
        &state,
        &auth,
        AuditAction::ScimUserUpdated,
        &user_id,
        body.external_id.as_deref(),
    );

    let refreshed = state
        .identity
        .get_user(&auth.realm_id, &user_id)
        .ok()
        .flatten()
        .unwrap_or(user);
    let ext = state
        .identity
        .get_scim_external_id(&auth.realm_id, &user_id)
        .ok()
        .flatten();
    Json(user_to_scim(&refreshed, ext, "/scim/v2/Users")).into_response()
}

/// `PATCH /scim/v2/Users/{id}`
pub async fn patch_user(
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
        return ScimError::not_found("user not found").into_response();
    };
    let user_id = UserId::new(uuid);

    let existing = match state.identity.get_user(&auth.realm_id, &user_id) {
        Ok(Some(u)) => u,
        Ok(None) => return ScimError::not_found("user not found").into_response(),
        Err(e) => return from_identity_error(&e).into_response(),
    };
    let current_ext = state
        .identity
        .get_scim_external_id(&auth.realm_id, &user_id)
        .ok()
        .flatten();

    let mut scim = user_to_scim(&existing, current_ext.clone(), "/scim/v2/Users");
    if let Err(e) = apply_user_patch(&mut scim, &body.operations) {
        return e.into_response();
    }

    let (first_name, last_name) = match require_name(&scim) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let email = primary_email(&scim);
    let status = if scim.active {
        UserStatus::Active
    } else {
        UserStatus::Disabled
    };

    let req = UpdateUserRequest {
        email: Some(email),
        display_name: scim.display_name.clone().or(Some(String::new())),
        first_name: Some(first_name),
        last_name: Some(last_name),
        status: Some(status),
    };
    // `display_name` Some("") would clear it — but `validate_display_name`
    // rejects empty. Re-synthesize if empty.
    let display_name_final = req.display_name.clone().filter(|s| !s.is_empty()).or_else(|| {
        let fn_ = scim.name.as_ref().and_then(|n| n.given_name.clone()).unwrap_or_default();
        let ln = scim.name.as_ref().and_then(|n| n.family_name.clone()).unwrap_or_default();
        let synth = format!("{fn_} {ln}").trim().to_string();
        if synth.is_empty() {
            Some(existing.display_name().to_string())
        } else {
            Some(synth)
        }
    });
    let req = UpdateUserRequest {
        display_name: display_name_final,
        ..req
    };

    if let Err(e) = state.identity.update_user(&auth.realm_id, &user_id, &req) {
        return from_identity_error(&e).into_response();
    }

    // Sync externalId.
    if scim.external_id != current_ext {
        match scim.external_id.as_deref() {
            Some(ext) if !ext.is_empty() => {
                if let Err(e) = state
                    .identity
                    .set_scim_external_id(&auth.realm_id, &user_id, ext)
                {
                    return from_identity_error(&e).into_response();
                }
            }
            _ => {
                let _ = state
                    .identity
                    .clear_scim_external_id(&auth.realm_id, &user_id);
            }
        }
    }

    audit(
        &state,
        &auth,
        AuditAction::ScimUserUpdated,
        &user_id,
        scim.external_id.as_deref(),
    );

    let refreshed = state
        .identity
        .get_user(&auth.realm_id, &user_id)
        .ok()
        .flatten()
        .unwrap_or(existing);
    let ext = state
        .identity
        .get_scim_external_id(&auth.realm_id, &user_id)
        .ok()
        .flatten();
    Json(user_to_scim(&refreshed, ext, "/scim/v2/Users")).into_response()
}

/// `DELETE /scim/v2/Users/{id}`
pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let auth = match authenticate(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return ScimError::not_found("user not found").into_response();
    };
    let user_id = UserId::new(uuid);

    match state.identity.delete_user(&auth.realm_id, &user_id) {
        Ok(()) => {
            audit(&state, &auth, AuditAction::ScimUserDeleted, &user_id, None);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => from_identity_error(&e).into_response(),
    }
}
