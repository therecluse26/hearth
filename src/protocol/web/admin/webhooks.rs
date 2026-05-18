//! Webhook management handlers for the admin UI.

use super::*;
use crate::core::WebhookId;
use crate::identity::CreateWebhookRequest;

// ---------------------------------------------------------------------------
// View models
// ---------------------------------------------------------------------------

/// A row in the webhooks list table.
pub struct WebhookRow {
    pub id: String,
    pub url: String,
    pub events: Vec<String>,
    pub enabled: bool,
    pub last_delivery: Option<DeliveryRow>,
}

/// Summary of the most recent delivery attempt for a webhook.
pub struct DeliveryRow {
    pub success: bool,
    pub status_code: String,
    pub timestamp_display: String,
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/webhooks/list.html")]
struct WebhookListTemplate {
    webhooks: Vec<WebhookRow>,
    realm_name: String,
    flash_message: Option<String>,
    /// Active workspace tab label (used by `_workspace_tabs.html` include).
    active_tab: &'static str,
    /// Cursor for the next page of results; `None` when on the last page.
    next_cursor: Option<String>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    theme_css: String,
    realm_theme_css: Option<String>,
}

/// Query params accepted by the webhook list page.
#[derive(Debug, serde::Deserialize)]
pub struct WebhookListParams {
    pub flash: Option<String>,
}

/// `GET /ui/admin/realms/{realm}/webhooks` — lists registered webhooks.
pub async fn admin_webhooks_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    Query(params): Query<WebhookListParams>,
) -> Response {
    let flash_message = params.flash.as_deref().map(|f| match f {
        "created" => "Webhook created.".to_string(),
        "deleted" => "Webhook deleted.".to_string(),
        other => other.to_string(),
    });

    let realm_name = target.0.name().to_string();
    let identity = state.identity.clone();
    let realm_id = target.id().clone();
    let rows = tokio::task::spawn_blocking(move || identity.list_webhooks(&realm_id))
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_default();

    let webhook_rows: Vec<WebhookRow> = rows
        .into_iter()
        .map(|wh| WebhookRow {
            id: wh.id().as_uuid().to_string(),
            url: wh.url.clone(),
            events: wh.events.clone(),
            enabled: wh.enabled,
            last_delivery: None,
        })
        .collect();

    render(&WebhookListTemplate {
        webhooks: webhook_rows,
        realm_name,
        flash_message,
        active_tab: "webhooks",
        next_cursor: None,
        chrome: true,
        active: "realm-workspace",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name_for(target.id()),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
    })
}

// ---------------------------------------------------------------------------
// Event type constants (shown as checkboxes in the create form)
// ---------------------------------------------------------------------------

pub struct WebhookEventType {
    pub value: String,
    pub description: Option<String>,
    /// Whether this event type is already in the form's subscription list.
    /// Precomputed so templates avoid runtime `contains` with borrowed args.
    pub is_subscribed: bool,
}

fn available_event_types(subscribed: &[String]) -> Vec<WebhookEventType> {
    [
        ("user.created", "User was created"),
        ("user.updated", "User profile was updated"),
        ("user.deleted", "User was deleted"),
        ("session.created", "New session was created"),
        ("session.revoked", "Session was revoked"),
        ("role.assigned", "Role was assigned to a user"),
        ("role.revoked", "Role was revoked from a user"),
        ("credential.changed", "User changed their password"),
    ]
    .into_iter()
    .map(|(value, desc)| WebhookEventType {
        is_subscribed: subscribed.iter().any(|s| s == value),
        value: value.to_string(),
        description: Some(desc.to_string()),
    })
    .collect()
}

// ---------------------------------------------------------------------------
// Create form
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/webhooks/new.html")]
#[allow(dead_code)]
struct WebhookNewTemplate {
    realm_name: String,
    form_url: String,
    form_secret: String,
    form_enabled: bool,
    subscribed_events: Vec<String>,
    available_event_types: Vec<WebhookEventType>,
    error: Option<String>,
    active_tab: &'static str,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    theme_css: String,
    realm_theme_css: Option<String>,
}

/// `GET /ui/admin/realms/{realm}/webhooks/new` — render create form.
pub async fn admin_webhook_create_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
) -> Response {
    render(&WebhookNewTemplate {
        realm_name: target.0.name().to_string(),
        form_url: String::new(),
        form_secret: String::new(),
        form_enabled: true,
        subscribed_events: Vec::new(),
        available_event_types: available_event_types(&[]),
        error: None,
        active_tab: "webhooks",
        chrome: true,
        active: "realm-workspace",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name_for(target.id()),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
    })
}

/// Form body for creating a webhook.
#[derive(Debug, Deserialize)]
pub struct CreateWebhookForm {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub secret: String,
    /// Checked event type checkboxes — may appear multiple times.
    #[serde(default)]
    pub events: Vec<String>,
    /// Checkbox: present means enabled.
    #[serde(default)]
    pub enabled: Option<String>,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/realms/{realm}/webhooks/new` — create a webhook.
pub async fn admin_webhook_create_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    FriendlyForm(form): FriendlyForm<CreateWebhookForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let realm_name = target.0.name().to_string();

    if form.url.trim().is_empty() {
        return render(&WebhookNewTemplate {
            realm_name,
            form_url: form.url.clone(),
            form_secret: form.secret.clone(),
            form_enabled: form.enabled.is_some(),
            subscribed_events: form.events.clone(),
            available_event_types: available_event_types(&form.events),
            error: Some("Endpoint URL is required.".to_string()),
            active_tab: "webhooks",
            chrome: true,
            active: "realm-workspace",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: false,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
            theme_css: state.theme_css.clone(),
            realm_theme_css: state.realm_theme_css(),
        });
    }

    let req = CreateWebhookRequest {
        url: form.url.trim().to_string(),
        secret: if form.secret.is_empty() {
            None
        } else {
            Some(form.secret.clone())
        },
        events: form.events.clone(),
        enabled: form.enabled.is_some(),
    };

    let identity = state.identity.clone();
    let realm_id = target.id().clone();
    let result = tokio::task::spawn_blocking(move || identity.create_webhook(&realm_id, &req))
        .await
        .unwrap_or_else(|e| {
            Err(crate::identity::IdentityError::Internal {
                reason: e.to_string(),
            })
        });

    match result {
        Ok(_wh) => axum::response::Redirect::to(&format!(
            "/ui/admin/realms/{realm_name}/webhooks?flash=created"
        ))
        .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "create_webhook failed");
            render(&WebhookNewTemplate {
                realm_name,
                form_url: form.url.clone(),
                form_secret: form.secret.clone(),
                form_enabled: form.enabled.is_some(),
                subscribed_events: form.events.clone(),
                available_event_types: available_event_types(&form.events),
                error: Some("Failed to save webhook. Please try again.".to_string()),
                active_tab: "webhooks",
                chrome: true,
                active: "realm-workspace",
                user_email: Some(session.user_email.clone()),
                is_admin: true,
                flash: None,
                csrf: session.csrf.clone(),
                narrow: false,
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
                theme_css: state.theme_css.clone(),
                realm_theme_css: state.realm_theme_css(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

/// `POST /ui/admin/realms/{realm}/webhooks/{id}/delete` — delete a webhook.
pub async fn admin_webhook_delete(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, webhook_id)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<DeleteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let Ok(uuid) = webhook_id.parse::<uuid::Uuid>() else {
        return super::handlers_common::not_found("Webhook not found");
    };
    let wid = WebhookId::new(uuid);

    let identity = state.identity.clone();
    let realm_id = target.id().clone();
    let result = tokio::task::spawn_blocking(move || identity.delete_webhook(&realm_id, &wid))
        .await
        .unwrap_or_else(|e| {
            Err(crate::identity::IdentityError::Internal {
                reason: e.to_string(),
            })
        });

    match result {
        Ok(()) => axum::response::Redirect::to(&format!(
            "/ui/admin/realms/{}/webhooks?flash=deleted",
            target.0.name()
        ))
        .into_response(),
        Err(crate::identity::IdentityError::WebhookNotFound) => {
            super::handlers_common::not_found("Webhook not found")
        }
        Err(e) => {
            tracing::warn!(error = %e, "delete_webhook failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Test (fire event to existing webhook)
// ---------------------------------------------------------------------------

/// `POST /ui/admin/realms/{realm}/webhooks/{id}/test` — fire a test event to an existing webhook.
pub async fn admin_webhook_test(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, webhook_id)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<DeleteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let Ok(uuid) = webhook_id.parse::<uuid::Uuid>() else {
        return super::handlers_common::not_found("Webhook not found");
    };
    let wid = WebhookId::new(uuid);

    let identity = state.identity.clone();
    let realm_id = target.id().clone();
    let wh = match tokio::task::spawn_blocking(move || identity.get_webhook(&realm_id, &wid))
        .await
        .ok()
        .and_then(|r| r.ok())
        .flatten()
    {
        Some(w) => w,
        None => return super::handlers_common::not_found("Webhook not found"),
    };

    fire_test_ping(wh.url.as_str(), wh.secret.as_deref()).await;

    axum::response::Redirect::to(&format!(
        "/ui/admin/realms/{}/webhooks?flash=test_sent",
        target.0.name()
    ))
    .into_response()
}

// ---------------------------------------------------------------------------
// Test-ping JSON endpoint (pre-save test from the create form)
// ---------------------------------------------------------------------------

/// Minimal JSON body for the pre-save test-ping endpoint.
#[derive(Debug, Deserialize)]
pub struct TestPingBody {
    pub url: String,
    #[serde(default)]
    pub secret: Option<String>,
}

/// `POST /ui/admin/realms/{realm}/webhooks/test-ping` — fires a synthetic ping
/// to an arbitrary URL (used by the new-webhook form before saving).
///
/// Returns `application/json` with `{"success": bool, "message": "..."}` so
/// Alpine.js can display the result inline.
pub async fn admin_webhook_test_ping(
    RequireAdmin(_session): RequireAdmin,
    AxumPath(_realm_name): AxumPath<String>,
    axum::Json(body): axum::Json<TestPingBody>,
) -> axum::response::Json<serde_json::Value> {
    let (success, message) = fire_test_ping_result(body.url.as_str(), body.secret.as_deref()).await;
    axum::response::Json(serde_json::json!({
        "success": success,
        "message": message,
    }))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async fn fire_test_ping(url: &str, secret: Option<&str>) {
    let _ = fire_test_ping_result(url, secret).await;
}

async fn fire_test_ping_result(url: &str, secret: Option<&str>) -> (bool, String) {
    let url = url.to_string();
    let secret = secret.map(ToString::to_string);
    tokio::task::spawn_blocking(move || {
        let payload = serde_json::json!({
            "event": "ping",
            "realm_id": null,
            "timestamp": crate::core::Timestamp::now().as_micros(),
        });
        let payload_bytes = match serde_json::to_vec(&payload) {
            Ok(b) => b,
            Err(e) => return (false, format!("Failed to build payload: {e}")),
        };
        let mut req = ureq::post(&url)
            .header("Content-Type", "application/json")
            .header("User-Agent", "Hearth-Webhook/1.0");

        // Sign with HMAC-SHA256 when a secret is configured.
        if let Some(s) = &secret {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            type HmacSha256 = Hmac<Sha256>;
            if let Ok(mut mac) = HmacSha256::new_from_slice(s.as_bytes()) {
                mac.update(&payload_bytes);
                let sig = mac.finalize().into_bytes();
                let sig_hex = hex::encode(sig);
                req = req.header("X-Hearth-Signature-256", &format!("sha256={sig_hex}"));
            }
        }

        match req.send(payload_bytes.as_slice()) {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    (true, format!("HTTP {}", status.as_u16()))
                } else {
                    (false, format!("HTTP {}", status.as_u16()))
                }
            }
            Err(e) => (false, format!("Connection error: {e}")),
        }
    })
    .await
    .unwrap_or((false, "Delivery task panicked".to_string()))
}
