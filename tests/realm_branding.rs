//! Integration tests for HEA-98: realm branding + email template configuration.
//!
//! Covers:
//! - Per-realm `logo_url` and `primary_color` persistence in `RealmConfig`
//! - Per-realm stored email template upsert, retrieval, and deletion
//! - Placeholder substitution and locale fallback
//! - Validation failures for disallowed placeholders

mod common;

use hearth::identity::email::{
    validate_email_template, EmailTemplateBody, LocalizedEmailTemplate,
};
use hearth::identity::{CreateRealmRequest, RealmConfig, UpdateRealmRequest};

// ===== Branding field persistence =====

#[tokio::test]
async fn realm_branding_logo_and_primary_color_persist() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "brand-test-corp".to_string(),
            config: None,
        })
        .expect("create realm");

    let updated = identity
        .update_realm(
            realm.id(),
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    logo_url: Some("https://example.com/logo.png".to_string()),
                    primary_color: Some("#FF5500".to_string()),
                    ..RealmConfig::default()
                }),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("update realm");

    assert_eq!(
        updated.config().logo_url.as_deref(),
        Some("https://example.com/logo.png")
    );
    assert_eq!(
        updated.config().primary_color.as_deref(),
        Some("#FF5500")
    );

    // Reload from storage and verify persistence.
    let reloaded = identity
        .get_realm(realm.id())
        .expect("get realm")
        .expect("present");
    assert_eq!(
        reloaded.config().logo_url.as_deref(),
        Some("https://example.com/logo.png")
    );
    assert_eq!(
        reloaded.config().primary_color.as_deref(),
        Some("#FF5500")
    );
}

#[tokio::test]
async fn realm_branding_can_be_cleared() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "clear-brand-corp".to_string(),
            config: Some(RealmConfig {
                logo_url: Some("https://example.com/logo.png".to_string()),
                primary_color: Some("#FF5500".to_string()),
                ..RealmConfig::default()
            }),
        })
        .expect("create");

    let updated = identity
        .update_realm(
            realm.id(),
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    logo_url: None,
                    primary_color: None,
                    ..RealmConfig::default()
                }),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("update");

    assert!(updated.config().logo_url.is_none());
    assert!(updated.config().primary_color.is_none());
}

// ===== Stored email template lifecycle =====

#[tokio::test]
async fn email_template_upsert_and_retrieve() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "tmpl-upsert-corp".to_string(),
            config: None,
        })
        .expect("create");

    let mut templates = std::collections::HashMap::new();
    templates.insert(
        "verification".to_string(),
        LocalizedEmailTemplate {
            default: EmailTemplateBody {
                subject: Some("Verify your {{product_name}} account".to_string()),
                html_body: Some(
                    "<p>Click <a href='{{verification_url}}'>here</a>.</p>".to_string(),
                ),
                text_body: Some("Verify at {{verification_url}}".to_string()),
            },
            locales: Default::default(),
        },
    );

    let updated = identity
        .update_realm(
            realm.id(),
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    email_templates: templates,
                    ..RealmConfig::default()
                }),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("update");

    let tmpl = updated.config().email_templates.get("verification").expect("template present");
    assert_eq!(
        tmpl.default.subject.as_deref(),
        Some("Verify your {{product_name}} account")
    );

    // Reload and verify persistence.
    let reloaded = identity
        .get_realm(realm.id())
        .expect("get")
        .expect("present");
    let tmpl = reloaded
        .config()
        .email_templates
        .get("verification")
        .expect("stored");
    assert!(tmpl.default.html_body.is_some());
}

#[tokio::test]
async fn email_template_delete_removes_entry() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let mut templates = std::collections::HashMap::new();
    templates.insert(
        "password_reset".to_string(),
        LocalizedEmailTemplate {
            default: EmailTemplateBody {
                subject: Some("Reset your password".to_string()),
                ..Default::default()
            },
            ..Default::default()
        },
    );

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "tmpl-delete-corp".to_string(),
            config: Some(RealmConfig {
                email_templates: templates,
                ..RealmConfig::default()
            }),
        })
        .expect("create");

    assert!(realm.config().email_templates.contains_key("password_reset"));

    let mut new_templates = realm.config().email_templates.clone();
    new_templates.remove("password_reset");

    let updated = identity
        .update_realm(
            realm.id(),
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    email_templates: new_templates,
                    ..RealmConfig::default()
                }),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("update");

    assert!(!updated.config().email_templates.contains_key("password_reset"));
}

// ===== Locale fallback =====

#[tokio::test]
async fn locale_fallback_exact_match() {
    let mut tmpl = LocalizedEmailTemplate::default();
    tmpl.default.subject = Some("Hello".to_string());
    tmpl.locales.insert(
        "fr".to_string(),
        EmailTemplateBody {
            subject: Some("Bonjour".to_string()),
            ..Default::default()
        },
    );

    assert_eq!(tmpl.resolve(Some("fr")).subject.as_deref(), Some("Bonjour"));
    assert_eq!(tmpl.resolve(None).subject.as_deref(), Some("Hello"));
}

#[tokio::test]
async fn locale_fallback_language_prefix() {
    let mut tmpl = LocalizedEmailTemplate::default();
    tmpl.default.subject = Some("Default".to_string());
    tmpl.locales.insert(
        "pt".to_string(),
        EmailTemplateBody {
            subject: Some("Olá".to_string()),
            ..Default::default()
        },
    );

    // "pt-BR" → falls back to "pt" because no exact "pt-BR" entry.
    assert_eq!(
        tmpl.resolve(Some("pt-BR")).subject.as_deref(),
        Some("Olá")
    );
    // Unknown locale → falls back to default.
    assert_eq!(
        tmpl.resolve(Some("de")).subject.as_deref(),
        Some("Default")
    );
}

// ===== Placeholder validation =====

#[test]
fn validate_rejects_disallowed_placeholder_in_verification() {
    let result = validate_email_template("verification", "Click {{reset_url}} to verify.");
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("disallowed"), "got: {msg}");
    assert!(msg.contains("reset_url"), "got: {msg}");
}

#[test]
fn validate_accepts_allowed_placeholders() {
    assert!(
        validate_email_template(
            "verification",
            "Welcome to {{product_name}}! Click {{verification_url}}."
        )
        .is_ok()
    );
    assert!(
        validate_email_template(
            "password_reset",
            "Reset at {{reset_url}} — {{product_name}}"
        )
        .is_ok()
    );
    assert!(
        validate_email_template(
            "invitation",
            "{{org_name}} via {{inviter_email}} — {{accept_url}}"
        )
        .is_ok()
    );
}

#[test]
fn validate_rejects_unknown_kind() {
    let result = validate_email_template("unknown_kind", "anything");
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("unknown email template kind"), "got: {msg}");
}

#[test]
fn validate_rejects_cross_kind_contamination() {
    // verification_url must not appear in password_reset templates.
    let result = validate_email_template("password_reset", "Link: {{verification_url}}");
    assert!(result.is_err());
}

#[test]
fn validate_detects_unclosed_braces() {
    let result = validate_email_template("verification", "{{unclosed_brace");
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("unclosed"), "got: {msg}");
}

#[test]
fn validate_empty_body_is_ok() {
    assert!(validate_email_template("verification", "").is_ok());
    assert!(validate_email_template("password_reset", "Plain text without placeholders").is_ok());
}

// ===== Placeholder substitution via EmailService =====

#[test]
fn render_stored_template_substitutes_all_vars() {
    use hearth::identity::email::render_email_template;

    let result = render_email_template(
        "Hello from {{product_name}}! Verify at {{verification_url}}.",
        &[
            ("product_name", "Hearth"),
            ("verification_url", "https://example.com/verify?t=abc"),
        ],
    );
    assert_eq!(
        result,
        "Hello from Hearth! Verify at https://example.com/verify?t=abc."
    );
}

#[test]
fn render_stored_template_leaves_unknown_tokens_unchanged() {
    use hearth::identity::email::render_email_template;

    let result = render_email_template("{{unknown_token}}", &[("product_name", "Hearth")]);
    assert_eq!(result, "{{unknown_token}}");
}
