//! Per-realm stored email template overrides with localization support.
//!
//! Operators upload custom templates via the admin API. Each template is
//! stored as a [`LocalizedEmailTemplate`] keyed by template kind (e.g.
//! `"verification"`, `"password_reset"`). Locale variants fall back to the
//! `default` body when no matching locale exists.
//!
//! Body strings use simple `{{placeholder}}` tokens (not Tera/Askama
//! syntax). Allowed placeholders are validated by the
//! [`placeholder`](super::placeholder) module before storage.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// The body content for a single email (one locale, one template kind).
///
/// All fields are optional — a custom template need only override the
/// fields it cares about. `None` fields inherit from the compiled default.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailTemplateBody {
    /// Custom subject line. May contain `{{product_name}}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// HTML body with `{{placeholder}}` tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub html_body: Option<String>,
    /// Plain-text body with `{{placeholder}}` tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text_body: Option<String>,
}

impl EmailTemplateBody {
    /// Returns `true` if all fields are `None`.
    pub fn is_empty(&self) -> bool {
        self.subject.is_none() && self.html_body.is_none() && self.text_body.is_none()
    }
}

/// A template override for one email kind, with optional locale variants.
///
/// `default` is used when no matching locale is found. `locales` maps
/// BCP-47 locale tags (e.g. `"fr"`, `"de"`, `"pt-BR"`) to locale-specific
/// body overrides.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalizedEmailTemplate {
    /// Locale-neutral default body. Used when no locale match is found.
    #[serde(default)]
    pub default: EmailTemplateBody,
    /// Locale-specific overrides keyed by BCP-47 tag.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub locales: HashMap<String, EmailTemplateBody>,
}

impl LocalizedEmailTemplate {
    /// Resolves the best matching body for `locale`.
    ///
    /// Resolution order:
    /// 1. Exact match on `locale` (e.g. `"pt-BR"`).
    /// 2. Language prefix match (e.g. `"pt"` for `"pt-BR"`).
    /// 3. `default`.
    pub fn resolve(&self, locale: Option<&str>) -> &EmailTemplateBody {
        if let Some(tag) = locale {
            if let Some(body) = self.locales.get(tag) {
                return body;
            }
            // Language-prefix fallback: "pt" for "pt-BR"
            if let Some(lang) = tag.split('-').next() {
                if let Some(body) = self.locales.get(lang) {
                    return body;
                }
            }
        }
        &self.default
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_body(subject: &str) -> EmailTemplateBody {
        EmailTemplateBody {
            subject: Some(subject.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn resolve_exact_locale() {
        let mut t = LocalizedEmailTemplate::default();
        t.locales.insert("fr".to_string(), make_body("Bonjour"));
        assert_eq!(t.resolve(Some("fr")).subject.as_deref(), Some("Bonjour"));
    }

    #[test]
    fn resolve_language_prefix_fallback() {
        let mut t = LocalizedEmailTemplate::default();
        t.locales.insert("pt".to_string(), make_body("Olá"));
        assert_eq!(t.resolve(Some("pt-BR")).subject.as_deref(), Some("Olá"));
    }

    #[test]
    fn resolve_falls_back_to_default() {
        let mut t = LocalizedEmailTemplate::default();
        t.default = make_body("Hello");
        assert_eq!(t.resolve(None).subject.as_deref(), Some("Hello"));
        assert_eq!(t.resolve(Some("de")).subject.as_deref(), Some("Hello"));
    }

    #[test]
    fn resolve_exact_beats_prefix() {
        let mut t = LocalizedEmailTemplate::default();
        t.locales.insert("pt".to_string(), make_body("Generic PT"));
        t.locales.insert("pt-BR".to_string(), make_body("BR Portuguese"));
        assert_eq!(
            t.resolve(Some("pt-BR")).subject.as_deref(),
            Some("BR Portuguese")
        );
    }

    #[test]
    fn is_empty_true_for_default() {
        assert!(EmailTemplateBody::default().is_empty());
    }

    #[test]
    fn is_empty_false_when_subject_set() {
        assert!(!make_body("hi").is_empty());
    }

    #[test]
    fn serde_round_trip() {
        let mut t = LocalizedEmailTemplate::default();
        t.default.subject = Some("Default".to_string());
        t.locales
            .insert("fr".to_string(), make_body("Bonjour en français"));

        let json = serde_json::to_string(&t).expect("serialize");
        let back: LocalizedEmailTemplate = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(t, back);
    }
}
