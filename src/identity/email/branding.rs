//! Per-tenant email branding configuration.
//!
//! Each tenant can override the accent color, support email, and footer
//! text. The [`EmailBranding::merge`] function produces a resolved
//! branding by overlaying tenant overrides on global defaults.
//!
//! `product_name` and `logo_url` are **global** branding concerns
//! (shared by the web UI and emails) and live in
//! [`BrandingConfig`](crate::config::BrandingConfig).

use serde::{Deserialize, Serialize};

/// Per-tenant email branding configuration.
///
/// All fields are optional. When `None`, [`ResolvedBranding`] uses
/// built-in defaults (accent color `#E85D04`, etc.).
///
/// `product_name` and `logo_url` are sourced from the global
/// [`BrandingConfig`](crate::config::BrandingConfig) and injected by
/// [`EmailService`](super::service::EmailService).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailBranding {
    /// Hex color code for accent elements. Defaults to `#E85D04`.
    pub accent_color: Option<String>,
    /// Support email address shown in the email footer.
    pub support_email: Option<String>,
    /// Additional text appended to the email footer.
    pub custom_footer_text: Option<String>,
}

impl EmailBranding {
    /// Merges global defaults with tenant overrides.
    ///
    /// Tenant `Some` fields take precedence over global `Some` fields.
    /// Returns a new `EmailBranding` with all overrides applied.
    pub fn merge(global: &Self, tenant: &Self) -> Self {
        Self {
            accent_color: tenant
                .accent_color
                .clone()
                .or_else(|| global.accent_color.clone()),
            support_email: tenant
                .support_email
                .clone()
                .or_else(|| global.support_email.clone()),
            custom_footer_text: tenant
                .custom_footer_text
                .clone()
                .or_else(|| global.custom_footer_text.clone()),
        }
    }

    /// Returns the accent color, falling back to the default brand color.
    pub fn accent_color_or_default(&self) -> &str {
        self.accent_color.as_deref().unwrap_or(DEFAULT_ACCENT_COLOR)
    }
}

/// Default accent color (warm orange).
const DEFAULT_ACCENT_COLOR: &str = "#E85D04";

/// Fully-resolved branding values with no `Option`s — ready for template
/// rendering. Constructed by [`EmailService::resolve_branding`].
#[derive(Clone, Debug)]
pub(crate) struct ResolvedBranding {
    /// Product name (always set).
    pub product_name: String,
    /// Optional logo URL (used with `<img src>`).
    pub logo_url: Option<String>,
    /// Raw SVG markup to inline directly in the email HTML.
    /// When set, `logo_url` should be `None` — templates use one or the other.
    pub logo_svg_inline: Option<String>,
    /// Accent color hex (always set).
    pub accent_color: String,
    /// Optional support email.
    pub support_email: Option<String>,
    /// Optional custom footer text.
    pub custom_footer_text: Option<String>,
}

impl ResolvedBranding {
    /// Converts raw [`EmailBranding`] into resolved fields with defaults.
    ///
    /// `product_name` and `logo_url` are supplied by the caller (sourced
    /// from global [`BrandingConfig`](crate::config::BrandingConfig))
    /// rather than from `EmailBranding`.
    ///
    /// This does **not** handle logo inlining or local-path cleanup —
    /// callers outside this module must use [`EmailService::resolve_branding`]
    /// instead to get a fully resolved result.
    pub(super) fn from_branding(
        branding: &EmailBranding,
        product_name: &str,
        logo_url: Option<&str>,
    ) -> Self {
        Self {
            product_name: product_name.to_string(),
            logo_url: logo_url.map(str::to_string),
            logo_svg_inline: None,
            accent_color: branding.accent_color_or_default().to_string(),
            support_email: branding.support_email.clone(),
            custom_footer_text: branding.custom_footer_text.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_global_only() {
        let global = EmailBranding {
            accent_color: Some("#FF0000".to_string()),
            ..Default::default()
        };
        let tenant = EmailBranding::default();

        let merged = EmailBranding::merge(&global, &tenant);
        assert_eq!(merged.accent_color.as_deref(), Some("#FF0000"));
    }

    #[test]
    fn merge_tenant_overrides_global() {
        let global = EmailBranding {
            accent_color: Some("#111111".to_string()),
            support_email: Some("global@example.com".to_string()),
            ..Default::default()
        };
        let tenant = EmailBranding {
            accent_color: Some("#222222".to_string()),
            ..Default::default()
        };

        let merged = EmailBranding::merge(&global, &tenant);
        assert_eq!(merged.accent_color.as_deref(), Some("#222222"));
        // support_email falls through to global
        assert_eq!(merged.support_email.as_deref(), Some("global@example.com"));
    }

    #[test]
    fn merge_both_none_uses_defaults() {
        let merged = EmailBranding::merge(&EmailBranding::default(), &EmailBranding::default());
        assert_eq!(merged.accent_color_or_default(), "#E85D04");
    }

    #[test]
    fn accent_color_or_default_returns_brand_color() {
        let b = EmailBranding::default();
        assert_eq!(b.accent_color_or_default(), "#E85D04");
    }

    #[test]
    fn resolved_branding_from_defaults() {
        let b = EmailBranding::default();
        let resolved = ResolvedBranding::from_branding(&b, "Hearth", None);
        assert_eq!(resolved.product_name, "Hearth");
        assert_eq!(resolved.accent_color, "#E85D04");
        assert!(resolved.logo_url.is_none());
        assert!(resolved.logo_svg_inline.is_none());
        assert!(resolved.support_email.is_none());
    }

    #[test]
    fn resolved_branding_with_custom_values() {
        let b = EmailBranding {
            accent_color: Some("#ABC123".to_string()),
            support_email: Some("help@example.com".to_string()),
            custom_footer_text: Some("Custom footer".to_string()),
        };
        let resolved =
            ResolvedBranding::from_branding(&b, "Acme", Some("https://acme.com/logo.png"));
        assert_eq!(resolved.product_name, "Acme");
        assert_eq!(
            resolved.logo_url.as_deref(),
            Some("https://acme.com/logo.png")
        );
        assert_eq!(resolved.accent_color, "#ABC123");
        assert_eq!(resolved.support_email.as_deref(), Some("help@example.com"));
    }

    #[test]
    fn branding_serde_round_trip() {
        let b = EmailBranding {
            accent_color: Some("#ABC123".to_string()),
            support_email: Some("help@example.com".to_string()),
            custom_footer_text: Some("Custom footer".to_string()),
        };
        let json = serde_json::to_string(&b).expect("serialize");
        let deserialized: EmailBranding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(b, deserialized);
    }
}
