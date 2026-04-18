//! Per-tenant email branding configuration.
//!
//! Each tenant can override the default product name, logo, accent color,
//! support email, and footer text. The [`EmailBranding::merge`] function
//! produces a resolved branding by overlaying tenant overrides on global
//! defaults.

use serde::{Deserialize, Serialize};

/// Per-tenant email branding configuration.
///
/// All fields are optional. When `None`, [`ResolvedBranding`] uses
/// built-in defaults (product name "Hearth", default accent color, etc.).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailBranding {
    /// Product name shown in email subject and body. Defaults to "Hearth".
    pub product_name: Option<String>,
    /// URL to a logo image shown in the email header.
    pub logo_url: Option<String>,
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
            product_name: tenant
                .product_name
                .clone()
                .or_else(|| global.product_name.clone()),
            logo_url: tenant.logo_url.clone().or_else(|| global.logo_url.clone()),
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

    /// Returns the product name, falling back to "Hearth".
    pub fn product_name_or_default(&self) -> &str {
        self.product_name.as_deref().unwrap_or("Hearth")
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
    /// Resolves branding from an [`EmailBranding`], applying defaults
    /// for required fields.
    pub fn from_branding(branding: &EmailBranding) -> Self {
        Self {
            product_name: branding.product_name_or_default().to_string(),
            logo_url: branding.logo_url.clone(),
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
            product_name: Some("Global Corp".to_string()),
            accent_color: Some("#FF0000".to_string()),
            ..Default::default()
        };
        let tenant = EmailBranding::default();

        let merged = EmailBranding::merge(&global, &tenant);
        assert_eq!(merged.product_name.as_deref(), Some("Global Corp"));
        assert_eq!(merged.accent_color.as_deref(), Some("#FF0000"));
        assert!(merged.logo_url.is_none());
    }

    #[test]
    fn merge_tenant_only() {
        let global = EmailBranding::default();
        let tenant = EmailBranding {
            product_name: Some("Tenant Portal".to_string()),
            logo_url: Some("https://tenant.com/logo.png".to_string()),
            ..Default::default()
        };

        let merged = EmailBranding::merge(&global, &tenant);
        assert_eq!(merged.product_name.as_deref(), Some("Tenant Portal"));
        assert_eq!(
            merged.logo_url.as_deref(),
            Some("https://tenant.com/logo.png")
        );
    }

    #[test]
    fn merge_tenant_overrides_global() {
        let global = EmailBranding {
            product_name: Some("Global".to_string()),
            accent_color: Some("#111111".to_string()),
            support_email: Some("global@example.com".to_string()),
            ..Default::default()
        };
        let tenant = EmailBranding {
            product_name: Some("Tenant".to_string()),
            accent_color: Some("#222222".to_string()),
            ..Default::default()
        };

        let merged = EmailBranding::merge(&global, &tenant);
        assert_eq!(merged.product_name.as_deref(), Some("Tenant"));
        assert_eq!(merged.accent_color.as_deref(), Some("#222222"));
        // support_email falls through to global
        assert_eq!(merged.support_email.as_deref(), Some("global@example.com"));
    }

    #[test]
    fn merge_both_none_uses_defaults() {
        let merged = EmailBranding::merge(&EmailBranding::default(), &EmailBranding::default());
        assert!(merged.product_name.is_none());
        assert_eq!(merged.product_name_or_default(), "Hearth");
        assert_eq!(merged.accent_color_or_default(), "#E85D04");
    }

    #[test]
    fn product_name_or_default_returns_hearth() {
        let b = EmailBranding::default();
        assert_eq!(b.product_name_or_default(), "Hearth");
    }

    #[test]
    fn accent_color_or_default_returns_brand_color() {
        let b = EmailBranding::default();
        assert_eq!(b.accent_color_or_default(), "#E85D04");
    }

    #[test]
    fn resolved_branding_from_defaults() {
        let b = EmailBranding::default();
        let resolved = ResolvedBranding::from_branding(&b);
        assert_eq!(resolved.product_name, "Hearth");
        assert_eq!(resolved.accent_color, "#E85D04");
        assert!(resolved.logo_url.is_none());
        assert!(resolved.logo_svg_inline.is_none());
        assert!(resolved.support_email.is_none());
    }

    #[test]
    fn branding_serde_round_trip() {
        let b = EmailBranding {
            product_name: Some("Test".to_string()),
            logo_url: Some("https://example.com/logo.png".to_string()),
            accent_color: Some("#ABC123".to_string()),
            support_email: Some("help@example.com".to_string()),
            custom_footer_text: Some("Custom footer".to_string()),
        };
        let json = serde_json::to_string(&b).expect("serialize");
        let deserialized: EmailBranding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(b, deserialized);
    }
}
