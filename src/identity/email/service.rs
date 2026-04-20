//! Email orchestration service.
//!
//! [`EmailService`] is the public API for sending branded, templated
//! emails. Callers use high-level methods like `send_verification_email`
//! rather than constructing messages manually.
//!
//! The service resolves per-tenant branding, renders templates (compiled
//! Askama or disk-based Tera), and dispatches to the underlying
//! [`EmailSender`] transport.

use std::path::Path;

use super::branding::{EmailBranding, ResolvedBranding};
use super::templates;
use super::{EmailError, SharedEmailSender};

/// Orchestration layer for sending branded, templated emails.
///
/// Wraps a [`SharedEmailSender`] (transport) and adds branding +
/// template rendering on top. Callers interact with this service
/// rather than the raw transport.
pub struct EmailService {
    sender: SharedEmailSender,
    /// Global product name (from [`BrandingConfig`](crate::config::BrandingConfig)).
    product_name: String,
    /// Global logo URL (from [`BrandingConfig`](crate::config::BrandingConfig)).
    logo_url: Option<String>,
    default_branding: EmailBranding,
    custom_templates: Option<tera::Tera>,
    /// Built-in SVG markup for the default Hearth logo. Inlined directly
    /// in emails when no custom logo URL is configured, avoiding broken
    /// images from `localhost` or firewalled servers.
    default_logo_svg: String,
}

impl EmailService {
    /// Creates a new email service.
    ///
    /// `product_name` and `logo_url` come from the global
    /// [`BrandingConfig`](crate::config::BrandingConfig) and apply to
    /// all outbound emails. `default_branding` provides email-specific
    /// defaults (accent color, support email, footer) that can be
    /// overridden per-tenant. `default_logo_svg` is the raw SVG markup
    /// for the built-in logo, inlined when no custom logo URL is set.
    /// If `templates_dir` is set, Tera templates are loaded from disk;
    /// missing templates fall back to the compiled defaults.
    pub fn new(
        sender: SharedEmailSender,
        product_name: String,
        logo_url: Option<String>,
        default_branding: EmailBranding,
        default_logo_svg: String,
        templates_dir: Option<&Path>,
    ) -> Result<Self, EmailError> {
        let custom_templates = templates_dir
            .map(templates::load_custom_templates)
            .transpose()
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "failed to load custom email templates, using compiled defaults");
                None
            });

        Ok(Self {
            sender,
            product_name,
            logo_url,
            default_branding,
            custom_templates,
            default_logo_svg,
        })
    }

    /// Sends a verification email with per-tenant branding.
    ///
    /// Resolves branding (global defaults + tenant overrides), renders
    /// the verification template, and dispatches to the transport.
    pub fn send_verification_email(
        &self,
        to: &str,
        url: &str,
        tenant_branding: Option<&EmailBranding>,
    ) -> Result<(), EmailError> {
        let branding = self.resolve_branding(tenant_branding);
        let mut msg =
            templates::render_verification(url, &branding, self.custom_templates.as_ref())
                .or_else(|_| {
                    // Fallback to compiled templates if custom rendering fails
                    templates::render_verification(url, &branding, None)
                })?;
        msg.to = to.to_string();
        self.sender.send(&msg)
    }

    /// Sends a first-run setup notification email.
    ///
    /// Uses global branding only (no tenant exists yet during setup).
    pub fn send_setup_notification(&self, to: &str, url: &str) -> Result<(), EmailError> {
        let branding = self.resolve_branding(None);
        let mut msg = templates::render_setup(url, &branding, self.custom_templates.as_ref())
            .or_else(|_| templates::render_setup(url, &branding, None))?;
        msg.to = to.to_string();
        self.sender.send(&msg)
    }

    /// Sends a password reset email with per-tenant branding.
    ///
    /// Resolves branding (global defaults + tenant overrides), renders
    /// the password reset template, and dispatches to the transport.
    pub fn send_password_reset_email(
        &self,
        to: &str,
        url: &str,
        tenant_branding: Option<&EmailBranding>,
    ) -> Result<(), EmailError> {
        let branding = self.resolve_branding(tenant_branding);
        let mut msg =
            templates::render_password_reset(url, &branding, self.custom_templates.as_ref())
                .or_else(|_| {
                    // Fallback to compiled templates if custom rendering fails
                    templates::render_password_reset(url, &branding, None)
                })?;
        msg.to = to.to_string();
        self.sender.send(&msg)
    }

    /// Sends an organization invitation email.
    ///
    /// Contains an acceptance URL and context about who sent the invitation.
    pub fn send_invitation_email(
        &self,
        to: &str,
        accept_url: &str,
        org_name: &str,
        inviter_email: &str,
        tenant_branding: Option<&EmailBranding>,
    ) -> Result<(), EmailError> {
        let branding = self.resolve_branding(tenant_branding);
        let mut msg = templates::render_invitation(
            accept_url,
            org_name,
            inviter_email,
            &branding,
            self.custom_templates.as_ref(),
        )
        .or_else(|_| {
            // Fallback to compiled templates if custom rendering fails
            templates::render_invitation(accept_url, org_name, inviter_email, &branding, None)
        })?;
        msg.to = to.to_string();
        self.sender.send(&msg)
    }

    /// Sends a test email (admin transport verification).
    ///
    /// Uses the resolved branding to confirm transport configuration works.
    pub fn send_test_email(
        &self,
        to: &str,
        tenant_branding: Option<&EmailBranding>,
    ) -> Result<(), EmailError> {
        let branding = self.resolve_branding(tenant_branding);
        let mut msg = templates::render_test(&branding, self.custom_templates.as_ref())
            .or_else(|_| templates::render_test(&branding, None))?;
        msg.to = to.to_string();
        self.sender.send(&msg)
    }

    /// Resolves branding by merging global defaults with tenant overrides.
    ///
    /// Computes `logo_svg_inline` based on the resolved `logo_url`:
    /// - No logo URL → inline the built-in Hearth SVG.
    /// - Remote URL (`http://` or `https://`) → use `<img src>` (keep `logo_url`).
    /// - Local `.svg` path → read and inline from disk; fall back to default on I/O error.
    /// - Local non-SVG path → fall back to default Hearth SVG (can't inline raster).
    ///
    /// Local file paths are **always** cleared from `logo_url` — they are never valid
    /// as `<img src>` in emails.
    fn resolve_branding(&self, tenant: Option<&EmailBranding>) -> ResolvedBranding {
        let merged = match tenant {
            Some(t) => EmailBranding::merge(&self.default_branding, t),
            None => self.default_branding.clone(),
        };
        let mut resolved =
            ResolvedBranding::from_branding(&merged, &self.product_name, self.logo_url.as_deref());

        let is_local_path = resolved
            .logo_url
            .as_ref()
            .is_some_and(|url| !url.starts_with("http://") && !url.starts_with("https://"));

        let logo_svg_inline = match &resolved.logo_url {
            None => Some(self.default_logo_svg.clone()),
            Some(url) if url.starts_with("http://") || url.starts_with("https://") => None,
            Some(path)
                if std::path::Path::new(path)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("svg")) =>
            {
                std::fs::read_to_string(path).ok()
            }
            _ => None,
        };

        // Local paths are never valid as email <img src> — always clear them.
        // If inlining failed (I/O error or non-SVG), fall back to the default logo.
        if is_local_path {
            resolved.logo_url = None;
            resolved.logo_svg_inline = logo_svg_inline
                .map(|svg| prepare_svg_for_email(&svg))
                .or_else(|| Some(prepare_svg_for_email(&self.default_logo_svg)));
        } else if let Some(svg) = logo_svg_inline {
            resolved.logo_url = None;
            resolved.logo_svg_inline = Some(prepare_svg_for_email(&svg));
        }

        resolved
    }

    /// Returns a reference to the underlying sender (for setup token flows
    /// that need the raw transport).
    pub fn sender(&self) -> &SharedEmailSender {
        &self.sender
    }
}

/// Prepares raw SVG markup for inline rendering in email HTML.
///
/// SVGs authored in Inkscape or similar tools typically use absolute units
/// (`width="500mm"`) which render at full physical size in email clients,
/// ignoring any CSS constraints on wrapper elements.  This function:
///
/// 1. Strips the XML processing instruction (`<?xml ... ?>`) — unnecessary
///    when the SVG is inlined inside an HTML document.
/// 2. Removes `width` and `height` attributes from the root `<svg>` element
///    (they may specify mm/cm/in/pt/px values that resist CSS overrides).
/// 3. Injects `height="48"` (pixels) so the logo fits a standard email
///    header. The `viewBox` preserves the aspect ratio.
fn prepare_svg_for_email(svg: &str) -> String {
    let mut s = svg.to_string();

    // 1. Strip XML processing instruction
    if let Some(pi_end) = s.find("?>") {
        s = s[pi_end + 2..].trim_start().to_string();
    }

    // 2. Strip HTML/XML comments (e.g. Inkscape "Created with" comment)
    while let Some(start) = s.find("<!--") {
        if let Some(end) = s[start..].find("-->") {
            let before = &s[..start];
            let after = s[start + end + 3..].trim_start();
            s = format!("{before}{after}");
        } else {
            break;
        }
    }

    // 3. Remove width="..." and height="..." from the opening <svg> tag
    let Some(svg_tag_end) = s.find('>') else {
        return s;
    };
    let tag = s[..svg_tag_end].to_string();
    let rest = &s[svg_tag_end..];

    let cleaned = remove_svg_attr(&remove_svg_attr(&tag, "width"), "height");

    // 4. Inject constrained pixel height (viewBox provides aspect ratio)
    let new_tag = cleaned.replacen(
        "<svg",
        r#"<svg height="48" style="display:block;margin:0 auto""#,
        1,
    );

    format!("{new_tag}{rest}")
}

/// Removes a named attribute from an SVG tag string.
///
/// Handles both `attr="val"` on the same line as `<svg` and on separate
/// lines with leading whitespace (common in Inkscape exports).
fn remove_svg_attr(tag: &str, attr_name: &str) -> String {
    let needle = format!("{attr_name}=\"");
    let Some(needle_pos) = tag.find(&needle) else {
        return tag.to_string();
    };

    // Find the closing quote after the value
    let value_start = needle_pos + needle.len();
    let Some(close_offset) = tag[value_start..].find('"') else {
        return tag.to_string();
    };
    let attr_end = value_start + close_offset + 1;

    // Eat preceding whitespace (handles multi-line SVG tags)
    let mut attr_start = needle_pos;
    while attr_start > 0 && tag.as_bytes()[attr_start - 1].is_ascii_whitespace() {
        attr_start -= 1;
    }

    let mut result = tag[..attr_start].to_string();
    result.push_str(&tag[attr_end..]);
    result
}

impl std::fmt::Debug for EmailService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailService")
            .field("default_branding", &self.default_branding)
            .field(
                "custom_templates",
                &self.custom_templates.as_ref().map(|_| "<loaded>"),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::identity::email::LoggingEmailSender;

    const TEST_SVG: &str = r#"<svg xmlns="http://www.w3.org/2000/svg"><text>Hearth</text></svg>"#;

    fn log_service() -> EmailService {
        let sender: SharedEmailSender = Arc::new(LoggingEmailSender::new());
        EmailService::new(
            sender,
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            TEST_SVG.to_string(),
            None,
        )
        .expect("service")
    }

    fn branded_service() -> EmailService {
        let sender: SharedEmailSender = Arc::new(LoggingEmailSender::new());
        let branding = EmailBranding {
            accent_color: Some("#123456".to_string()),
            ..Default::default()
        };
        EmailService::new(
            sender,
            "Global Corp".to_string(),
            None,
            branding,
            TEST_SVG.to_string(),
            None,
        )
        .expect("service")
    }

    #[test]
    fn send_verification_with_default_branding() {
        let service = log_service();
        let result = service.send_verification_email(
            "alice@example.com",
            "https://auth.example.com/verify?t=abc",
            None,
        );
        assert!(result.is_ok(), "send should succeed: {result:?}");
    }

    #[test]
    fn send_verification_with_tenant_branding() {
        let service = branded_service();
        let tenant = EmailBranding {
            accent_color: Some("#ABCDEF".to_string()),
            ..Default::default()
        };
        let result = service.send_verification_email(
            "alice@example.com",
            "https://auth.example.com/verify?t=abc",
            Some(&tenant),
        );
        assert!(result.is_ok(), "send should succeed: {result:?}");
    }

    #[test]
    fn send_setup_notification() {
        let service = log_service();
        let result = service.send_setup_notification(
            "ops@example.com",
            "https://auth.example.com/ui/setup?token=xyz",
        );
        assert!(result.is_ok(), "send should succeed: {result:?}");
    }

    #[test]
    fn branding_resolution_uses_global_defaults() {
        let service = branded_service();
        let resolved = service.resolve_branding(None);
        assert_eq!(resolved.product_name, "Global Corp");
        assert_eq!(resolved.accent_color, "#123456");
    }

    #[test]
    fn branding_resolution_tenant_overrides() {
        let service = branded_service();
        let tenant = EmailBranding {
            accent_color: Some("#AABBCC".to_string()),
            ..Default::default()
        };
        let resolved = service.resolve_branding(Some(&tenant));
        // product_name comes from global BrandingConfig, not tenant EmailBranding
        assert_eq!(resolved.product_name, "Global Corp");
        // accent_color overridden by tenant
        assert_eq!(resolved.accent_color, "#AABBCC");
    }

    #[test]
    fn send_password_reset_with_default_branding() {
        let service = log_service();
        let result = service.send_password_reset_email(
            "alice@example.com",
            "https://auth.example.com/reset?t=abc",
            None,
        );
        assert!(result.is_ok(), "send should succeed: {result:?}");
    }

    #[test]
    fn send_password_reset_with_tenant_branding() {
        let service = branded_service();
        let tenant = EmailBranding {
            accent_color: Some("#ABCDEF".to_string()),
            ..Default::default()
        };
        let result = service.send_password_reset_email(
            "alice@example.com",
            "https://auth.example.com/reset?t=abc",
            Some(&tenant),
        );
        assert!(result.is_ok(), "send should succeed: {result:?}");
    }

    #[test]
    fn send_test_email_with_default_branding() {
        let service = log_service();
        let result = service.send_test_email("admin@example.com", None);
        assert!(result.is_ok(), "send should succeed: {result:?}");
    }

    #[test]
    fn debug_output() {
        let service = log_service();
        let debug = format!("{service:?}");
        assert!(debug.contains("EmailService"), "debug: {debug}");
    }

    #[test]
    fn prepare_svg_strips_xml_pi_and_comments() {
        let svg = r#"<?xml version="1.0"?>
<!-- Created with Inkscape -->
<svg viewBox="0 0 100 100"><rect/></svg>"#;
        let result = prepare_svg_for_email(svg);
        assert!(!result.contains("<?xml"), "XML PI should be stripped");
        assert!(!result.contains("<!--"), "comments should be stripped");
        assert!(result.contains("<rect/>"), "body should be preserved");
    }

    #[test]
    fn prepare_svg_removes_mm_dimensions_and_injects_height() {
        let svg = r#"<svg
   width="500mm"
   height="200mm"
   viewBox="0 0 500 200"
   xmlns="http://www.w3.org/2000/svg">
  <rect/>
</svg>"#;
        let result = prepare_svg_for_email(svg);
        assert!(
            !result.contains("500mm"),
            "width in mm should be removed: {result}"
        );
        assert!(
            !result.contains("200mm"),
            "height in mm should be removed: {result}"
        );
        assert!(
            result.contains(r#"height="48""#),
            "should have height=48: {result}"
        );
        assert!(
            result.contains("viewBox"),
            "viewBox should be preserved: {result}"
        );
    }

    #[test]
    fn prepare_svg_simple_tag_gets_height() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg"><text>Hi</text></svg>"#;
        let result = prepare_svg_for_email(svg);
        assert!(
            result.contains(r#"height="48""#),
            "height injected: {result}"
        );
        assert!(result.contains("<text>Hi</text>"), "body preserved");
    }
}
