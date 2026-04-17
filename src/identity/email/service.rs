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
    default_branding: EmailBranding,
    custom_templates: Option<tera::Tera>,
}

impl EmailService {
    /// Creates a new email service.
    ///
    /// `default_branding` provides global defaults that can be overridden
    /// per-tenant. If `templates_dir` is set, Tera templates are loaded
    /// from disk; missing templates fall back to the compiled defaults.
    pub fn new(
        sender: SharedEmailSender,
        default_branding: EmailBranding,
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
            default_branding,
            custom_templates,
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
        let branding = ResolvedBranding::from_branding(&self.default_branding);
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
    fn resolve_branding(&self, tenant: Option<&EmailBranding>) -> ResolvedBranding {
        let merged = match tenant {
            Some(t) => EmailBranding::merge(&self.default_branding, t),
            None => self.default_branding.clone(),
        };
        ResolvedBranding::from_branding(&merged)
    }

    /// Returns a reference to the underlying sender (for setup token flows
    /// that need the raw transport).
    pub fn sender(&self) -> &SharedEmailSender {
        &self.sender
    }
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

    fn log_service() -> EmailService {
        let sender: SharedEmailSender = Arc::new(LoggingEmailSender::new());
        EmailService::new(sender, EmailBranding::default(), None).expect("service")
    }

    fn branded_service() -> EmailService {
        let sender: SharedEmailSender = Arc::new(LoggingEmailSender::new());
        let branding = EmailBranding {
            product_name: Some("Global Corp".to_string()),
            accent_color: Some("#123456".to_string()),
            ..Default::default()
        };
        EmailService::new(sender, branding, None).expect("service")
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
            product_name: Some("Tenant Portal".to_string()),
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
            product_name: Some("Tenant".to_string()),
            ..Default::default()
        };
        let resolved = service.resolve_branding(Some(&tenant));
        assert_eq!(resolved.product_name, "Tenant");
        // accent_color falls through to global
        assert_eq!(resolved.accent_color, "#123456");
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
            product_name: Some("Tenant Portal".to_string()),
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
}
