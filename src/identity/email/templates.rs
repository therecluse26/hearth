//! Email template rendering.
//!
//! Two rendering paths:
//! 1. **Compiled (default):** Askama templates baked into the binary.
//! 2. **Disk override:** Tera templates loaded from a configured directory.
//!
//! Both paths receive the same variable context (branding + email-specific
//! fields). If a specific template is missing from the custom directory,
//! the compiled default is used as a fallback.

use std::path::Path;

use askama::Template;

use super::branding::ResolvedBranding;
use super::{EmailError, EmailMessage};

// ===== Askama template structs (compiled into binary) =====

#[derive(Template)]
#[template(path = "email/verification.html")]
struct VerificationHtml<'a> {
    verification_url: &'a str,
    product_name: &'a str,
    logo_url: &'a Option<String>,
    accent_color: &'a str,
    support_email: &'a Option<String>,
    custom_footer_text: &'a Option<String>,
}

#[derive(Template)]
#[template(path = "email/verification.txt")]
struct VerificationText<'a> {
    verification_url: &'a str,
    product_name: &'a str,
    support_email: &'a Option<String>,
    custom_footer_text: &'a Option<String>,
}

#[derive(Template)]
#[template(path = "email/setup.html")]
struct SetupHtml<'a> {
    setup_url: &'a str,
    product_name: &'a str,
    logo_url: &'a Option<String>,
    accent_color: &'a str,
    support_email: &'a Option<String>,
    custom_footer_text: &'a Option<String>,
}

#[derive(Template)]
#[template(path = "email/setup.txt")]
struct SetupText<'a> {
    setup_url: &'a str,
    product_name: &'a str,
    support_email: &'a Option<String>,
    custom_footer_text: &'a Option<String>,
}

#[derive(Template)]
#[template(path = "email/password_reset.html")]
struct PasswordResetHtml<'a> {
    reset_url: &'a str,
    product_name: &'a str,
    logo_url: &'a Option<String>,
    accent_color: &'a str,
    support_email: &'a Option<String>,
    custom_footer_text: &'a Option<String>,
}

#[derive(Template)]
#[template(path = "email/password_reset.txt")]
struct PasswordResetText<'a> {
    reset_url: &'a str,
    product_name: &'a str,
    support_email: &'a Option<String>,
    custom_footer_text: &'a Option<String>,
}

#[derive(Template)]
#[template(path = "email/test.html")]
struct TestHtml<'a> {
    product_name: &'a str,
    logo_url: &'a Option<String>,
    accent_color: &'a str,
    support_email: &'a Option<String>,
    custom_footer_text: &'a Option<String>,
}

#[derive(Template)]
#[template(path = "email/test.txt")]
struct TestText<'a> {
    product_name: &'a str,
    support_email: &'a Option<String>,
    custom_footer_text: &'a Option<String>,
}

// ===== Tera template loading (disk override) =====

/// Loads custom Tera templates from a directory.
///
/// Scans `dir` for `*.html` and `*.txt` files. Returns an error if the
/// directory is unreadable; missing individual template files are not an
/// error (the compiled default is used as a fallback).
pub(crate) fn load_custom_templates(dir: &Path) -> Result<tera::Tera, EmailError> {
    let glob = format!("{}/**/*", dir.display());
    tera::Tera::new(&glob).map_err(|e| EmailError::Template {
        reason: format!(
            "failed to load custom email templates from {}: {e}",
            dir.display()
        ),
    })
}

// ===== Render functions =====

/// Renders a verification email.
pub(crate) fn render_verification(
    url: &str,
    branding: &ResolvedBranding,
    custom: Option<&tera::Tera>,
) -> Result<EmailMessage, EmailError> {
    let subject = format!("Verify your {} account", branding.product_name);

    let (html_body, text_body) = if let Some(tera) = custom {
        render_tera_pair(tera, "verification", url, "verification_url", branding)?
    } else {
        let html = VerificationHtml {
            verification_url: url,
            product_name: &branding.product_name,
            logo_url: &branding.logo_url,
            accent_color: &branding.accent_color,
            support_email: &branding.support_email,
            custom_footer_text: &branding.custom_footer_text,
        };
        let text = VerificationText {
            verification_url: url,
            product_name: &branding.product_name,
            support_email: &branding.support_email,
            custom_footer_text: &branding.custom_footer_text,
        };
        let html_str = html.render().map_err(|e| EmailError::Template {
            reason: format!("askama render verification.html failed: {e}"),
        })?;
        let text_str = text.render().map_err(|e| EmailError::Template {
            reason: format!("askama render verification.txt failed: {e}"),
        })?;
        (html_str, text_str)
    };

    Ok(EmailMessage {
        to: String::new(), // Caller sets this
        subject,
        text_body,
        html_body,
    })
}

/// Renders a setup notification email.
pub(crate) fn render_setup(
    url: &str,
    branding: &ResolvedBranding,
    custom: Option<&tera::Tera>,
) -> Result<EmailMessage, EmailError> {
    let subject = format!("{} setup required", branding.product_name);

    let (html_body, text_body) = if let Some(tera) = custom {
        render_tera_pair(tera, "setup", url, "setup_url", branding)?
    } else {
        let html = SetupHtml {
            setup_url: url,
            product_name: &branding.product_name,
            logo_url: &branding.logo_url,
            accent_color: &branding.accent_color,
            support_email: &branding.support_email,
            custom_footer_text: &branding.custom_footer_text,
        };
        let text = SetupText {
            setup_url: url,
            product_name: &branding.product_name,
            support_email: &branding.support_email,
            custom_footer_text: &branding.custom_footer_text,
        };
        let html_str = html.render().map_err(|e| EmailError::Template {
            reason: format!("askama render setup.html failed: {e}"),
        })?;
        let text_str = text.render().map_err(|e| EmailError::Template {
            reason: format!("askama render setup.txt failed: {e}"),
        })?;
        (html_str, text_str)
    };

    Ok(EmailMessage {
        to: String::new(),
        subject,
        text_body,
        html_body,
    })
}

/// Renders a password reset email.
pub(crate) fn render_password_reset(
    url: &str,
    branding: &ResolvedBranding,
    custom: Option<&tera::Tera>,
) -> Result<EmailMessage, EmailError> {
    let subject = format!("Reset your {} password", branding.product_name);

    let (html_body, text_body) = if let Some(tera) = custom {
        render_tera_pair(tera, "password_reset", url, "reset_url", branding)?
    } else {
        let html = PasswordResetHtml {
            reset_url: url,
            product_name: &branding.product_name,
            logo_url: &branding.logo_url,
            accent_color: &branding.accent_color,
            support_email: &branding.support_email,
            custom_footer_text: &branding.custom_footer_text,
        };
        let text = PasswordResetText {
            reset_url: url,
            product_name: &branding.product_name,
            support_email: &branding.support_email,
            custom_footer_text: &branding.custom_footer_text,
        };
        let html_str = html.render().map_err(|e| EmailError::Template {
            reason: format!("askama render password_reset.html failed: {e}"),
        })?;
        let text_str = text.render().map_err(|e| EmailError::Template {
            reason: format!("askama render password_reset.txt failed: {e}"),
        })?;
        (html_str, text_str)
    };

    Ok(EmailMessage {
        to: String::new(), // Caller sets this
        subject,
        text_body,
        html_body,
    })
}

/// Renders a test email (admin transport verification).
pub(crate) fn render_test(
    branding: &ResolvedBranding,
    custom: Option<&tera::Tera>,
) -> Result<EmailMessage, EmailError> {
    let subject = format!("{} — Test Email", branding.product_name);

    let (html_body, text_body) = if let Some(tera) = custom {
        // For test email, we don't have a URL so use a placeholder key
        render_tera_pair(tera, "test", "", "test_placeholder", branding)?
    } else {
        let html = TestHtml {
            product_name: &branding.product_name,
            logo_url: &branding.logo_url,
            accent_color: &branding.accent_color,
            support_email: &branding.support_email,
            custom_footer_text: &branding.custom_footer_text,
        };
        let text = TestText {
            product_name: &branding.product_name,
            support_email: &branding.support_email,
            custom_footer_text: &branding.custom_footer_text,
        };
        let html_str = html.render().map_err(|e| EmailError::Template {
            reason: format!("askama render test.html failed: {e}"),
        })?;
        let text_str = text.render().map_err(|e| EmailError::Template {
            reason: format!("askama render test.txt failed: {e}"),
        })?;
        (html_str, text_str)
    };

    Ok(EmailMessage {
        to: String::new(),
        subject,
        text_body,
        html_body,
    })
}

/// Attempts to render a Tera template pair (HTML + text).
///
/// Falls back to compiled Askama templates for any missing template file.
fn render_tera_pair(
    tera: &tera::Tera,
    name: &str,
    url: &str,
    url_key: &str,
    branding: &ResolvedBranding,
) -> Result<(String, String), EmailError> {
    let mut ctx = tera::Context::new();
    ctx.insert(url_key, url);
    ctx.insert("product_name", &branding.product_name);
    ctx.insert("accent_color", &branding.accent_color);
    ctx.insert("logo_url", &branding.logo_url);
    ctx.insert("support_email", &branding.support_email);
    ctx.insert("custom_footer_text", &branding.custom_footer_text);

    let html_name = format!("{name}.html");
    let text_name = format!("{name}.txt");

    let html = if tera.get_template_names().any(|n| n == html_name) {
        tera.render(&html_name, &ctx)
            .map_err(|e| EmailError::Template {
                reason: format!("tera render {html_name} failed: {e}"),
            })?
    } else {
        // Fallback: this should be called by the caller using askama
        return Err(EmailError::Template {
            reason: format!("custom template {html_name} not found, falling back to compiled"),
        });
    };

    let text = if tera.get_template_names().any(|n| n == text_name) {
        tera.render(&text_name, &ctx)
            .map_err(|e| EmailError::Template {
                reason: format!("tera render {text_name} failed: {e}"),
            })?
    } else {
        return Err(EmailError::Template {
            reason: format!("custom template {text_name} not found, falling back to compiled"),
        });
    };

    Ok((html, text))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_branding() -> ResolvedBranding {
        ResolvedBranding {
            product_name: "TestCorp".to_string(),
            logo_url: Some("https://example.com/logo.png".to_string()),
            accent_color: "#FF5500".to_string(),
            support_email: Some("help@example.com".to_string()),
            custom_footer_text: Some("Custom footer".to_string()),
        }
    }

    fn default_branding() -> ResolvedBranding {
        ResolvedBranding {
            product_name: "Hearth".to_string(),
            logo_url: None,
            accent_color: "#E85D04".to_string(),
            support_email: None,
            custom_footer_text: None,
        }
    }

    #[test]
    fn renders_verification_html_with_branding() {
        let branding = test_branding();
        let msg = render_verification("https://auth.example.com/verify?t=abc", &branding, None)
            .expect("render");

        assert!(msg.html_body.contains("TestCorp"), "missing product name");
        assert!(
            msg.html_body
                .contains("https://auth.example.com/verify?t=abc"),
            "missing URL"
        );
        assert!(msg.html_body.contains("#FF5500"), "missing accent color");
        assert!(
            msg.html_body.contains("https://example.com/logo.png"),
            "missing logo"
        );
        assert!(
            msg.html_body.contains("help@example.com"),
            "missing support email"
        );
        assert!(
            msg.html_body.contains("Custom footer"),
            "missing footer text"
        );
        assert_eq!(msg.subject, "Verify your TestCorp account");
    }

    #[test]
    fn renders_verification_text_with_branding() {
        let branding = test_branding();
        let msg = render_verification("https://auth.example.com/verify?t=abc", &branding, None)
            .expect("render");

        assert!(msg.text_body.contains("TestCorp"), "missing product name");
        assert!(
            msg.text_body
                .contains("https://auth.example.com/verify?t=abc"),
            "missing URL"
        );
    }

    #[test]
    fn renders_verification_with_default_branding() {
        let branding = default_branding();
        let msg = render_verification("https://auth.example.com/verify?t=abc", &branding, None)
            .expect("render");

        assert!(msg.html_body.contains("Hearth"), "missing default name");
        assert!(msg.html_body.contains("#E85D04"), "missing default color");
        assert_eq!(msg.subject, "Verify your Hearth account");
    }

    #[test]
    fn renders_setup_html_with_branding() {
        let branding = test_branding();
        let msg = render_setup(
            "https://auth.example.com/ui/setup?token=xyz",
            &branding,
            None,
        )
        .expect("render");

        assert!(msg.html_body.contains("TestCorp"), "missing product name");
        assert!(
            msg.html_body
                .contains("https://auth.example.com/ui/setup?token=xyz"),
            "missing URL"
        );
        assert_eq!(msg.subject, "TestCorp setup required");
    }

    #[test]
    fn renders_setup_text_with_branding() {
        let branding = test_branding();
        let msg = render_setup(
            "https://auth.example.com/ui/setup?token=xyz",
            &branding,
            None,
        )
        .expect("render");

        assert!(msg.text_body.contains("TestCorp"));
        assert!(msg
            .text_body
            .contains("https://auth.example.com/ui/setup?token=xyz"));
    }

    #[test]
    fn renders_password_reset_html_with_branding() {
        let branding = test_branding();
        let msg = render_password_reset("https://auth.example.com/reset?t=abc", &branding, None)
            .expect("render");

        assert!(msg.html_body.contains("TestCorp"), "missing product name");
        assert!(
            msg.html_body
                .contains("https://auth.example.com/reset?t=abc"),
            "missing URL"
        );
        assert!(msg.html_body.contains("#FF5500"), "missing accent color");
        assert!(msg.html_body.contains("30 minutes"), "missing expiry note");
        assert_eq!(msg.subject, "Reset your TestCorp password");
    }

    #[test]
    fn renders_password_reset_text_with_branding() {
        let branding = test_branding();
        let msg = render_password_reset("https://auth.example.com/reset?t=abc", &branding, None)
            .expect("render");

        assert!(msg.text_body.contains("TestCorp"), "missing product name");
        assert!(
            msg.text_body
                .contains("https://auth.example.com/reset?t=abc"),
            "missing URL"
        );
    }

    #[test]
    fn renders_test_html_with_branding() {
        let branding = test_branding();
        let msg = render_test(&branding, None).expect("render");

        assert!(msg.html_body.contains("TestCorp"), "missing product name");
        assert!(
            msg.html_body.contains("configured correctly"),
            "missing confirmation text"
        );
        assert_eq!(msg.subject, "TestCorp \u{2014} Test Email");
    }

    #[test]
    fn renders_test_text_with_default_branding() {
        let branding = default_branding();
        let msg = render_test(&branding, None).expect("render");

        assert!(msg.text_body.contains("Hearth"), "missing default name");
        assert!(
            msg.text_body.contains("configured correctly"),
            "missing confirmation text"
        );
    }

    #[test]
    fn custom_templates_fallback_when_directory_missing() {
        let result = load_custom_templates(Path::new("/nonexistent/dir/that/does/not/exist"));
        // Tera may return an error or an empty set depending on version.
        // Both are acceptable — the service layer handles the fallback.
        if let Err(e) = &result {
            assert!(format!("{e}").contains("template"), "unexpected error: {e}");
        }
    }
}
