//! Placeholder validation and substitution for stored email templates.
//!
//! Stored templates use `{{token}}` syntax for variable interpolation.
//! Before persisting a template body, callers MUST call [`validate`] to
//! ensure only approved tokens appear. This prevents template injection
//! and operator confusion about unsupported variables.
//!
//! ## Allowed placeholders by template kind
//!
//! | Template kind      | Extra tokens beyond the common set                 |
//! |--------------------|-----------------------------------------------------|
//! | `verification`     | `{{verification_url}}`                              |
//! | `password_reset`   | `{{reset_url}}`                                     |
//! | `welcome`          | `{{user_email}}`                                    |
//! | `invitation`       | `{{accept_url}}`, `{{org_name}}`, `{{inviter_email}}`|
//!
//! Common to all: `{{product_name}}`, `{{support_email}}`, `{{custom_footer_text}}`

use super::EmailError;

/// Placeholders available in every template kind.
const COMMON_PLACEHOLDERS: &[&str] = &[
    "{{product_name}}",
    "{{support_email}}",
    "{{custom_footer_text}}",
];

/// Returns the full set of allowed placeholders for a given template kind.
///
/// Returns `None` when `kind` is not a recognized template kind.
pub fn allowed_placeholders(kind: &str) -> Option<Vec<&'static str>> {
    let extra: &[&str] = match kind {
        "verification" => &["{{verification_url}}"],
        "password_reset" => &["{{reset_url}}"],
        "welcome" => &["{{user_email}}"],
        "invitation" => &["{{accept_url}}", "{{org_name}}", "{{inviter_email}}"],
        _ => return None,
    };

    let mut all = COMMON_PLACEHOLDERS.to_vec();
    all.extend_from_slice(extra);
    Some(all)
}

/// Validates that `text` contains only approved `{{placeholder}}` tokens
/// for the given `kind`.
///
/// Returns `Err(EmailError::Template)` with the first disallowed token found.
/// Returns `Ok(())` when all tokens are in the allowlist (or there are none).
pub fn validate(kind: &str, text: &str) -> Result<(), EmailError> {
    let allowed = allowed_placeholders(kind).ok_or_else(|| EmailError::Template {
        reason: format!(
            "unknown email template kind {kind:?}; \
             valid kinds are: verification, password_reset, welcome, invitation"
        ),
    })?;

    let mut search = text;
    while let Some(open) = search.find("{{") {
        let after_open = &search[open + 2..];
        let close = after_open.find("}}").ok_or_else(|| EmailError::Template {
            reason: "unclosed '{{' in template body".to_string(),
        })?;
        let token = format!("{{{{{}}}}}", &after_open[..close]);
        if !allowed.contains(&token.as_str()) {
            return Err(EmailError::Template {
                reason: format!(
                    "disallowed placeholder {token} in {kind:?} template; \
                     allowed: {}",
                    allowed.join(", ")
                ),
            });
        }
        search = &after_open[close + 2..];
    }
    Ok(())
}

/// Performs `{{placeholder}}` substitution using the provided key-value map.
///
/// Unrecognised tokens are left unchanged (callers should call [`validate`]
/// first so this situation only arises in tests or with pre-validated data).
pub fn render(template: &str, vars: &[(&str, &str)]) -> String {
    let mut out = template.to_string();
    for (key, val) in vars {
        let token = format!("{{{{{key}}}}}");
        out = out.replace(&token, val);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== allowed_placeholders =====

    #[test]
    fn known_kind_returns_some() {
        assert!(allowed_placeholders("verification").is_some());
        assert!(allowed_placeholders("password_reset").is_some());
        assert!(allowed_placeholders("welcome").is_some());
        assert!(allowed_placeholders("invitation").is_some());
    }

    #[test]
    fn unknown_kind_returns_none() {
        assert!(allowed_placeholders("unknown").is_none());
        assert!(allowed_placeholders("").is_none());
    }

    #[test]
    fn verification_includes_verification_url() {
        let allowed = allowed_placeholders("verification").expect("known kind");
        assert!(allowed.contains(&"{{verification_url}}"));
        assert!(allowed.contains(&"{{product_name}}"));
    }

    #[test]
    fn invitation_includes_all_extra_tokens() {
        let allowed = allowed_placeholders("invitation").expect("known kind");
        assert!(allowed.contains(&"{{accept_url}}"));
        assert!(allowed.contains(&"{{org_name}}"));
        assert!(allowed.contains(&"{{inviter_email}}"));
    }

    // ===== validate =====

    #[test]
    fn validate_clean_text_ok() {
        assert!(validate("verification", "No placeholders here.").is_ok());
    }

    #[test]
    fn validate_allowed_placeholder_ok() {
        assert!(validate("verification", "Click {{verification_url}} to verify.").is_ok());
    }

    #[test]
    fn validate_common_placeholder_ok() {
        assert!(validate("password_reset", "Email from {{product_name}}").is_ok());
    }

    #[test]
    fn validate_disallowed_placeholder_err() {
        let err = validate("verification", "{{reset_url}}").expect_err("expected validation error");
        let msg = format!("{err}");
        assert!(msg.contains("reset_url"), "got: {msg}");
        assert!(msg.contains("disallowed"), "got: {msg}");
    }

    #[test]
    fn validate_unknown_kind_err() {
        let err = validate("bogus_kind", "hello").expect_err("expected validation error");
        let msg = format!("{err}");
        assert!(msg.contains("unknown email template kind"), "got: {msg}");
    }

    #[test]
    fn validate_unclosed_brace_err() {
        let err = validate("verification", "{{unclosed").expect_err("expected validation error");
        let msg = format!("{err}");
        assert!(msg.contains("unclosed"), "got: {msg}");
    }

    #[test]
    fn validate_multiple_placeholders_ok() {
        assert!(validate(
            "invitation",
            "{{org_name}} invited by {{inviter_email}}, click {{accept_url}}"
        )
        .is_ok());
    }

    #[test]
    fn validate_cross_kind_placeholder_rejected() {
        // verification_url is not allowed in password_reset
        let err = validate("password_reset", "{{verification_url}}")
            .expect_err("expected validation error");
        let msg = format!("{err}");
        assert!(msg.contains("disallowed"), "got: {msg}");
    }

    // ===== render =====

    #[test]
    fn render_substitutes_known_vars() {
        let result = render("Hello from {{product_name}}!", &[("product_name", "Acme")]);
        assert_eq!(result, "Hello from Acme!");
    }

    #[test]
    fn render_leaves_unknown_tokens_unchanged() {
        let result = render("{{unknown_var}}", &[("product_name", "X")]);
        assert_eq!(result, "{{unknown_var}}");
    }

    #[test]
    fn render_multiple_vars() {
        let result = render(
            "{{org_name}} — invited by {{inviter_email}}",
            &[("org_name", "Acme"), ("inviter_email", "bob@acme.com")],
        );
        assert_eq!(result, "Acme — invited by bob@acme.com");
    }

    #[test]
    fn render_repeated_token() {
        let result = render(
            "{{product_name}} is {{product_name}}",
            &[("product_name", "Hearth")],
        );
        assert_eq!(result, "Hearth is Hearth");
    }
}
