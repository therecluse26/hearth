//! Environment variable substitution for configuration strings.
//!
//! Replaces `${VAR_NAME}` patterns with the corresponding environment
//! variable values. Uses a hand-written scanner (no regex crate needed).

use crate::config::error::ConfigError;

/// Substitutes `${VAR_NAME}` patterns in the input string with environment
/// variable values.
///
/// Returns an error if a referenced variable is not set. Literal `${}`
/// sequences (empty variable name) are left unchanged.
pub(crate) fn substitute_env_vars(input: &str) -> Result<String, ConfigError> {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            // Consume the '{'
            chars.next();

            // Collect variable name until '}'
            let mut var_name = String::new();
            let mut found_close = false;
            for c in chars.by_ref() {
                if c == '}' {
                    found_close = true;
                    break;
                }
                var_name.push(c);
            }

            if !found_close || var_name.is_empty() {
                // Malformed or empty — write through literally
                result.push('$');
                result.push('{');
                result.push_str(&var_name);
                if found_close {
                    result.push('}');
                }
            } else {
                // Look up the environment variable
                match std::env::var(&var_name) {
                    Ok(value) => result.push_str(&value),
                    Err(_) => {
                        return Err(ConfigError::MissingEnvVar { var_name });
                    }
                }
            }
        } else {
            result.push(ch);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_var_substitution_in_yaml() {
        std::env::set_var("HEARTH_TEST_DIR", "/tmp/hearth-test");
        let input = "data_dir: ${HEARTH_TEST_DIR}/storage";
        let result = substitute_env_vars(input).expect("substitution should succeed");
        assert_eq!(result, "data_dir: /tmp/hearth-test/storage");
        std::env::remove_var("HEARTH_TEST_DIR");
    }

    #[test]
    fn missing_env_var_returns_error() {
        // Ensure this var definitely doesn't exist
        std::env::remove_var("HEARTH_NONEXISTENT_VAR_FOR_TEST");
        let input = "path: ${HEARTH_NONEXISTENT_VAR_FOR_TEST}";
        let result = substitute_env_vars(input);
        assert!(result.is_err());
        let err = result.expect_err("should be MissingEnvVar");
        let display = format!("{err}");
        assert!(
            display.contains("HEARTH_NONEXISTENT_VAR_FOR_TEST"),
            "error should name the missing variable, got: {display}"
        );
    }

    #[test]
    fn no_substitution_when_no_vars() {
        let input = "server:\n  port: 8420\n  bind: 127.0.0.1";
        let result = substitute_env_vars(input).expect("no-op substitution");
        assert_eq!(result, input);
    }

    #[test]
    fn multiple_vars_substituted() {
        std::env::set_var("HEARTH_TEST_HOST", "0.0.0.0");
        std::env::set_var("HEARTH_TEST_PORT", "9090");
        let input = "host: ${HEARTH_TEST_HOST}\nport: ${HEARTH_TEST_PORT}";
        let result = substitute_env_vars(input).expect("multi-var substitution");
        assert_eq!(result, "host: 0.0.0.0\nport: 9090");
        std::env::remove_var("HEARTH_TEST_HOST");
        std::env::remove_var("HEARTH_TEST_PORT");
    }

    #[test]
    fn empty_braces_pass_through() {
        let input = "value: ${}";
        let result = substitute_env_vars(input).expect("empty braces pass through");
        assert_eq!(result, "value: ${}");
    }

    #[test]
    fn unclosed_brace_passes_through() {
        let input = "value: ${UNCLOSED";
        let result = substitute_env_vars(input).expect("unclosed brace pass through");
        assert_eq!(result, "value: ${UNCLOSED");
    }

    #[test]
    fn dollar_without_brace_passes_through() {
        let input = "price: $100";
        let result = substitute_env_vars(input).expect("dollar without brace");
        assert_eq!(result, "price: $100");
    }
}
