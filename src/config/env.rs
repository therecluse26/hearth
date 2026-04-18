//! Environment variable substitution for configuration strings.
//!
//! Replaces `${VAR_NAME}` patterns with the corresponding environment
//! variable values. Supports `${VAR:-default}` syntax for fallback
//! values (matching POSIX shell `:-` semantics).
//!
//! Also provides `.env` file loading via [`load_dotenv`].

use crate::config::error::ConfigError;
use std::path::Path;

/// A warning emitted when an environment variable referenced in the
/// config is missing or empty. Unlike previous behaviour (hard error),
/// warnings allow the server to start and report the issue through
/// tracing + the admin UI.
#[derive(Debug, Clone)]
pub struct EnvVarWarning {
    /// Name of the environment variable.
    pub var_name: String,
    /// What went wrong.
    pub kind: EnvVarWarningKind,
}

/// The flavour of an [`EnvVarWarning`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvVarWarningKind {
    /// The variable is not set in the environment and no default was provided.
    Missing,
    /// The variable is set to an empty string and no default was provided.
    Empty,
}

impl EnvVarWarning {
    /// Human-readable label suitable for the admin dashboard.
    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self.kind {
            EnvVarWarningKind::Missing => "not set (substituted empty string)",
            EnvVarWarningKind::Empty => "set but empty (possible misconfiguration)",
        }
    }
}

/// Substitutes `${VAR_NAME}` and `${VAR_NAME:-default}` patterns in the
/// input string with environment variable values.
///
/// # Default syntax
///
/// `${VAR:-fallback}` uses `fallback` when `VAR` is unset **or** empty
/// (matching POSIX shell `:-` semantics). The default value extends to
/// the closing `}` and may contain colons (e.g. `${HOST:-0.0.0.0:8080}`).
/// `${VAR:-}` explicitly defaults to the empty string (no warning).
///
/// # Graceful degradation
///
/// If a variable is missing or empty **and** no default was specified,
/// the function substitutes an empty string and records a warning. This
/// prevents the server from crashing before tracing initialises.
///
/// Literal `${}` sequences (empty variable name) are left unchanged.
pub(crate) fn substitute_env_vars(input: &str) -> (String, Vec<EnvVarWarning>) {
    let mut result = String::with_capacity(input.len());
    let mut warnings = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            // Consume the '{'
            chars.next();

            // Collect everything until '}'
            let mut raw = String::new();
            let mut found_close = false;
            for c in chars.by_ref() {
                if c == '}' {
                    found_close = true;
                    break;
                }
                raw.push(c);
            }

            if !found_close || raw.is_empty() {
                // Malformed or empty — write through literally
                result.push('$');
                result.push('{');
                result.push_str(&raw);
                if found_close {
                    result.push('}');
                }
            } else {
                // Split on first `:-` to extract var name and optional default
                let (var_name, default_value) = match raw.find(":-") {
                    Some(pos) => (&raw[..pos], Some(&raw[pos + 2..])),
                    None => (raw.as_str(), None),
                };

                match std::env::var(var_name) {
                    Ok(value) if !value.is_empty() => {
                        // Variable is set and non-empty — always use it
                        result.push_str(&value);
                    }
                    Ok(_empty) => {
                        // Variable is set but empty
                        if let Some(default) = default_value {
                            result.push_str(default);
                        } else {
                            // No default — substitute empty + warn
                            warnings.push(EnvVarWarning {
                                var_name: var_name.to_string(),
                                kind: EnvVarWarningKind::Empty,
                            });
                        }
                    }
                    Err(_) => {
                        // Variable is not set
                        if let Some(default) = default_value {
                            result.push_str(default);
                        } else {
                            // No default — substitute empty + warn
                            warnings.push(EnvVarWarning {
                                var_name: var_name.to_string(),
                                kind: EnvVarWarningKind::Missing,
                            });
                        }
                    }
                }
            }
        } else {
            result.push(ch);
        }
    }

    (result, warnings)
}

/// Loads a `.env` file and injects each `KEY=VALUE` pair into the process
/// environment, **skipping variables that are already set**.
///
/// Silently succeeds if `path` does not exist — a missing `.env` is not an
/// error. Returns an error only for genuine parse failures in an existing file.
///
/// # Format supported
///
/// - `KEY=VALUE` — unquoted; inline comments stripped after ` #`
/// - `KEY="VALUE"` — double-quoted; supports `\n`, `\r`, `\t`, `\\`, `\"`
/// - `KEY='VALUE'` — single-quoted; no escape processing
/// - `export KEY=VALUE` — optional `export` prefix
/// - Lines starting with `#` and blank lines are ignored
///
/// Real environment variables always take precedence: if `KEY` is already set
/// in the process environment it will not be overwritten.
///
/// # Threading
///
/// This function mutates the process environment via [`std::env::set_var`].
/// It must be called before the async runtime starts (i.e., during startup
/// initialization) to avoid concurrent access to the environment.
pub(crate) fn load_dotenv(path: &Path) -> Result<(), ConfigError> {
    let content = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(ConfigError::FileRead(e)),
    };

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.trim();

        // Skip blank lines and full-line comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Strip optional `export` prefix (e.g. `export KEY=VALUE`)
        let line = line
            .strip_prefix("export")
            .and_then(|rest| {
                // Require at least one whitespace after `export`
                let trimmed = rest.trim_start();
                if trimmed.len() < rest.len() {
                    Some(trimmed)
                } else {
                    None
                }
            })
            .unwrap_or(line);

        let eq = line.find('=').ok_or_else(|| ConfigError::DotenvParse {
            line: line_no,
            message: format!("expected KEY=VALUE, got: {line:?}"),
        })?;

        let key = line[..eq].trim_end();
        if key.is_empty() {
            return Err(ConfigError::DotenvParse {
                line: line_no,
                message: "key must not be empty".to_string(),
            });
        }

        let value = parse_dotenv_value(&line[eq + 1..]);

        // Real env vars take precedence; .env only fills gaps
        if std::env::var(key).is_err() {
            std::env::set_var(key, &value);
        }
    }

    Ok(())
}

/// Parses the value portion of a `KEY=VALUE` `.env` line.
fn parse_dotenv_value(raw: &str) -> String {
    // Trim any leading whitespace before the value (e.g. `KEY= "foo"`)
    let s = raw.trim_start();

    if let Some(inner) = s.strip_prefix('"') {
        parse_double_quoted(inner)
    } else if let Some(inner) = s.strip_prefix('\'') {
        // Single-quoted: no escape sequences; content up to the next `'`
        inner
            .split_once('\'')
            .map_or_else(|| inner.to_string(), |(v, _)| v.to_string())
    } else {
        // Unquoted: strip inline comment and trailing whitespace
        strip_inline_comment(s).trim_end().to_string()
    }
}

/// Parses a double-quoted `.env` value, handling common escape sequences.
///
/// Reads characters until the closing `"` is found. Supports `\\`, `\"`,
/// `\n`, `\r`, and `\t`.
fn parse_double_quoted(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => break,
            '\\' => match chars.next() {
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some(other) => result.push(other),
                None => break,
            },
            other => result.push(other),
        }
    }
    result
}

/// Strips an inline comment from an unquoted `.env` value.
///
/// An inline comment begins at the first ` #` (space followed by `#`).
/// A bare `#` at the very start of the value is also treated as a comment.
fn strip_inline_comment(s: &str) -> &str {
    if s.starts_with('#') {
        return "";
    }
    match s.find(" #") {
        Some(pos) => &s[..pos],
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_var_substitution_in_yaml() {
        std::env::set_var("HEARTH_TEST_DIR", "/tmp/hearth-test");
        let input = "data_dir: ${HEARTH_TEST_DIR}/storage";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, "data_dir: /tmp/hearth-test/storage");
        assert!(warnings.is_empty());
        std::env::remove_var("HEARTH_TEST_DIR");
    }

    #[test]
    fn missing_env_var_warns_not_errors() {
        std::env::remove_var("HEARTH_NONEXISTENT_VAR_FOR_TEST");
        let input = "path: ${HEARTH_NONEXISTENT_VAR_FOR_TEST}";
        let (result, warnings) = substitute_env_vars(input);
        // Should substitute empty string, not error
        assert_eq!(result, "path: ");
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].var_name, "HEARTH_NONEXISTENT_VAR_FOR_TEST");
        assert_eq!(warnings[0].kind, EnvVarWarningKind::Missing);
    }

    #[test]
    fn empty_env_var_warns() {
        std::env::set_var("HEARTH_EMPTY_VAR_TEST", "");
        let input = "val: ${HEARTH_EMPTY_VAR_TEST}";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, "val: ");
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].var_name, "HEARTH_EMPTY_VAR_TEST");
        assert_eq!(warnings[0].kind, EnvVarWarningKind::Empty);
        std::env::remove_var("HEARTH_EMPTY_VAR_TEST");
    }

    #[test]
    fn no_substitution_when_no_vars() {
        let input = "server:\n  port: 8420\n  bind: 127.0.0.1";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, input);
        assert!(warnings.is_empty());
    }

    #[test]
    fn multiple_vars_substituted() {
        std::env::set_var("HEARTH_TEST_HOST", "0.0.0.0");
        std::env::set_var("HEARTH_TEST_PORT", "9090");
        let input = "host: ${HEARTH_TEST_HOST}\nport: ${HEARTH_TEST_PORT}";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, "host: 0.0.0.0\nport: 9090");
        assert!(warnings.is_empty());
        std::env::remove_var("HEARTH_TEST_HOST");
        std::env::remove_var("HEARTH_TEST_PORT");
    }

    #[test]
    fn empty_braces_pass_through() {
        let input = "value: ${}";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, "value: ${}");
        assert!(warnings.is_empty());
    }

    #[test]
    fn unclosed_brace_passes_through() {
        let input = "value: ${UNCLOSED";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, "value: ${UNCLOSED");
        assert!(warnings.is_empty());
    }

    #[test]
    fn dollar_without_brace_passes_through() {
        let input = "price: $100";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, "price: $100");
        assert!(warnings.is_empty());
    }

    // === ${VAR:-default} tests ===

    #[test]
    fn env_var_with_default_when_unset() {
        std::env::remove_var("HEARTH_DEFAULT_UNSET_TEST");
        let input = "bind: ${HEARTH_DEFAULT_UNSET_TEST:-127.0.0.1}";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, "bind: 127.0.0.1");
        assert!(warnings.is_empty(), "default should suppress warning");
    }

    #[test]
    fn env_var_with_default_when_set() {
        std::env::set_var("HEARTH_DEFAULT_SET_TEST", "0.0.0.0");
        let input = "bind: ${HEARTH_DEFAULT_SET_TEST:-127.0.0.1}";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, "bind: 0.0.0.0");
        assert!(warnings.is_empty());
        std::env::remove_var("HEARTH_DEFAULT_SET_TEST");
    }

    #[test]
    fn env_var_with_default_when_empty() {
        std::env::set_var("HEARTH_DEFAULT_EMPTY_TEST", "");
        let input = "bind: ${HEARTH_DEFAULT_EMPTY_TEST:-127.0.0.1}";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, "bind: 127.0.0.1");
        assert!(
            warnings.is_empty(),
            "empty var with default should not warn"
        );
        std::env::remove_var("HEARTH_DEFAULT_EMPTY_TEST");
    }

    #[test]
    fn env_var_default_containing_colons() {
        std::env::remove_var("HEARTH_COLON_DEFAULT_TEST");
        let input = "addr: ${HEARTH_COLON_DEFAULT_TEST:-host:8080}";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, "addr: host:8080");
        assert!(warnings.is_empty());
    }

    #[test]
    fn env_var_with_empty_default() {
        std::env::remove_var("HEARTH_EMPTY_DEFAULT_TEST");
        let input = "val: ${HEARTH_EMPTY_DEFAULT_TEST:-}";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, "val: ");
        assert!(
            warnings.is_empty(),
            "explicit empty default should not warn"
        );
    }

    // === load_dotenv tests ===

    #[test]
    fn dotenv_loads_key_value_pairs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dotenv = dir.path().join(".env");
        std::fs::write(
            &dotenv,
            "HEARTH_DENV_LOAD_A=hello\nHEARTH_DENV_LOAD_B=world\n",
        )
        .expect("write .env");
        std::env::remove_var("HEARTH_DENV_LOAD_A");
        std::env::remove_var("HEARTH_DENV_LOAD_B");

        load_dotenv(&dotenv).expect("load_dotenv");

        assert_eq!(std::env::var("HEARTH_DENV_LOAD_A").unwrap(), "hello");
        assert_eq!(std::env::var("HEARTH_DENV_LOAD_B").unwrap(), "world");
        std::env::remove_var("HEARTH_DENV_LOAD_A");
        std::env::remove_var("HEARTH_DENV_LOAD_B");
    }

    #[test]
    fn dotenv_does_not_override_existing_env() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dotenv = dir.path().join(".env");
        std::fs::write(&dotenv, "HEARTH_DENV_NO_OVERRIDE=from_file\n").expect("write .env");
        std::env::set_var("HEARTH_DENV_NO_OVERRIDE", "from_env");

        load_dotenv(&dotenv).expect("load_dotenv");

        assert_eq!(
            std::env::var("HEARTH_DENV_NO_OVERRIDE").unwrap(),
            "from_env",
            "real env var must not be overwritten by .env"
        );
        std::env::remove_var("HEARTH_DENV_NO_OVERRIDE");
    }

    #[test]
    fn dotenv_skips_comments_and_blank_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dotenv = dir.path().join(".env");
        std::fs::write(
            &dotenv,
            "# This is a comment\n\nHEARTH_DENV_COMMENT_KEY=value\n# another comment\n",
        )
        .expect("write .env");
        std::env::remove_var("HEARTH_DENV_COMMENT_KEY");

        load_dotenv(&dotenv).expect("load_dotenv");

        assert_eq!(std::env::var("HEARTH_DENV_COMMENT_KEY").unwrap(), "value");
        std::env::remove_var("HEARTH_DENV_COMMENT_KEY");
    }

    #[test]
    fn dotenv_handles_double_quoted_values() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dotenv = dir.path().join(".env");
        std::fs::write(&dotenv, "HEARTH_DENV_DQ=\" hello world \"\n").expect("write .env");
        std::env::remove_var("HEARTH_DENV_DQ");

        load_dotenv(&dotenv).expect("load_dotenv");

        assert_eq!(std::env::var("HEARTH_DENV_DQ").unwrap(), " hello world ");
        std::env::remove_var("HEARTH_DENV_DQ");
    }

    #[test]
    fn dotenv_handles_double_quoted_escapes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dotenv = dir.path().join(".env");
        std::fs::write(&dotenv, r#"HEARTH_DENV_ESC="line1\nline2\ttab""#).expect("write .env");
        std::env::remove_var("HEARTH_DENV_ESC");

        load_dotenv(&dotenv).expect("load_dotenv");

        assert_eq!(
            std::env::var("HEARTH_DENV_ESC").unwrap(),
            "line1\nline2\ttab"
        );
        std::env::remove_var("HEARTH_DENV_ESC");
    }

    #[test]
    fn dotenv_handles_single_quoted_values() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dotenv = dir.path().join(".env");
        // Single-quoted: backslashes are literal, no escaping
        std::fs::write(&dotenv, "HEARTH_DENV_SQ='no\\escape'\n").expect("write .env");
        std::env::remove_var("HEARTH_DENV_SQ");

        load_dotenv(&dotenv).expect("load_dotenv");

        assert_eq!(std::env::var("HEARTH_DENV_SQ").unwrap(), r"no\escape");
        std::env::remove_var("HEARTH_DENV_SQ");
    }

    #[test]
    fn dotenv_handles_export_prefix() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dotenv = dir.path().join(".env");
        std::fs::write(&dotenv, "export HEARTH_DENV_EXPORT=exported\n").expect("write .env");
        std::env::remove_var("HEARTH_DENV_EXPORT");

        load_dotenv(&dotenv).expect("load_dotenv");

        assert_eq!(std::env::var("HEARTH_DENV_EXPORT").unwrap(), "exported");
        std::env::remove_var("HEARTH_DENV_EXPORT");
    }

    #[test]
    fn dotenv_strips_inline_comments_from_unquoted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dotenv = dir.path().join(".env");
        std::fs::write(&dotenv, "HEARTH_DENV_INLINE=myvalue # this is a comment\n")
            .expect("write .env");
        std::env::remove_var("HEARTH_DENV_INLINE");

        load_dotenv(&dotenv).expect("load_dotenv");

        assert_eq!(std::env::var("HEARTH_DENV_INLINE").unwrap(), "myvalue");
        std::env::remove_var("HEARTH_DENV_INLINE");
    }

    #[test]
    fn dotenv_missing_file_is_silently_ignored() {
        let result = load_dotenv(std::path::Path::new("/nonexistent/.env"));
        assert!(result.is_ok(), "missing .env must not be an error");
    }

    #[test]
    fn dotenv_malformed_line_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dotenv = dir.path().join(".env");
        std::fs::write(&dotenv, "GOOD=value\nBAD_LINE_NO_EQUALS\n").expect("write .env");

        let err = load_dotenv(&dotenv).expect_err("malformed line should error");
        let display = format!("{err}");
        assert!(
            display.contains("line 2"),
            "should report line number, got: {display}"
        );
    }

    #[test]
    fn dotenv_empty_key_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dotenv = dir.path().join(".env");
        std::fs::write(&dotenv, "=value\n").expect("write .env");

        let err = load_dotenv(&dotenv).expect_err("empty key should error");
        let display = format!("{err}");
        assert!(display.contains("key must not be empty"), "got: {display}");
    }
}
