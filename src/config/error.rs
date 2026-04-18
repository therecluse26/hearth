//! Configuration error types.

use std::fmt;

/// Errors originating from configuration loading and validation.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConfigError {
    /// Failed to read the configuration file from disk.
    FileRead(std::io::Error),
    /// The YAML content could not be parsed.
    ParseError(String),
    /// An environment variable referenced in the config is not set.
    MissingEnvVar {
        /// The name of the missing environment variable.
        var_name: String,
    },
    /// A line in a `.env` file could not be parsed.
    DotenvParse {
        /// 1-based line number in the `.env` file.
        line: usize,
        /// Description of the parse failure.
        message: String,
    },
    /// A configuration value failed validation.
    ValidationError {
        /// The config field that failed validation.
        field: String,
        /// Description of why the value is invalid.
        reason: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileRead(err) => write!(f, "failed to read configuration file: {err}"),
            Self::ParseError(msg) => write!(f, "failed to parse configuration: {msg}"),
            Self::MissingEnvVar { var_name } => {
                write!(f, "environment variable not set: {var_name}")
            }
            Self::DotenvParse { line, message } => {
                write!(f, "failed to parse .env file at line {line}: {message}")
            }
            Self::ValidationError { field, reason } => {
                write!(f, "invalid configuration for '{field}': {reason}")
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::FileRead(err) => Some(err),
            Self::ParseError(_)
            | Self::MissingEnvVar { .. }
            | Self::DotenvParse { .. }
            | Self::ValidationError { .. } => None,
        }
    }
}

impl From<std::io::Error> for ConfigError {
    fn from(err: std::io::Error) -> Self {
        Self::FileRead(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn config_error_display_and_trait() {
        let err = ConfigError::FileRead(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "config.yaml not found",
        ));
        let display = format!("{err}");
        assert!(display.contains("read configuration"), "got: {display}");
        assert!(display.contains("not found"), "got: {display}");

        let err2 = ConfigError::ParseError("unexpected token".to_string());
        let display2 = format!("{err2}");
        assert!(display2.contains("parse"), "got: {display2}");
        assert!(display2.contains("unexpected token"), "got: {display2}");

        let err3 = ConfigError::MissingEnvVar {
            var_name: "HEARTH_SECRET".to_string(),
        };
        let display3 = format!("{err3}");
        assert!(display3.contains("HEARTH_SECRET"), "got: {display3}");

        let err4 = ConfigError::ValidationError {
            field: "server.port".to_string(),
            reason: "must be between 1 and 65535".to_string(),
        };
        let display4 = format!("{err4}");
        assert!(display4.contains("server.port"), "got: {display4}");
        assert!(display4.contains("65535"), "got: {display4}");

        // Verify it implements std::error::Error
        let _: &dyn std::error::Error = &err4;

        // Verify source chaining for FileRead
        let io_err = ConfigError::FileRead(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "access denied",
        ));
        assert!(io_err.source().is_some());
        assert!(err4.source().is_none());
    }
}
