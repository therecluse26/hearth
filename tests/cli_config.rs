//! CLI integration tests for `hearth config validate` and `hearth config example`.
//!
//! Spawns the compiled binary as a child process and verifies exit codes,
//! stdout/stderr content, and output validity.
//!
//! Covers TEST_SCENARIOS: hearth config validate / hearth config example

use std::process::Command;

/// Returns the path to the compiled `hearth` binary.
fn hearth_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe()
        .expect("current exe")
        .parent()
        .expect("parent dir")
        .parent()
        .expect("grandparent dir")
        .to_path_buf();
    path.push("hearth");
    path
}

// === hearth config validate ===

/// A minimal valid production config (data_dir prevents the empty-dir error).
const VALID_CONFIG: &str = r#"
storage:
  data_dir: "/tmp/hearth-test"
oidc:
  issuer: "https://auth.example.com"
"#;

/// Config with an invalid field (empty data_dir triggers a validation error).
const INVALID_CONFIG_EMPTY_DATA_DIR: &str = r#"
storage:
  data_dir: ""
"#;

/// Config with a bad SMTP block — missing smtp section when transport = smtp.
const INVALID_CONFIG_SMTP_MISSING_BLOCK: &str = r#"
storage:
  data_dir: "/tmp/hearth-test"
oidc:
  issuer: "https://auth.example.com"
email:
  transport: smtp
  from: "auth@example.com"
"#;

#[test]
fn validate_returns_0_for_valid_config() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("hearth.yaml");
    std::fs::write(&config_path, VALID_CONFIG).expect("write config");

    let status = Command::new(hearth_bin())
        .args([
            "config",
            "validate",
            config_path.to_str().expect("valid UTF-8 path"),
        ])
        .status()
        .expect("spawn hearth");

    assert!(
        status.success(),
        "hearth config validate should exit 0 for a valid config"
    );
}

#[test]
fn validate_prints_summary_on_success() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("hearth.yaml");
    std::fs::write(&config_path, VALID_CONFIG).expect("write config");

    let output = Command::new(hearth_bin())
        .args([
            "config",
            "validate",
            config_path.to_str().expect("valid UTF-8 path"),
        ])
        .output()
        .expect("spawn hearth");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Configuration valid"),
        "stdout should contain 'Configuration valid', got: {stdout}"
    );
    assert!(
        stdout.contains("storage:") || stdout.contains("/tmp/hearth-test"),
        "stdout should include storage path summary, got: {stdout}"
    );
    assert!(
        stdout.contains("email transport:"),
        "stdout should include email transport, got: {stdout}"
    );
    assert!(
        stdout.contains("TLS:"),
        "stdout should include TLS mode, got: {stdout}"
    );
}

#[test]
fn validate_returns_1_for_empty_data_dir() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("hearth.yaml");
    std::fs::write(&config_path, INVALID_CONFIG_EMPTY_DATA_DIR).expect("write config");

    let output = Command::new(hearth_bin())
        .args([
            "config",
            "validate",
            config_path.to_str().expect("valid UTF-8 path"),
        ])
        .output()
        .expect("spawn hearth");

    assert!(
        !output.status.success(),
        "hearth config validate should exit 1 for invalid config"
    );
    assert_eq!(output.status.code(), Some(1));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid") || stderr.contains("storage.data_dir"),
        "stderr should mention the invalid field, got: {stderr}"
    );
}

#[test]
fn validate_returns_1_for_missing_smtp_block() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("hearth.yaml");
    std::fs::write(&config_path, INVALID_CONFIG_SMTP_MISSING_BLOCK).expect("write config");

    let output = Command::new(hearth_bin())
        .args([
            "config",
            "validate",
            config_path.to_str().expect("valid UTF-8 path"),
        ])
        .output()
        .expect("spawn hearth");

    assert!(
        !output.status.success(),
        "hearth config validate should exit 1 for smtp without smtp block"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("email.smtp"),
        "stderr should mention email.smtp, got: {stderr}"
    );
}

#[test]
fn validate_returns_1_for_bad_yaml_syntax() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("hearth.yaml");
    std::fs::write(&config_path, "server:\n  port: [unclosed").expect("write config");

    let status = Command::new(hearth_bin())
        .args([
            "config",
            "validate",
            config_path.to_str().expect("valid UTF-8 path"),
        ])
        .status()
        .expect("spawn hearth");

    assert_eq!(status.code(), Some(1), "bad YAML should exit 1");
}

#[test]
fn validate_returns_1_for_nonexistent_file() {
    let status = Command::new(hearth_bin())
        .args(["config", "validate", "/nonexistent/hearth.yaml"])
        .status()
        .expect("spawn hearth");

    assert_eq!(status.code(), Some(1));
}

// === hearth config example ===

#[test]
fn example_output_is_valid_yaml() {
    let output = Command::new(hearth_bin())
        .args(["config", "example"])
        .output()
        .expect("spawn hearth");

    assert!(
        output.status.success(),
        "hearth config example should exit 0"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.is_empty(),
        "hearth config example should produce output"
    );

    // The example YAML must parse successfully.
    let parsed: serde_yaml::Value =
        serde_yaml::from_str(&stdout).expect("example output must be valid YAML");
    assert!(
        parsed.is_mapping(),
        "example YAML root must be a mapping, got: {parsed:?}"
    );
}

#[test]
fn example_output_contains_key_sections() {
    let output = Command::new(hearth_bin())
        .args(["config", "example"])
        .output()
        .expect("spawn hearth");

    let stdout = String::from_utf8_lossy(&output.stdout);

    for section in &["server:", "storage:", "observability:", "email:"] {
        assert!(
            stdout.contains(section),
            "example YAML should contain section '{section}'"
        );
    }
}

#[test]
fn example_output_file_option_writes_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_path = dir.path().join("hearth.yaml");

    let status = Command::new(hearth_bin())
        .args([
            "config",
            "example",
            "--output",
            out_path.to_str().expect("valid UTF-8 path"),
        ])
        .status()
        .expect("spawn hearth");

    assert!(
        status.success(),
        "hearth config example --output should exit 0"
    );

    let content = std::fs::read_to_string(&out_path).expect("output file should exist");
    assert!(!content.is_empty(), "output file should not be empty");

    // The written file must also parse as valid YAML.
    serde_yaml::from_str::<serde_yaml::Value>(&content)
        .expect("written example must be valid YAML");
}

#[test]
fn example_written_config_passes_validate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("hearth.yaml");

    // Generate the example
    Command::new(hearth_bin())
        .args([
            "config",
            "example",
            "--output",
            config_path.to_str().expect("valid UTF-8 path"),
        ])
        .status()
        .expect("spawn hearth for example");

    // The example YAML must pass validate
    let validate_status = Command::new(hearth_bin())
        .args([
            "config",
            "validate",
            config_path.to_str().expect("valid UTF-8 path"),
        ])
        .status()
        .expect("spawn hearth for validate");

    assert!(
        validate_status.success(),
        "the generated example config should pass validate"
    );
}
