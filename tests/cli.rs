//! CLI integration tests.
//!
//! Tests the `hearth` binary end-to-end by spawning it as a child process
//! and verifying behavior via HTTP requests and exit codes.
//!
//! Covers TEST\_SCENARIOS: CLI Tool (Integration)

use std::net::TcpListener;
use std::process::{Child, Command};
use std::time::Duration;

/// Finds an available TCP port by binding to port 0 and reading the assigned port.
fn find_available_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind to port 0");
    listener.local_addr().expect("local addr").port()
}

/// Guard that kills the server process on drop for test cleanup.
struct ServerGuard {
    child: Child,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Returns the path to the compiled `hearth` binary.
fn hearth_bin() -> std::path::PathBuf {
    // cargo nextest / cargo test puts the binary in target/debug
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

/// Starts the hearth server in dev mode on the given port.
fn start_server_dev(port: u16) -> ServerGuard {
    let child = Command::new(hearth_bin())
        .args(["serve", "--dev", "--port", &port.to_string()])
        .env("RUST_LOG", "info")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn hearth server");
    ServerGuard { child }
}

/// Waits for the server to accept TCP connections, polling up to `timeout`.
fn wait_for_server(port: u16, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

// === TEST_SCENARIOS: hearth serve --dev starts server and accepts connections ===

#[tokio::test]
async fn serve_dev_starts_and_accepts_connections() {
    let port = find_available_port();
    let _guard = start_server_dev(port);

    assert!(
        wait_for_server(port, Duration::from_secs(10)),
        "server should accept TCP connections within 10s"
    );

    // Verify a health endpoint responds
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/health"))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("health request");

    assert_eq!(resp.status(), 200, "health endpoint should return 200 OK");
}

#[tokio::test]
async fn serve_dev_exposes_oidc_discovery() {
    let port = find_available_port();
    let _guard = start_server_dev(port);

    assert!(
        wait_for_server(port, Duration::from_secs(10)),
        "server should accept TCP connections within 10s"
    );

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "http://127.0.0.1:{port}/.well-known/openid-configuration"
        ))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("discovery request");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("parse JSON");
    assert!(body.get("issuer").is_some(), "discovery should have issuer");
    assert!(
        body.get("jwks_uri").is_some(),
        "discovery should have jwks_uri"
    );
}

#[tokio::test]
async fn serve_dev_exposes_jwks() {
    let port = find_available_port();
    let _guard = start_server_dev(port);

    assert!(
        wait_for_server(port, Duration::from_secs(10)),
        "server should accept TCP connections within 10s"
    );

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/jwks"))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("jwks request");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("parse JSON");
    assert!(body.get("keys").is_some(), "JWKS should have keys array");
}

// === TEST_SCENARIOS: CLI exits with appropriate non-zero error codes ===

#[test]
fn cli_no_subcommand_exits_with_error() {
    let output = Command::new(hearth_bin())
        .output()
        .expect("run hearth without args");

    assert!(
        !output.status.success(),
        "hearth with no subcommand should exit non-zero"
    );
}

#[test]
fn cli_invalid_subcommand_exits_with_error() {
    let output = Command::new(hearth_bin())
        .arg("nonexistent-command")
        .output()
        .expect("run hearth with invalid subcommand");

    assert!(
        !output.status.success(),
        "hearth with invalid subcommand should exit non-zero"
    );
}

#[test]
fn cli_serve_invalid_port_exits_with_error() {
    let output = Command::new(hearth_bin())
        .args(["serve", "--port", "not-a-number"])
        .output()
        .expect("run hearth serve with invalid port");

    assert!(
        !output.status.success(),
        "hearth serve with invalid port should exit non-zero"
    );
}

#[test]
fn cli_serve_missing_config_file_exits_with_error() {
    let output = Command::new(hearth_bin())
        .args(["serve", "--config", "/nonexistent/hearth.yaml"])
        .output()
        .expect("run hearth serve with missing config");

    assert!(
        !output.status.success(),
        "hearth serve with missing config file should exit non-zero"
    );
}

// === TEST_SCENARIOS: CLI management commands ===

#[test]
fn cli_tenant_create_generates_uuid() {
    let output = Command::new(hearth_bin())
        .args(["tenant", "create"])
        .output()
        .expect("run hearth tenant create");

    assert!(
        output.status.success(),
        "tenant create should exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should output valid JSON with a tenant_id UUID
    let body: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("tenant create output should be JSON");
    let tenant_id = body["tenant_id"].as_str().expect("should have tenant_id");
    assert!(
        uuid::Uuid::parse_str(tenant_id).is_ok(),
        "tenant_id should be a valid UUID, got: {tenant_id}"
    );
}

#[tokio::test]
async fn cli_app_create_against_running_server() {
    let port = find_available_port();
    let _guard = start_server_dev(port);

    assert!(
        wait_for_server(port, Duration::from_secs(10)),
        "server should accept TCP connections within 10s"
    );

    // First create a tenant ID
    let tenant_output = Command::new(hearth_bin())
        .args(["tenant", "create"])
        .output()
        .expect("run hearth tenant create");
    assert!(
        tenant_output.status.success(),
        "tenant create should exit 0"
    );
    let tenant_body: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&tenant_output.stdout).trim())
            .expect("parse tenant JSON");
    let tenant_id = tenant_body["tenant_id"]
        .as_str()
        .expect("tenant_id")
        .to_string();

    // Register an app (OAuth client) via CLI
    let output = Command::new(hearth_bin())
        .args([
            "app",
            "create",
            "--server",
            &format!("http://127.0.0.1:{port}"),
            "--tenant-id",
            &tenant_id,
            "--name",
            "CLI Test App",
            "--redirect-uri",
            "https://cli-test.example.com/callback",
        ])
        .output()
        .expect("run hearth app create");

    assert!(
        output.status.success(),
        "app create should exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let body: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("app create output should be JSON");
    assert!(
        body["client_id"].as_str().is_some(),
        "should have client_id in output"
    );
    assert_eq!(
        body["client_name"].as_str().unwrap_or(""),
        "CLI Test App",
        "client_name should match"
    );
}
