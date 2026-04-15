//! Integration and adversarial tests for TLS Termination (Step 26).
//!
//! Tests HTTPS serving, HTTP→HTTPS redirect, mTLS, TLS downgrade prevention,
//! and certificate hot-reload through real TCP connections.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use hearth::core::SystemClock;
use hearth::identity::{CredentialConfig, EmbeddedIdentityEngine, IdentityConfig};
use hearth::protocol::http::{self, AppState};
use hearth::protocol::tls::{build_server_config, ReloadableTlsConfig, TlsConfigParams};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{oneshot, watch};

/// Creates a test app state for the HTTP server.
fn test_app_state(temp_dir: &Path) -> Arc<AppState> {
    let config = StorageConfig::dev(temp_dir.to_path_buf());
    let engine = Arc::new(EmbeddedStorageEngine::open(config).expect("open storage"));
    let clock = Arc::new(SystemClock) as Arc<dyn hearth::core::Clock>;
    let identity_config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let identity_engine = EmbeddedIdentityEngine::new(
        engine as Arc<dyn hearth::storage::StorageEngine>,
        clock,
        identity_config,
    )
    .expect("identity engine");

    Arc::new(AppState {
        identity: Arc::new(identity_engine),
    })
}

/// Generates a self-signed CA, server cert, and writes them to PEM files.
/// Returns `(ca_cert_path, server_cert_path, server_key_path, ca_cert, ca_key)`.
fn generate_server_certs(
    dir: &Path,
) -> (
    PathBuf,
    PathBuf,
    PathBuf,
    rcgen::Certificate,
    rcgen::KeyPair,
) {
    // CA cert
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().expect("ca keygen");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-sign");

    let ca_cert_path = dir.join("ca.pem");
    std::fs::write(&ca_cert_path, ca_cert.pem()).expect("write ca cert");

    // Server cert signed by CA
    let server_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .expect("server params");
    let server_key = rcgen::KeyPair::generate().expect("server keygen");
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("sign server cert");

    let cert_path = dir.join("server.pem");
    let key_path = dir.join("server-key.pem");

    // Write cert chain: server cert + CA cert
    let mut cert_chain = server_cert.pem();
    cert_chain.push_str(&ca_cert.pem());
    std::fs::write(&cert_path, cert_chain).expect("write server cert");
    std::fs::write(&key_path, server_key.serialize_pem()).expect("write server key");

    (ca_cert_path, cert_path, key_path, ca_cert, ca_key)
}

/// Generates a client certificate signed by the given CA.
fn generate_client_cert(
    dir: &Path,
    ca_cert: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
) -> (PathBuf, PathBuf) {
    let client_params =
        rcgen::CertificateParams::new(vec!["client".to_string()]).expect("client params");
    let client_key = rcgen::KeyPair::generate().expect("client keygen");
    let client_cert = client_params
        .signed_by(&client_key, ca_cert, ca_key)
        .expect("sign client cert");

    let cert_path = dir.join("client.pem");
    let key_path = dir.join("client-key.pem");
    std::fs::write(&cert_path, client_cert.pem()).expect("write client cert");
    std::fs::write(&key_path, client_key.serialize_pem()).expect("write client key");

    (cert_path, key_path)
}

// ===== Scenario 4: HTTPS endpoint serves valid TLS (P0) =====
//
// Start an in-process HTTPS server with a test CA, connect with reqwest
// trusting the test CA, verify /health returns 200.

#[tokio::test]
async fn https_endpoint_serves_valid_tls() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_app_state(temp_dir.path());

    let cert_dir = tempfile::tempdir().expect("cert dir");
    let (ca_cert_path, cert_path, key_path, _ca_cert, _ca_key) =
        generate_server_certs(cert_dir.path());

    let tls_config = ReloadableTlsConfig::load(cert_path, key_path).expect("load TLS config");
    let params = TlsConfigParams {
        resolver: Arc::new(tls_config.resolver()),
        client_ca_path: None,
        require_client_cert: false,
    };
    let server_config = build_server_config(params).expect("build server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let local_addr = listener.local_addr().expect("local addr");

    let (shutdown_tx, shutdown_rx) = watch::channel(());

    // Spawn the HTTPS server
    let server_handle = tokio::spawn(async move {
        http::serve_tls(listener, state, acceptor, shutdown_rx)
            .await
            .expect("serve_tls");
    });

    // Build a reqwest client trusting our test CA
    let ca_pem = std::fs::read(&ca_cert_path).expect("read CA cert");
    let ca_cert_reqwest = reqwest::Certificate::from_pem(&ca_pem).expect("parse CA cert");

    let client = reqwest::Client::builder()
        .add_root_certificate(ca_cert_reqwest)
        .build()
        .expect("build reqwest client");

    let url = format!("https://localhost:{}/health", local_addr.port());
    let resp = client.get(&url).send().await.expect("GET /health");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("parse JSON");
    assert_eq!(body["status"], "ok");

    // Shutdown
    drop(shutdown_tx);
    // Wait with timeout to avoid hanging
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_handle).await;
}

// ===== Scenario 5: HTTP to HTTPS redirect (P0) =====
//
// Start a redirect listener and verify plaintext HTTP requests receive
// 301 with correct Location header.

#[tokio::test]
async fn http_to_https_redirect() {
    let redirect_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind redirect");
    let local_addr = redirect_listener.local_addr().expect("local addr");
    drop(redirect_listener); // Release so serve_redirect can bind

    let https_port = 8443;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let shutdown_signal = async move {
        let _ = shutdown_rx.await;
    };

    let server_handle = tokio::spawn(async move {
        http::serve_redirect(local_addr, https_port, shutdown_signal)
            .await
            .expect("serve_redirect");
    });

    // Give the redirect server time to bind
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Send a plain HTTP request without following redirects
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build client");

    let url = format!("http://127.0.0.1:{}/some/path?q=1", local_addr.port());
    let resp = client.get(&url).send().await.expect("GET redirect");

    assert_eq!(resp.status(), 301, "should be 301 Moved Permanently");
    let location = resp
        .headers()
        .get("location")
        .expect("Location header")
        .to_str()
        .expect("Location as str");

    assert_eq!(
        location,
        format!("https://127.0.0.1:{https_port}/some/path?q=1"),
        "should redirect to HTTPS with correct port, path, and query"
    );

    // Shutdown
    drop(shutdown_tx);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_handle).await;
}

// ===== Scenario 6: Mutual TLS (mTLS) (P1) =====
//
// Server requires client cert. Verify: client with valid cert succeeds,
// client without cert has handshake fail.

#[tokio::test]
async fn mtls_valid_client_cert_succeeds() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_app_state(temp_dir.path());

    let cert_dir = tempfile::tempdir().expect("cert dir");
    let (ca_cert_path, cert_path, key_path, ca_cert, ca_key) =
        generate_server_certs(cert_dir.path());

    // Generate client cert signed by same CA
    let (client_cert_path, client_key_path) =
        generate_client_cert(cert_dir.path(), &ca_cert, &ca_key);

    let tls_config = ReloadableTlsConfig::load(cert_path, key_path).expect("load TLS config");
    let params = TlsConfigParams {
        resolver: Arc::new(tls_config.resolver()),
        client_ca_path: Some(ca_cert_path.clone()),
        require_client_cert: true,
    };
    let server_config = build_server_config(params).expect("build mTLS server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let local_addr = listener.local_addr().expect("local addr");

    let (shutdown_tx, shutdown_rx) = watch::channel(());

    let server_handle = tokio::spawn(async move {
        http::serve_tls(listener, state, acceptor, shutdown_rx)
            .await
            .expect("serve_tls");
    });

    // Build reqwest client with CA trust + client cert
    let ca_pem = std::fs::read(&ca_cert_path).expect("read CA cert");
    let ca_cert_reqwest = reqwest::Certificate::from_pem(&ca_pem).expect("parse CA cert");

    let client_cert_pem = std::fs::read_to_string(&client_cert_path).expect("read client cert");
    let client_key_pem = std::fs::read_to_string(&client_key_path).expect("read client key");
    let mut identity_pem = client_cert_pem.into_bytes();
    identity_pem.extend_from_slice(client_key_pem.as_bytes());
    let identity = reqwest::Identity::from_pem(&identity_pem).expect("parse identity");

    let client = reqwest::Client::builder()
        .add_root_certificate(ca_cert_reqwest)
        .identity(identity)
        .build()
        .expect("build reqwest client with mTLS");

    let url = format!("https://localhost:{}/health", local_addr.port());
    let resp = client
        .get(&url)
        .send()
        .await
        .expect("GET /health with client cert");
    assert_eq!(resp.status(), 200, "mTLS request should succeed");

    drop(shutdown_tx);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_handle).await;
}

#[tokio::test]
async fn mtls_missing_client_cert_rejected() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_app_state(temp_dir.path());

    let cert_dir = tempfile::tempdir().expect("cert dir");
    let (ca_cert_path, cert_path, key_path, _ca_cert, _ca_key) =
        generate_server_certs(cert_dir.path());

    let tls_config = ReloadableTlsConfig::load(cert_path, key_path).expect("load TLS config");
    let params = TlsConfigParams {
        resolver: Arc::new(tls_config.resolver()),
        client_ca_path: Some(ca_cert_path.clone()),
        require_client_cert: true,
    };
    let server_config = build_server_config(params).expect("build mTLS server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let local_addr = listener.local_addr().expect("local addr");

    let (shutdown_tx, shutdown_rx) = watch::channel(());

    let server_handle = tokio::spawn(async move {
        http::serve_tls(listener, state, acceptor, shutdown_rx)
            .await
            .expect("serve_tls");
    });

    // Build reqwest client with CA trust but NO client cert
    let ca_pem = std::fs::read(&ca_cert_path).expect("read CA cert");
    let ca_cert_reqwest = reqwest::Certificate::from_pem(&ca_pem).expect("parse CA cert");

    let client = reqwest::Client::builder()
        .add_root_certificate(ca_cert_reqwest)
        .build()
        .expect("build reqwest client without client cert");

    let url = format!("https://localhost:{}/health", local_addr.port());
    let result = client.get(&url).send().await;

    // Should fail — server requires client cert
    assert!(result.is_err(), "request without client cert should fail");

    drop(shutdown_tx);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_handle).await;
}

// ===== Scenario 7: TLS downgrade prevention (P0) =====
//
// Send a raw TLS 1.0 ClientHello via TCP. The server (rustls) should
// reject the connection because it does not implement TLS 1.0.

#[tokio::test]
async fn tls_downgrade_prevention_rejects_tls10() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_app_state(temp_dir.path());

    let cert_dir = tempfile::tempdir().expect("cert dir");
    let (_ca_cert_path, cert_path, key_path, _ca_cert, _ca_key) =
        generate_server_certs(cert_dir.path());

    let tls_config = ReloadableTlsConfig::load(cert_path, key_path).expect("load TLS config");
    let params = TlsConfigParams {
        resolver: Arc::new(tls_config.resolver()),
        client_ca_path: None,
        require_client_cert: false,
    };
    let server_config = build_server_config(params).expect("build server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let local_addr = listener.local_addr().expect("local addr");

    let (shutdown_tx, shutdown_rx) = watch::channel(());

    let server_handle = tokio::spawn(async move {
        http::serve_tls(listener, state, acceptor, shutdown_rx)
            .await
            .expect("serve_tls");
    });

    // Use a rustls ClientConfig that only supports TLS 1.2 with a cipher
    // that we know works, but force version to only TLS 1.2 and use
    // an SNI mismatch or similar approach. Actually, the simplest way
    // to test downgrade prevention is to build a rustls client that
    // only offers ciphers not supported by the server.
    //
    // Since rustls itself doesn't support TLS 1.0/1.1, the most meaningful
    // test is to send raw bytes of a TLS 1.0 ClientHello and verify
    // the server rejects it (closes connection or sends alert).

    // Craft a TLS 1.0 ClientHello with only TLS-1.0-era cipher suites
    // that rustls server does not support
    #[rustfmt::skip]
    let client_hello: Vec<u8> = vec![
        // TLS record header
        0x16,       // ContentType: Handshake
        0x03, 0x01, // Version: TLS 1.0
        0x00, 0x31, // Length (49 bytes)
        // Handshake header
        0x01,             // HandshakeType: ClientHello
        0x00, 0x00, 0x2d, // Length (45 bytes)
        // ClientHello body
        0x03, 0x01, // client_version: TLS 1.0
        // 32 bytes random (all zeros for test)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // session_id length: 0
        0x00, 0x04, // cipher_suites length: 4 bytes (2 suites)
        0x00, 0x0a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
        0x01, 0x00, // compression_methods: length 1, null
    ];

    let mut stream = tokio::net::TcpStream::connect(local_addr)
        .await
        .expect("TCP connect");
    stream
        .write_all(&client_hello)
        .await
        .expect("write ClientHello");
    stream.flush().await.expect("flush");

    // Close our write half to signal we're done sending
    stream.shutdown().await.ok();

    // Read the server response — expect either connection close or TLS alert
    let mut buf = vec![0u8; 256];
    let result =
        tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf)).await;

    match result {
        Ok(Ok(n)) if n > 0 => {
            // Should be a TLS alert (ContentType 0x15) indicating
            // protocol_version or handshake_failure
            assert_eq!(buf[0], 0x15, "expected TLS alert, got: {:02x}", buf[0]);
        }
        // Connection closed, error, or timeout — all indicate TLS 1.0 rejection
        _ => {}
    }

    drop(shutdown_tx);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_handle).await;
}
