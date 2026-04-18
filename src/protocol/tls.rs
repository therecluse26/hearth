//! TLS termination for the Hearth protocol layer.
//!
//! Provides PEM certificate/key loading, hot-reloadable TLS configuration via
//! [`ArcSwap`], and server config construction for `rustls`. The
//! [`ReloadableResolver`] implements [`rustls::server::ResolvesServerCert`] and
//! atomically swaps certificates on SIGHUP without dropping existing connections.

use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tracing::info;

/// Errors originating from TLS configuration and certificate handling.
#[derive(Debug)]
#[non_exhaustive]
pub enum TlsError {
    /// Failed to read a PEM file from disk.
    FileRead {
        /// The path that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The PEM file contained no certificates.
    NoCertificates {
        /// The path that contained no certs.
        path: PathBuf,
    },
    /// The PEM file contained no private key.
    NoPrivateKey {
        /// The path that contained no key.
        path: PathBuf,
    },
    /// Failed to build a signing key from the parsed private key.
    InvalidPrivateKey {
        /// Description of the failure.
        reason: String,
    },
    /// Failed to build the TLS server configuration.
    ConfigBuild {
        /// Description of the failure.
        reason: String,
    },
    /// Failed to load the client CA certificate for mTLS.
    ClientCa {
        /// Description of the failure.
        reason: String,
    },
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileRead { path, source } => {
                write!(f, "failed to read PEM file '{}': {source}", path.display())
            }
            Self::NoCertificates { path } => {
                write!(f, "no certificates found in '{}'", path.display())
            }
            Self::NoPrivateKey { path } => {
                write!(f, "no private key found in '{}'", path.display())
            }
            Self::InvalidPrivateKey { reason } => {
                write!(f, "invalid private key: {reason}")
            }
            Self::ConfigBuild { reason } => {
                write!(f, "failed to build TLS config: {reason}")
            }
            Self::ClientCa { reason } => {
                write!(f, "failed to load client CA: {reason}")
            }
        }
    }
}

impl std::error::Error for TlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::FileRead { source, .. } => Some(source),
            Self::NoCertificates { .. }
            | Self::NoPrivateKey { .. }
            | Self::InvalidPrivateKey { .. }
            | Self::ConfigBuild { .. }
            | Self::ClientCa { .. } => None,
        }
    }
}

/// Loads PEM-encoded certificates from a file.
///
/// Returns all certificates found in the file, in order. Returns an error
/// if the file cannot be read or contains no certificates.
pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let file = fs::File::open(path).map_err(|e| TlsError::FileRead {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::FileRead {
            path: path.to_path_buf(),
            source: e,
        })?;

    if certs.is_empty() {
        return Err(TlsError::NoCertificates {
            path: path.to_path_buf(),
        });
    }

    Ok(certs)
}

/// Loads a PEM-encoded private key from a file.
///
/// Supports PKCS#8, RSA, and EC private key formats. Returns the first
/// key found. Returns an error if the file cannot be read or contains no key.
pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let file = fs::File::open(path).map_err(|e| TlsError::FileRead {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut reader = BufReader::new(file);

    loop {
        match rustls_pemfile::read_one(&mut reader) {
            Ok(Some(rustls_pemfile::Item::Pkcs1Key(key))) => {
                return Ok(PrivateKeyDer::Pkcs1(key));
            }
            Ok(Some(rustls_pemfile::Item::Pkcs8Key(key))) => {
                return Ok(PrivateKeyDer::Pkcs8(key));
            }
            Ok(Some(rustls_pemfile::Item::Sec1Key(key))) => {
                return Ok(PrivateKeyDer::Sec1(key));
            }
            Ok(Some(_)) => {} // skip other PEM items (e.g. certs in the key file)
            Ok(None) => {
                return Err(TlsError::NoPrivateKey {
                    path: path.to_path_buf(),
                });
            }
            Err(e) => {
                return Err(TlsError::FileRead {
                    path: path.to_path_buf(),
                    source: e,
                });
            }
        }
    }
}

/// Builds a [`CertifiedKey`] from PEM files on disk.
fn build_certified_key(cert_path: &Path, key_path: &Path) -> Result<Arc<CertifiedKey>, TlsError> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|e| {
        TlsError::InvalidPrivateKey {
            reason: e.to_string(),
        }
    })?;

    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

/// Hot-reloadable TLS configuration.
///
/// Stores the current [`CertifiedKey`] in an [`ArcSwap`] for wait-free reads
/// during TLS handshakes. Calling [`reload`](Self::reload) re-reads PEM files
/// from disk and atomically swaps the certificate. On reload failure, the
/// previous certificate is preserved.
pub struct ReloadableTlsConfig {
    /// Atomically-swappable current certificate + signing key.
    certified_key: Arc<ArcSwap<CertifiedKey>>,
    /// Path to the PEM certificate file.
    cert_path: PathBuf,
    /// Path to the PEM private key file.
    key_path: PathBuf,
}

impl ReloadableTlsConfig {
    /// Loads TLS configuration from PEM files.
    ///
    /// Reads the certificate chain and private key, validates them, and
    /// stores them for use by [`ReloadableResolver`].
    pub fn load(cert_path: PathBuf, key_path: PathBuf) -> Result<Self, TlsError> {
        let certified_key = build_certified_key(&cert_path, &key_path)?;

        Ok(Self {
            certified_key: Arc::new(ArcSwap::from(certified_key)),
            cert_path,
            key_path,
        })
    }

    /// Re-reads PEM files from disk and atomically swaps the certificate.
    ///
    /// On success, all new TLS handshakes use the new certificate immediately.
    /// On failure, the previous certificate is preserved and the error is
    /// returned. Existing connections are unaffected either way.
    pub fn reload(&self) -> Result<(), TlsError> {
        let new_key = build_certified_key(&self.cert_path, &self.key_path)?;
        self.certified_key.store(new_key);
        info!("TLS certificate reloaded successfully");
        Ok(())
    }

    /// Creates a [`ReloadableResolver`] that reads from this config's
    /// [`ArcSwap`].
    pub fn resolver(&self) -> ReloadableResolver {
        ReloadableResolver {
            certified_key: Arc::clone(&self.certified_key),
        }
    }
}

/// A [`ResolvesServerCert`] implementation backed by [`ArcSwap`].
///
/// Performs a single atomic pointer load per TLS handshake — no locks,
/// no allocations, no syscalls. Safe for the hot path.
#[derive(Debug)]
pub struct ReloadableResolver {
    /// Shared pointer to the current certificate.
    certified_key: Arc<ArcSwap<CertifiedKey>>,
}

impl ResolvesServerCert for ReloadableResolver {
    fn resolve(&self, _client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.certified_key.load_full())
    }
}

/// Parameters for building a TLS [`ServerConfig`].
pub struct TlsConfigParams {
    /// The certificate resolver for the server.
    pub resolver: Arc<dyn ResolvesServerCert>,
    /// Optional path to a CA certificate for client certificate verification (mTLS).
    pub client_ca_path: Option<PathBuf>,
    /// Whether to require client certificates (mTLS).
    pub require_client_cert: bool,
}

/// Builds a [`rustls::ServerConfig`] with the given parameters.
///
/// Uses the default `ring` crypto provider. When `client_ca_path` is set and
/// `require_client_cert` is true, enables mutual TLS by configuring a
/// [`WebPkiClientVerifier`](rustls::server::WebPkiClientVerifier).
///
/// `rustls` structurally supports only TLS 1.2 and 1.3 — it does not implement
/// TLS 1.0/1.1, nor any weak cipher suites (RC4, DES, NULL, export).
pub fn build_server_config(params: TlsConfigParams) -> Result<ServerConfig, TlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let builder = if let Some(ca_path) = params.client_ca_path {
        let ca_certs = load_certs(&ca_path).map_err(|e| TlsError::ClientCa {
            reason: e.to_string(),
        })?;

        let mut root_store = rustls::RootCertStore::empty();
        for cert in ca_certs {
            root_store.add(cert).map_err(|e| TlsError::ClientCa {
                reason: e.to_string(),
            })?;
        }

        let verifier = if params.require_client_cert {
            rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(root_store),
                Arc::clone(&provider),
            )
            .build()
            .map_err(|e| TlsError::ClientCa {
                reason: e.to_string(),
            })?
        } else {
            rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(root_store),
                Arc::clone(&provider),
            )
            .allow_unauthenticated()
            .build()
            .map_err(|e| TlsError::ClientCa {
                reason: e.to_string(),
            })?
        };

        ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
            .map_err(|e| TlsError::ConfigBuild {
                reason: e.to_string(),
            })?
            .with_client_cert_verifier(verifier)
    } else {
        ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
            .map_err(|e| TlsError::ConfigBuild {
                reason: e.to_string(),
            })?
            .with_no_client_auth()
    };

    let mut config = builder.with_cert_resolver(params.resolver);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Helper: generates a self-signed certificate and key using rcgen,
    /// writes them to PEM files in the given directory.
    fn generate_test_certs(dir: &Path) -> (PathBuf, PathBuf) {
        let key_pair = rcgen::KeyPair::generate().expect("keygen");
        let cert_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        let cert = cert_params.self_signed(&key_pair).expect("self-sign");

        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");

        fs::write(&cert_path, cert.pem()).expect("write cert");
        fs::write(&key_path, key_pair.serialize_pem()).expect("write key");

        (cert_path, key_path)
    }

    /// Generates a self-signed CA certificate and key, writes to PEM files.
    fn generate_ca_cert(dir: &Path) -> (PathBuf, rcgen::KeyPair, rcgen::Certificate) {
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let ca_key = rcgen::KeyPair::generate().expect("ca keygen");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-sign");

        let ca_cert_path = dir.join("ca.pem");
        fs::write(&ca_cert_path, ca_cert.pem()).expect("write ca cert");

        (ca_cert_path, ca_key, ca_cert)
    }

    // === TEST_SCENARIOS: Load TLS certificate and private key from PEM files ===

    #[test]
    fn load_certs_success() {
        let dir = TempDir::new().expect("tempdir");
        let (cert_path, _key_path) = generate_test_certs(dir.path());

        let certs = load_certs(&cert_path).expect("load certs");
        assert!(!certs.is_empty(), "should load at least one certificate");
    }

    #[test]
    fn load_private_key_success() {
        let dir = TempDir::new().expect("tempdir");
        let (_cert_path, key_path) = generate_test_certs(dir.path());

        let key = load_private_key(&key_path);
        assert!(key.is_ok(), "should load private key");
    }

    #[test]
    fn load_certs_missing_file() {
        let result = load_certs(Path::new("/nonexistent/cert.pem"));
        assert!(result.is_err());
        let err = result.expect_err("should fail");
        let display = format!("{err}");
        assert!(display.contains("failed to read"), "got: {display}");
    }

    #[test]
    fn load_private_key_missing_file() {
        let result = load_private_key(Path::new("/nonexistent/key.pem"));
        assert!(result.is_err());
        let display = format!("{}", result.expect_err("should fail"));
        assert!(display.contains("failed to read"), "got: {display}");
    }

    #[test]
    fn load_certs_empty_pem() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("empty.pem");
        fs::write(&path, "not a real pem file\n").expect("write");

        let result = load_certs(&path);
        assert!(result.is_err());
        let display = format!("{}", result.expect_err("should fail"));
        assert!(display.contains("no certificates"), "got: {display}");
    }

    #[test]
    fn load_private_key_no_key_in_pem() {
        let dir = TempDir::new().expect("tempdir");
        // Write a cert PEM (no key) to the key path
        let (cert_path, _) = generate_test_certs(dir.path());
        let cert_pem = fs::read_to_string(&cert_path).expect("read cert");
        let no_key_path = dir.path().join("no_key.pem");
        fs::write(&no_key_path, cert_pem).expect("write");

        let result = load_private_key(&no_key_path);
        assert!(result.is_err());
        let display = format!("{}", result.expect_err("should fail"));
        assert!(display.contains("no private key"), "got: {display}");
    }

    #[test]
    fn reloadable_tls_config_load_success() {
        let dir = TempDir::new().expect("tempdir");
        let (cert_path, key_path) = generate_test_certs(dir.path());

        let config = ReloadableTlsConfig::load(cert_path, key_path);
        assert!(config.is_ok(), "should load config successfully");
    }

    // === TEST_SCENARIOS: Certificate hot-reload ===

    #[test]
    fn certificate_hot_reload() {
        let dir = TempDir::new().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        // Generate cert A and write to the paths
        let kp_a = rcgen::KeyPair::generate().expect("keygen A");
        let params_a =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params A");
        let cert_a = params_a.self_signed(&kp_a).expect("sign A");
        fs::write(&cert_path, cert_a.pem()).expect("write cert A");
        fs::write(&key_path, kp_a.serialize_pem()).expect("write key A");

        let config =
            ReloadableTlsConfig::load(cert_path.clone(), key_path.clone()).expect("load A");

        // Capture cert A's DER via the ArcSwap directly
        let der_a = {
            let guard = config.certified_key.load();
            guard.cert[0].as_ref().to_vec()
        };

        // Generate cert B and overwrite the files
        let kp_b = rcgen::KeyPair::generate().expect("keygen B");
        let params_b =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params B");
        let cert_b = params_b.self_signed(&kp_b).expect("sign B");
        fs::write(&cert_path, cert_b.pem()).expect("write cert B");
        fs::write(&key_path, kp_b.serialize_pem()).expect("write key B");

        // Reload
        config.reload().expect("reload");

        // Verify cert has changed
        let der_b = {
            let guard = config.certified_key.load();
            guard.cert[0].as_ref().to_vec()
        };

        assert_ne!(der_a, der_b, "cert should have changed after reload");
    }

    #[test]
    fn reload_failure_preserves_old_cert() {
        let dir = TempDir::new().expect("tempdir");
        let (cert_path, key_path) = generate_test_certs(dir.path());

        let config =
            ReloadableTlsConfig::load(cert_path.clone(), key_path.clone()).expect("initial load");

        // Capture original cert DER
        let original_der = {
            let guard = config.certified_key.load();
            guard.cert[0].as_ref().to_vec()
        };

        // Corrupt the cert file
        fs::write(&cert_path, "garbage data\n").expect("corrupt cert");

        // Reload should fail
        let result = config.reload();
        assert!(result.is_err(), "reload with corrupt cert should fail");

        // Old cert should still be in place
        let still_original_der = {
            let guard = config.certified_key.load();
            guard.cert[0].as_ref().to_vec()
        };

        assert_eq!(
            original_der, still_original_der,
            "failed reload should preserve old cert"
        );
    }

    // === TEST_SCENARIOS: TLS 1.3 negotiation + Weak cipher rejection ===

    #[test]
    fn build_server_config_success() {
        let dir = TempDir::new().expect("tempdir");
        let (cert_path, key_path) = generate_test_certs(dir.path());
        let tls_config = ReloadableTlsConfig::load(cert_path, key_path).expect("load config");

        let params = TlsConfigParams {
            resolver: Arc::new(tls_config.resolver()),
            client_ca_path: None,
            require_client_cert: false,
        };

        let server_config = build_server_config(params).expect("build config");

        // Verify ALPN protocols are set for h2 and http/1.1
        assert!(
            server_config.alpn_protocols.contains(&b"h2".to_vec()),
            "should support h2 ALPN"
        );
        assert!(
            server_config.alpn_protocols.contains(&b"http/1.1".to_vec()),
            "should support http/1.1 ALPN"
        );
    }

    #[test]
    fn no_weak_cipher_suites() {
        let dir = TempDir::new().expect("tempdir");
        let (cert_path, key_path) = generate_test_certs(dir.path());
        let tls_config = ReloadableTlsConfig::load(cert_path, key_path).expect("load config");

        let params = TlsConfigParams {
            resolver: Arc::new(tls_config.resolver()),
            client_ca_path: None,
            require_client_cert: false,
        };

        let server_config = build_server_config(params).expect("build config");

        // rustls does not implement any weak ciphers, but let's document and verify
        let weak_cipher_names = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5"];

        for suite in &server_config.crypto_provider().cipher_suites {
            let name = format!("{:?}", suite.suite());
            for weak in &weak_cipher_names {
                assert!(
                    !name.contains(weak),
                    "cipher suite {name} contains weak algorithm {weak}"
                );
            }
        }
    }

    /// Verifies that we configure both TLS 1.2 and TLS 1.3 by checking
    /// that the cipher suites include both TLS 1.2-specific and TLS 1.3-specific suites.
    #[test]
    fn supports_tls12_and_tls13_cipher_suites() {
        let dir = TempDir::new().expect("tempdir");
        let (cert_path, key_path) = generate_test_certs(dir.path());
        let tls_config = ReloadableTlsConfig::load(cert_path, key_path).expect("load config");

        let params = TlsConfigParams {
            resolver: Arc::new(tls_config.resolver()),
            client_ca_path: None,
            require_client_cert: false,
        };

        let server_config = build_server_config(params).expect("build config");

        let suite_names: Vec<String> = server_config
            .crypto_provider()
            .cipher_suites
            .iter()
            .map(|s| format!("{:?}", s.suite()))
            .collect();

        // TLS 1.3 suites contain "TLS13"
        let has_tls13 = suite_names.iter().any(|n| n.contains("TLS13"));
        assert!(
            has_tls13,
            "should have TLS 1.3 cipher suites: {suite_names:?}"
        );

        // TLS 1.2 suites contain "TLS_ECDHE"
        let has_tls12 = suite_names.iter().any(|n| n.contains("TLS_ECDHE"));
        assert!(
            has_tls12,
            "should have TLS 1.2 cipher suites: {suite_names:?}"
        );
    }

    // === mTLS config build ===

    #[test]
    fn build_server_config_with_mtls() {
        let dir = TempDir::new().expect("tempdir");
        let (cert_path, key_path) = generate_test_certs(dir.path());
        let (ca_cert_path, _ca_key, _ca_cert) = generate_ca_cert(dir.path());
        let tls_config = ReloadableTlsConfig::load(cert_path, key_path).expect("load config");

        let params = TlsConfigParams {
            resolver: Arc::new(tls_config.resolver()),
            client_ca_path: Some(ca_cert_path),
            require_client_cert: true,
        };

        let result = build_server_config(params);
        assert!(result.is_ok(), "should build mTLS config: {result:?}");
    }

    // === TlsError display ===

    #[test]
    fn tls_error_display() {
        let err = TlsError::NoCertificates {
            path: PathBuf::from("/tmp/test.pem"),
        };
        let display = format!("{err}");
        assert!(display.contains("no certificates"), "got: {display}");
        assert!(display.contains("/tmp/test.pem"), "got: {display}");

        let err2 = TlsError::InvalidPrivateKey {
            reason: "bad key".to_string(),
        };
        let display2 = format!("{err2}");
        assert!(display2.contains("invalid private key"), "got: {display2}");
    }
}
