//! Configuration section structs.
//!
//! Each section implements `Default` with production-safe values and
//! `Deserialize` for YAML parsing. `#[serde(default)]` on each section
//! means partial YAML files work seamlessly.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

use crate::identity::claims_config::ClaimMapping;
use crate::identity::email::EmailBranding;
use crate::identity::ClientTrustLevel;
use crate::rbac::{
    Permission, PermissionDefinition, ProtectedResource, Role, RoleId, RoleScopeKind, ScopeBundle,
};

/// Server network configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Address to bind the server to.
    #[serde(default = "ServerConfig::default_bind_address")]
    pub bind_address: String,
    /// Port to listen on.
    #[serde(default = "ServerConfig::default_port")]
    pub port: u16,
    /// Path to TLS certificate file (optional; no TLS if absent).
    pub tls_cert_path: Option<PathBuf>,
    /// Path to TLS private key file (optional; no TLS if absent).
    pub tls_key_path: Option<PathBuf>,
    /// Path to a CA certificate for client certificate verification (mTLS).
    pub tls_client_ca_path: Option<PathBuf>,
    /// Whether to require a client certificate (mTLS). Requires `tls_client_ca_path`.
    #[serde(default)]
    pub tls_require_client_cert: bool,
    /// Trusted reverse proxy IP addresses (CIDR notation not yet supported).
    ///
    /// When configured, the server extracts the real client IP from the
    /// `X-Forwarded-For` header using the rightmost-non-trusted algorithm.
    /// When empty (default), the peer socket IP is used directly and XFF is
    /// ignored — the safe default for direct-to-internet deployments.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Name of the realm to use when a bare `/ui/*` URL is hit on a
    /// multi-realm deployment.
    ///
    /// Resolution order for pre-auth pages:
    /// 1. Explicit `/ui/realms/<name>/...` path wins.
    /// 2. On single-realm deployments the sole realm is used implicitly.
    /// 3. Multi-realm + `default_realm` set → that realm is used.
    /// 4. Multi-realm + `default_realm` unset → `/ui/login` (etc.) shows
    ///    a realm picker; POSTs return 400.
    ///
    /// Validated at startup: if set, the named realm MUST exist after
    /// realm reconciliation runs, else the server refuses to start.
    #[serde(default)]
    pub default_realm: Option<String>,
    /// Port for the gRPC management API. When `None` (the default), the
    /// gRPC server is not started — REST-only deployments are unaffected.
    #[serde(default)]
    pub grpc_port: Option<u16>,
    /// Optional bind address for the gRPC listener. Defaults to
    /// `bind_address` when unset.
    #[serde(default)]
    pub grpc_bind_address: Option<String>,
    /// Filesystem directory containing the admin UI's mutable static
    /// assets — currently only `app.css` (the Tailwind build output).
    ///
    /// When set, [`crate::protocol::web::serve_static`] reads
    /// `<assets_dir>/app.css` once at server startup; restarting the
    /// server picks up a fresh Tailwind build without recompiling Rust.
    /// When `None` (the default) the binary serves the copy embedded by
    /// `include_bytes!` at compile time.
    ///
    /// Path resolution: relative paths are interpreted relative to the
    /// process working directory. A typical container layout exposes
    /// `/etc/hearth/assets/` and points this at it.
    ///
    /// Other static assets (`htmx.min.js`, the Hearth SVG marks) remain
    /// truly immutable for a binary's lifetime and stay embedded.
    #[serde(default)]
    pub assets_dir: Option<PathBuf>,
    /// Trust `X-Forwarded-Proto: https` from reverse proxies listed in
    /// `trusted_proxies`.
    ///
    /// When `true`, session cookies gain the `Secure` attribute when the
    /// forwarded proto header indicates HTTPS.  Only enable when
    /// `trusted_proxies` is properly configured.
    #[serde(default)]
    pub trust_forwarded_proto: bool,
}

impl ServerConfig {
    fn default_bind_address() -> String {
        "127.0.0.1".to_string()
    }

    const fn default_port() -> u16 {
        8420
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: Self::default_bind_address(),
            port: Self::default_port(),
            tls_cert_path: None,
            tls_key_path: None,
            tls_client_ca_path: None,
            tls_require_client_cert: false,
            trusted_proxies: Vec::new(),
            default_realm: None,
            grpc_port: None,
            grpc_bind_address: None,
            assets_dir: None,
            trust_forwarded_proto: false,
        }
    }
}

/// Background SST compaction configuration (all fields optional).
#[derive(Debug, Clone, Deserialize)]
pub struct CompactionSection {
    /// Whether automatic background compaction is enabled.
    #[serde(default = "CompactionSection::default_enabled")]
    pub enabled: bool,
    /// Seconds between periodic compaction sweeps.
    #[serde(default = "CompactionSection::default_interval_secs")]
    pub interval_secs: u64,
    /// Minimum SST files before a compaction is attempted.
    #[serde(default = "CompactionSection::default_min_sst_count")]
    pub min_sst_count: usize,
}

impl Default for CompactionSection {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 3600,
            min_sst_count: 3,
        }
    }
}

impl CompactionSection {
    const fn default_enabled() -> bool {
        true
    }
    const fn default_interval_secs() -> u64 {
        3600
    }
    const fn default_min_sst_count() -> usize {
        3
    }
}

/// Storage engine configuration.
///
/// These values control WAL, memtable, and hot tier behavior.
/// Distinct from `storage::StorageConfig` — conversion happens in main.rs wiring.
#[derive(Debug, Clone, Deserialize)]
pub struct StorageSection {
    /// Directory for data files (WAL, SSTs).
    #[serde(default = "StorageSection::default_data_dir")]
    pub data_dir: String,
    /// Maximum WAL file size in bytes before rotation.
    #[serde(default = "StorageSection::default_wal_max_size_bytes")]
    pub wal_max_size_bytes: u64,
    /// Memtable size threshold in bytes before flush to SST.
    #[serde(default = "StorageSection::default_memtable_flush_bytes")]
    pub memtable_flush_bytes: u64,
    /// Maximum number of entries in the hot tier cache.
    /// When `None` (default), auto-sizes from system memory or
    /// `hot_tier_max_memory`. When `Some(n)`, uses this exact count,
    /// bypassing auto-sizing.
    #[serde(default)]
    pub hot_tier_capacity: Option<usize>,
    /// Hot tier memory budget in bytes. When set, overrides the
    /// system-detected memory budget used during auto-sizing.
    /// Ignored when `hot_tier_capacity` is `Some(n)`.
    #[serde(default)]
    pub hot_tier_max_memory: Option<usize>,
    /// Whether to fsync WAL writes. MUST be true in production.
    #[serde(default = "StorageSection::default_fsync")]
    pub fsync: bool,
    /// Background SST compaction (all fields optional).
    #[serde(default)]
    pub compaction: CompactionSection,
}

impl StorageSection {
    fn default_data_dir() -> String {
        "./data".to_string()
    }

    const fn default_wal_max_size_bytes() -> u64 {
        256 * 1024 * 1024 // 256 MiB
    }

    const fn default_memtable_flush_bytes() -> u64 {
        64 * 1024 * 1024 // 64 MiB
    }

    const fn default_fsync() -> bool {
        true
    }
}

impl Default for StorageSection {
    fn default() -> Self {
        Self {
            data_dir: Self::default_data_dir(),
            wal_max_size_bytes: Self::default_wal_max_size_bytes(),
            memtable_flush_bytes: Self::default_memtable_flush_bytes(),
            hot_tier_capacity: None,
            hot_tier_max_memory: None,
            fsync: Self::default_fsync(),
            compaction: CompactionSection::default(),
        }
    }
}

/// Metrics endpoint configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    /// Whether to expose the Prometheus `/metrics` HTTP endpoint.
    ///
    /// Set to `false` to disable the endpoint (e.g., when metrics are
    /// collected via a sidecar instead of a direct scrape).
    #[serde(default = "MetricsConfig::default_enabled")]
    pub enabled: bool,
}

impl MetricsConfig {
    const fn default_enabled() -> bool {
        true
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
        }
    }
}

/// OTLP transport protocol.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OtlpProtocol {
    /// gRPC transport (default, port 4317).
    #[default]
    Grpc,
    /// HTTP/protobuf transport (port 4318).
    Http,
}

/// OpenTelemetry OTLP export configuration.
///
/// When present under `observability.otlp`, Hearth ships spans to the
/// configured collector endpoint via gRPC or HTTP.
#[derive(Debug, Clone, Deserialize)]
pub struct OtlpConfig {
    /// Collector endpoint URL.
    ///
    /// Defaults to `http://localhost:4317` for gRPC and
    /// `http://localhost:4318` for HTTP when omitted.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Transport protocol: `grpc` (default) or `http`.
    #[serde(default)]
    pub protocol: OtlpProtocol,
    /// Additional request headers forwarded to the collector.
    ///
    /// Useful for authentication tokens required by managed collectors.
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    /// `service.name` resource attribute reported in every span.
    #[serde(default = "OtlpConfig::default_service_name")]
    pub service_name: String,
}

impl OtlpConfig {
    fn default_service_name() -> String {
        "hearth".to_string()
    }

    /// Effective endpoint URL, substituting the protocol-specific default.
    pub fn effective_endpoint(&self) -> String {
        if let Some(ep) = &self.endpoint {
            return ep.clone();
        }
        match self.protocol {
            OtlpProtocol::Grpc => "http://localhost:4317".to_string(),
            OtlpProtocol::Http => "http://localhost:4318".to_string(),
        }
    }
}

/// Observability (logging and tracing) configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ObservabilityConfig {
    /// Tracing log level filter (trace, debug, info, warn, error).
    #[serde(default = "ObservabilityConfig::default_log_level")]
    pub log_level: String,
    /// Log output format: "text" or "json".
    #[serde(default = "ObservabilityConfig::default_log_format")]
    pub log_format: String,
    /// Optional OTLP export. When absent, no spans are exported.
    #[serde(default)]
    pub otlp: Option<OtlpConfig>,
}

impl ObservabilityConfig {
    fn default_log_level() -> String {
        "info".to_string()
    }

    fn default_log_format() -> String {
        "text".to_string()
    }

    /// Valid log level strings.
    pub(crate) const VALID_LOG_LEVELS: &'static [&'static str] =
        &["trace", "debug", "info", "warn", "error"];

    /// Valid log format strings.
    pub(crate) const VALID_LOG_FORMATS: &'static [&'static str] = &["text", "json"];
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            log_level: Self::default_log_level(),
            log_format: Self::default_log_format(),
            otlp: None,
        }
    }
}

/// Operational limits and timeouts.
#[derive(Debug, Clone, Deserialize)]
pub struct OperationalConfig {
    /// Request timeout in seconds.
    #[serde(default = "OperationalConfig::default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    /// Graceful shutdown timeout in seconds.
    #[serde(default = "OperationalConfig::default_shutdown_timeout_secs")]
    pub shutdown_timeout_secs: u64,
    /// Maximum concurrent connections.
    #[serde(default = "OperationalConfig::default_max_connections")]
    pub max_connections: u32,
    /// Internal work queue depth.
    #[serde(default = "OperationalConfig::default_queue_depth")]
    pub queue_depth: u32,
}

impl OperationalConfig {
    const fn default_request_timeout_secs() -> u64 {
        30
    }

    const fn default_shutdown_timeout_secs() -> u64 {
        10
    }

    const fn default_max_connections() -> u32 {
        1024
    }

    const fn default_queue_depth() -> u32 {
        4096
    }
}

impl Default for OperationalConfig {
    fn default() -> Self {
        Self {
            request_timeout_secs: Self::default_request_timeout_secs(),
            shutdown_timeout_secs: Self::default_shutdown_timeout_secs(),
            max_connections: Self::default_max_connections(),
            queue_depth: Self::default_queue_depth(),
        }
    }
}

/// Email delivery transport selector.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EmailTransport {
    /// Write email contents (subject, recipient, verification URL) to the
    /// `tracing` log at WARN level. No external delivery. Default.
    #[default]
    Log,
    /// Deliver via SMTP to an external mail server. Requires an
    /// accompanying [`SmtpConfig`] block and a `from` address.
    Smtp,
    /// Deliver via the `SendGrid` v3 API. Requires a [`SendgridConfig`].
    Sendgrid,
    /// Deliver via the `Postmark` API. Requires a [`PostmarkConfig`].
    Postmark,
    /// Deliver via the `Mailgun` API. Requires a [`MailgunConfig`].
    Mailgun,
    /// Deliver via the `Mailtrap` Sending API. Requires a [`MailtrapConfig`].
    Mailtrap,
}

/// SMTP transport-level encryption mode.
///
/// Mirrors the semantics of `lettre::transport::smtp::client::Tls`:
///
/// - [`SmtpEncryption::None`] — cleartext SMTP (e.g. a local Mailpit
///   on `:1025`). Never use over untrusted networks.
/// - [`SmtpEncryption::Starttls`] — explicit TLS upgrade (RFC 3207) on
///   the submission port. Default; matches modern providers on :587.
/// - [`SmtpEncryption::Tls`] — implicit TLS (RFC 8314), historically
///   "SMTPS" on :465.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SmtpEncryption {
    /// Plaintext SMTP. No encryption.
    None,
    /// Explicit TLS upgrade via STARTTLS. Default.
    #[default]
    Starttls,
    /// Implicit TLS (SMTPS).
    Tls,
}

/// SMTP transport settings.
///
/// Required when [`EmailTransport::Smtp`] is selected. Credentials are
/// optional; if `username` is set then `password` MUST also be set (and
/// vice versa) — the config validator enforces the pair.
#[derive(Debug, Clone, Deserialize)]
pub struct SmtpConfig {
    /// SMTP server hostname (e.g. `smtp.example.com`, `mailpit`).
    pub host: String,
    /// SMTP server port (typically 25, 465, 587, or 1025 for Mailpit).
    pub port: u16,
    /// Transport-level encryption mode. Defaults to `starttls`.
    #[serde(default)]
    pub encryption: SmtpEncryption,
    /// SMTP AUTH username. When `Some`, `password` MUST also be `Some`.
    #[serde(default)]
    pub username: Option<String>,
    /// SMTP AUTH password. Must accompany `username`.
    #[serde(default)]
    pub password: Option<String>,
}

/// `SendGrid` transport settings.
///
/// Required when [`EmailTransport::Sendgrid`] is selected.
#[derive(Debug, Clone, Deserialize)]
pub struct SendgridConfig {
    /// `SendGrid` API key.
    pub api_key: String,
}

/// `Postmark` transport settings.
///
/// Required when [`EmailTransport::Postmark`] is selected.
#[derive(Debug, Clone, Deserialize)]
pub struct PostmarkConfig {
    /// `Postmark` server token.
    pub server_token: String,
}

/// `Mailgun` region selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MailgunRegion {
    /// US region (default).
    #[default]
    Us,
    /// EU region.
    Eu,
}

/// `Mailgun` transport settings.
///
/// Required when [`EmailTransport::Mailgun`] is selected.
#[derive(Debug, Clone, Deserialize)]
pub struct MailgunConfig {
    /// `Mailgun` API key.
    pub api_key: String,
    /// `Mailgun` sending domain (e.g. `mg.example.com`).
    pub domain: String,
    /// Region selector. Defaults to US.
    #[serde(default)]
    pub region: MailgunRegion,
}

/// `Mailtrap` transport settings.
///
/// Required when [`EmailTransport::Mailtrap`] is selected.
#[derive(Debug, Clone, Deserialize)]
pub struct MailtrapConfig {
    /// `Mailtrap` API key.
    pub api_key: String,
    /// Mailtrap inbox ID for sandbox/testing mode.
    ///
    /// When set, emails are sent to the sandbox API
    /// (`sandbox.api.mailtrap.io`) instead of the sending API
    /// (`send.api.mailtrap.io`). Obtain the inbox ID from your
    /// Mailtrap dashboard URL (e.g. `https://mailtrap.io/inboxes/12345/messages`).
    pub inbox_id: Option<u64>,
}

/// Email sender configuration.
///
/// Controls how verification emails (and later, other transactional mail)
/// are delivered. Defaults to the `Log` transport, suitable for local
/// development. Production deployments should set `transport: smtp` (or
/// one of the HTTP providers) and provide the corresponding config block.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct EmailConfig {
    /// Which transport to use for outbound email.
    #[serde(default)]
    pub transport: EmailTransport,
    /// Sender address used in the `From:` header. Required when
    /// `transport` is not `Log`; ignored otherwise.
    #[serde(default)]
    pub from: Option<String>,
    /// SMTP-specific settings. Required when `transport == Smtp`.
    #[serde(default)]
    pub smtp: Option<SmtpConfig>,
    /// `SendGrid`-specific settings. Required when `transport == Sendgrid`.
    #[serde(default)]
    pub sendgrid: Option<SendgridConfig>,
    /// `Postmark`-specific settings. Required when `transport == Postmark`.
    #[serde(default)]
    pub postmark: Option<PostmarkConfig>,
    /// `Mailgun`-specific settings. Required when `transport == Mailgun`.
    #[serde(default)]
    pub mailgun: Option<MailgunConfig>,
    /// `Mailtrap`-specific settings. Required when `transport == Mailtrap`.
    #[serde(default)]
    pub mailtrap: Option<MailtrapConfig>,
    /// Global email branding defaults. Per-realm overrides are stored
    /// in `RealmConfig.email_branding`.
    #[serde(default)]
    pub branding: Option<EmailBranding>,
    /// Optional directory containing custom Tera email templates.
    /// If set, templates from this directory override the compiled defaults.
    #[serde(default)]
    pub templates_dir: Option<String>,
}

/// Global branding configuration.
///
/// Applies across the admin UI and email templates. When `logo_url` is
/// `None`, the built-in Hearth SVG logo is used everywhere. When
/// `product_name` is `None`, "Hearth" is used.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct BrandingConfig {
    /// Product name shown in the UI (logo alt text) and email subjects.
    /// Defaults to `"Hearth"` when `None`.
    #[serde(default)]
    pub product_name: Option<String>,
    /// URL for the logo image. Applies to both the admin UI and email
    /// templates. When `None`, the built-in Hearth logo is used.
    ///
    /// For the UI, a relative path (e.g. `/ui/static/img/hearth-wide-web.svg`)
    /// is fine. For emails, an absolute URL is required — when the default
    /// logo is used, the server constructs `{base_url}/ui/static/img/hearth-wide-web.svg`.
    #[serde(default)]
    pub logo_url: Option<String>,
    /// Named UI theme. One of: `ember` (default dark), `ocean`, `midnight`,
    /// `forest`, `cloud` (light), `slate` (light). Case-insensitive.
    /// Validated at startup — an unknown name is a config error.
    #[serde(default)]
    pub theme: Option<String>,
    /// Path to a custom CSS file appended after the named theme. The file is
    /// read once at startup. It may override any `--ht-*` CSS variable or
    /// add arbitrary rules. `None` means no custom CSS.
    #[serde(default)]
    pub custom_css: Option<String>,
}

impl BrandingConfig {
    /// Returns the product name, falling back to `"Hearth"`.
    pub fn product_name_or_default(&self) -> &str {
        self.product_name.as_deref().unwrap_or("Hearth")
    }
}

/// Per-realm web branding block in YAML.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RealmWebYaml {
    /// Named theme override for this realm's UI sessions.
    #[serde(default)]
    pub theme: Option<String>,
    /// Path to a custom CSS file for this realm's UI sessions.
    #[serde(default)]
    pub custom_css: Option<String>,
    /// Realm-specific product name shown in titles, logo alt text, and
    /// email subjects when a request is scoped to this realm. Falls back
    /// to the global `branding.product_name` when unset. The 2026-04-30
    /// UX audit caught a realm titled "Test Corp" leaking into every
    /// other realm's pages because there was no per-realm override.
    #[serde(default)]
    pub product_name: Option<String>,
}

/// First-run onboarding configuration.
///
/// When `enabled`, Hearth generates a setup token at startup if no realm
/// exists and logs a one-time setup URL (Jenkins-style).
#[derive(Debug, Clone, Deserialize)]
pub struct OnboardingConfig {
    /// When `true`, the onboarding flow is available at `/ui/setup` until
    /// the first admin is created. Set to `false` to permanently disable.
    #[serde(default = "OnboardingConfig::default_enabled")]
    pub enabled: bool,
    /// Public base URL used in verification-email links (e.g.
    /// `https://auth.example.com`). When `None`, link generation falls
    /// back to `http://localhost`.
    #[serde(default)]
    pub base_url: Option<String>,
    /// Email address to send the first-run setup URL to on startup.
    ///
    /// When set and SMTP is configured, Hearth emails the setup URL to
    /// this address at startup (in addition to the WARN log). Useful in
    /// environments where console output is not readily accessible (e.g.
    /// Docker containers). Leave unset to rely on the log only.
    #[serde(default)]
    pub notification_email: Option<String>,
}

impl OnboardingConfig {
    const fn default_enabled() -> bool {
        true
    }
}

impl Default for OnboardingConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            base_url: None,
            notification_email: None,
        }
    }
}

// ===== OIDC & Token YAML config =====

/// OIDC configuration from the `oidc:` YAML section.
///
/// Controls OIDC Discovery metadata, authorization code TTL, and nonce enforcement.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct OidcYamlConfig {
    /// The issuer URL used in discovery documents and ID tokens.
    /// Must be a valid URL. Example: `"https://auth.example.com"`
    #[serde(default)]
    pub issuer: Option<String>,
    /// Authorization code TTL as a duration string (e.g. `"10m"`).
    /// Default: 10 minutes (600 seconds).
    #[serde(default)]
    pub authorization_code_ttl: Option<String>,
    /// Whether to enforce nonce uniqueness in authorization requests.
    #[serde(default)]
    pub enforce_nonces: Option<bool>,
    /// Require PKCE for confidential clients (RFC 9700 §2.1.1). Default: true.
    ///
    /// Set to `false` only for legacy confidential clients that cannot supply
    /// `code_challenge`. Production systems should leave this enabled.
    #[serde(default)]
    pub require_pkce_for_confidential_clients: Option<bool>,
}

/// Token configuration from the `token:` YAML section.
///
/// Controls JWT issuance parameters: issuer, audience, and TTLs.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TokenYamlConfig {
    /// The `iss` claim value. Defaults to `oidc.issuer` when omitted.
    #[serde(default)]
    pub issuer: Option<String>,
    /// The `aud` claim value.
    #[serde(default)]
    pub audience: Option<String>,
    /// Access token TTL as a duration string (e.g. `"15m"`).
    /// Default: 15 minutes.
    #[serde(default)]
    pub access_token_ttl: Option<String>,
    /// Refresh token TTL as a duration string (e.g. `"7d"`).
    /// Default: 7 days.
    #[serde(default)]
    pub refresh_token_ttl: Option<String>,
    /// Grace period during which the old signing key remains in JWKS after
    /// rotation (e.g. `"24h"`). Default: 24 hours.
    #[serde(default)]
    pub signing_key_rotation_grace_period: Option<String>,
}

// ===== Auth & Realm YAML config =====

/// Global authentication defaults in the `auth:` section.
///
/// These apply to all realms unless overridden per-realm in the `realms:` map.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthConfig {
    /// Default session TTL as a human-readable duration (e.g. "24h", "30m").
    #[serde(default)]
    pub session_ttl: Option<String>,
    /// Argon2id memory cost in KiB.
    #[serde(default)]
    pub password_memory_cost: Option<u32>,
    /// Argon2id time cost (iterations).
    #[serde(default)]
    pub password_time_cost: Option<u32>,
    /// Whether MFA is required for all users (global default).
    /// Per-realm `auth.mfa_required` overrides this.
    #[serde(default)]
    pub mfa_required: Option<bool>,
    /// Whether passkey login still requires a TOTP challenge (global default).
    /// Per-realm `auth.passkey_requires_mfa` overrides this.
    #[serde(default)]
    pub passkey_requires_mfa: Option<bool>,
}

/// Per-realm auth policy configuration in YAML.
///
/// These are policy declarations: the config layer stores them in `RealmConfig`,
/// but enforcement (checking MFA on login, validating password complexity, applying
/// rate limits) is a separate concern in the identity engine.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RealmAuthYaml {
    /// Whether MFA is required for all users in this realm.
    #[serde(default)]
    pub mfa_required: Option<bool>,
    /// Allowed MFA methods (e.g. `["totp", "webauthn"]`).
    #[serde(default)]
    pub mfa_methods: Option<Vec<String>>,
    /// Allowed authentication methods (e.g. `["password", "magic_link", "passkey"]`).
    #[serde(default)]
    pub allowed_auth_methods: Option<Vec<String>>,
    /// Password complexity requirements.
    #[serde(default)]
    pub password_policy: Option<PasswordPolicyYaml>,
    /// Per-realm token TTL overrides.
    #[serde(default)]
    pub token: Option<RealmTokenYaml>,
    /// Whether to enforce TOTP MFA even after passkey authentication.
    /// Passkeys are inherently multi-factor, but regulated environments
    /// may require an additional TOTP challenge. Defaults to `false`.
    #[serde(default)]
    pub passkey_requires_mfa: Option<bool>,
    /// Per-realm rate limit overrides.
    #[serde(default)]
    pub rate_limit: Option<RateLimitYaml>,
    /// Controls who may self-register. Defaults to `disabled` when absent.
    #[serde(default)]
    pub registration: Option<RegistrationPolicyYaml>,
    /// Controls dynamic client registration (RFC 7591). Defaults to `disabled` when absent.
    #[serde(default)]
    pub dcr: Option<DcrPolicyYaml>,
}

/// Self-service registration policy in YAML.
///
/// `mode` is one of: `disabled`, `open`, `invite_only`, `domain_restricted`.
/// When `mode = domain_restricted`, `allowed_domains` lists the permitted
/// email domains (case-insensitive).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RegistrationPolicyYaml {
    /// One of `disabled` (default), `open`, `invite_only`, `domain_restricted`.
    #[serde(default)]
    pub mode: RegistrationModeYaml,
    /// Required when `mode = domain_restricted`. Ignored otherwise.
    #[serde(default)]
    pub allowed_domains: Option<Vec<String>>,
}

/// Valid values for `realms.<name>.auth.registration.mode` in YAML.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationModeYaml {
    /// No public signup; only admins create users.
    #[default]
    Disabled,
    /// Anyone may register.
    Open,
    /// Must present a valid organization invitation.
    InviteOnly,
    /// Email domain must be in `allowed_domains`.
    DomainRestricted,
}

impl RegistrationPolicyYaml {
    /// Projects the YAML declaration into the engine-level enum.
    ///
    /// An ill-formed combination (e.g. `mode = domain_restricted` with an
    /// empty `allowed_domains`) collapses to an empty allow-list, which the
    /// engine correctly rejects as "no domain matches". Validation in
    /// `src/config/mod.rs` surfaces these cases to the operator at startup.
    pub(crate) fn to_domain(&self) -> crate::identity::RegistrationPolicy {
        match self.mode {
            RegistrationModeYaml::Disabled => crate::identity::RegistrationPolicy::Disabled,
            RegistrationModeYaml::Open => crate::identity::RegistrationPolicy::Open,
            RegistrationModeYaml::InviteOnly => crate::identity::RegistrationPolicy::InviteOnly,
            RegistrationModeYaml::DomainRestricted => {
                crate::identity::RegistrationPolicy::DomainRestricted(
                    self.allowed_domains.clone().unwrap_or_default(),
                )
            }
        }
    }
}

/// Dynamic Client Registration policy in YAML.
///
/// Controls whether OAuth clients may self-register via `POST /register`
/// (RFC 7591). Defaults to `disabled` when absent.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DcrPolicyYaml {
    /// One of `disabled` (default) or `open`.
    #[serde(default)]
    pub mode: DcrModeYaml,
}

/// Valid values for `realms.<name>.auth.dcr.mode` in YAML.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DcrModeYaml {
    /// Dynamic client registration is disabled. Only admins may create clients.
    #[default]
    Disabled,
    /// Any caller may register an OAuth client via `POST /register`.
    Open,
}

impl DcrPolicyYaml {
    /// Projects the YAML declaration into the engine-level enum.
    pub(crate) fn to_domain(&self) -> crate::identity::DcrPolicy {
        match self.mode {
            DcrModeYaml::Disabled => crate::identity::DcrPolicy::Disabled,
            DcrModeYaml::Open => crate::identity::DcrPolicy::Open,
        }
    }
}

/// Password complexity policy in YAML.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PasswordPolicyYaml {
    /// Minimum password length. Must be >= 1.
    #[serde(default)]
    pub min_length: Option<usize>,
    /// Require at least one uppercase letter.
    #[serde(default)]
    pub require_uppercase: Option<bool>,
    /// Require at least one digit.
    #[serde(default)]
    pub require_number: Option<bool>,
    /// Require at least one special character.
    #[serde(default)]
    pub require_special: Option<bool>,
    /// Password must not contain or equal the user's display name.
    #[serde(default)]
    pub not_username: Option<bool>,
    /// Password must not contain or equal the user's email address.
    #[serde(default)]
    pub not_email: Option<bool>,
    /// Number of previous passwords to remember; reuse is rejected.
    #[serde(default)]
    pub history_depth: Option<usize>,
    /// Maximum password age in days before the user must reset.
    #[serde(default)]
    pub max_age_days: Option<u32>,
}

/// Per-realm token TTL overrides in YAML.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RealmTokenYaml {
    /// Access token TTL as a duration string (e.g. `"15m"`).
    #[serde(default)]
    pub access_token_ttl: Option<String>,
    /// Refresh token TTL as a duration string (e.g. `"7d"`).
    #[serde(default)]
    pub refresh_token_ttl: Option<String>,
    /// Password reset token TTL as a duration string (e.g. `"30m"`).
    /// Defaults to 30 minutes when absent.
    #[serde(default)]
    pub password_reset_token_ttl: Option<String>,
}

/// Per-realm rate limit overrides in YAML.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RateLimitYaml {
    /// Maximum failed login attempts before lockout.
    #[serde(default)]
    pub max_failed_logins: Option<u32>,
    /// Lockout duration as a duration string (e.g. `"15m"`).
    #[serde(default)]
    pub lockout_duration: Option<String>,
}

/// YAML declaration for an organization within a realm.
///
/// Organizations declared under `realms.<name>.organizations:` are reconciled
/// with storage at startup: created if missing, updated if changed.
/// Members and invitations are runtime-only — not managed via YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct OrganizationYamlConfig {
    /// Human-readable organization name.
    pub name: String,
    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
    /// Optional configuration overrides.
    #[serde(default)]
    pub config: Option<OrgConfigYaml>,
}

/// Organization configuration overrides in YAML.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct OrgConfigYaml {
    /// Maximum number of members allowed. `None` means unlimited.
    #[serde(default)]
    pub max_members: Option<u32>,
}

/// YAML declaration for an OAuth 2.0 application (client).
///
/// Applications declared under `realms.<name>.applications:` are reconciled
/// with storage at startup: created if missing, updated if changed, archived
/// if removed from the YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationYamlConfig {
    /// Human-readable application name.
    pub name: String,
    /// Allowed OAuth 2.0 redirect URIs.
    #[serde(default)]
    pub redirect_uris: Option<Vec<String>>,
    /// Allowed OAuth 2.0 grant types (e.g. `["authorization_code", "client_credentials"]`).
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    /// Whether this is a confidential client (has a client secret).
    /// Defaults to `false` (public client).
    #[serde(default)]
    pub confidential: Option<bool>,
    /// Client secret. Supports `${ENV_VAR}` substitution.
    /// Required when `confidential: true`. Hashed with Argon2id before storage.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Whether this client is trusted to skip the OAuth consent screen.
    ///
    /// `None` (the default) or `Some(true)` keeps the standard
    /// prompt-before-code behaviour. `Some(false)` marks the client as
    /// trusted / first-party — users will be redirected directly to the
    /// `redirect_uri` without a consent prompt on first authorization.
    /// Only set this for clients where the user's consent is already
    /// implicit (e.g. first-party SSO inside an enterprise realm).
    #[serde(default)]
    pub require_consent: Option<bool>,
    /// URL to a logo displayed on the consent screen. Optional.
    #[serde(default)]
    pub client_logo_url: Option<String>,
    /// Stable slug used by YAML references and mapper gates.
    #[serde(default)]
    pub slug: Option<String>,
    /// Authz trust posture for this client.
    #[serde(default)]
    pub trust_level: Option<ClientTrustLevel>,
    /// Scopes this client may request.
    #[serde(default)]
    pub declared_scopes: Option<Vec<String>>,
    /// Whether a realm-level consent row covers all org contexts.
    #[serde(default)]
    pub consent_spans_orgs: Option<bool>,
}

/// YAML permission definition.
#[derive(Debug, Clone, Deserialize)]
pub struct PermissionYamlConfig {
    pub name: String,
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
}

/// YAML role definition.
#[derive(Debug, Clone, Deserialize)]
pub struct RoleYamlConfig {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub parents: Vec<String>,
    #[serde(default)]
    pub scope_kind: Option<String>,
}

/// YAML scope-bundle definition.
#[derive(Debug, Clone, Deserialize)]
pub struct ScopeBundleYamlConfig {
    pub name: String,
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// YAML protected-resource registration.
#[derive(Debug, Clone, Deserialize)]
pub struct ProtectedResourceYamlConfig {
    pub resource_uri: String,
    pub display_name: String,
    #[serde(default)]
    pub scopes: Vec<ScopeBundleYamlConfig>,
}

/// YAML claim-profile wrapper.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ClaimsYamlConfig {
    #[serde(default)]
    pub mappings: Vec<ClaimMapping>,
}

/// Per-realm email branding overrides in YAML.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RealmEmailYaml {
    /// Email branding overrides.
    #[serde(default)]
    pub branding: Option<EmailBranding>,
}

/// YAML group declaration in a realm config block.
#[derive(Debug, Clone, Deserialize)]
pub struct GroupYamlConfig {
    pub name: String,
    #[serde(default)]
    pub slug: Option<String>,
    /// Optional human-readable description.
    #[serde(default)]
    pub description: Option<String>,
}

/// Conflict-handling policy when migrating users between realms.
///
/// Determines what happens when a user with the same email already exists
/// in the destination realm.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MigrateConflictPolicy {
    /// Collect all conflicts and fail startup with the full list. Default.
    #[default]
    Error,
    /// Leave conflicting users in the source realm as orphans and continue.
    Skip,
}

/// Options for the `migrate:` sub-block inside a destination realm's YAML.
///
/// Controls which data categories are included in the migration and how
/// conflicts are handled. All fields have production-safe defaults.
#[derive(Debug, Clone, Deserialize)]
pub struct RealmMigrateYaml {
    /// Whether to migrate user records and credentials. Default: `true`.
    #[serde(default = "default_true")]
    pub users: bool,
    /// Whether to migrate org memberships for migrated users. Default: `true`.
    #[serde(default = "default_true")]
    pub orgs: bool,
    /// Whether to migrate OAuth applications (clients). Default: `false`.
    #[serde(default)]
    pub applications: bool,
    /// What to do when a user with the same email already exists in the
    /// destination realm. Default: `error` (fail startup with conflict list).
    #[serde(default)]
    pub on_conflict: MigrateConflictPolicy,
}

impl Default for RealmMigrateYaml {
    fn default() -> Self {
        Self {
            users: true,
            orgs: true,
            applications: false,
            on_conflict: MigrateConflictPolicy::default(),
        }
    }
}

fn default_true() -> bool {
    true
}

/// Per-realm YAML configuration block.
///
/// Fields are optional — `None` inherits from global `auth:` defaults.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RealmYamlConfig {
    /// Session TTL override (e.g. "12h").
    #[serde(default)]
    pub session_ttl: Option<String>,
    /// Argon2id memory cost override.
    #[serde(default)]
    pub password_memory_cost: Option<u32>,
    /// Argon2id time cost override.
    #[serde(default)]
    pub password_time_cost: Option<u32>,
    /// Per-realm email overrides.
    #[serde(default)]
    pub email: Option<RealmEmailYaml>,
    /// Per-realm web / UI branding overrides.
    #[serde(default)]
    pub web: Option<RealmWebYaml>,
    /// Per-realm auth policy overrides (MFA, password policy, rate limits, token TTLs).
    #[serde(default)]
    pub auth: Option<RealmAuthYaml>,
    /// SCIM 2.0 provisioning settings for this realm.
    #[serde(default)]
    pub scim: Option<RealmScimYaml>,
    /// Declarative OAuth 2.0 application (client) definitions.
    /// Reconciled with storage at startup.
    #[serde(default)]
    pub applications: Option<std::collections::HashMap<String, ApplicationYamlConfig>>,
    /// Declarative organization definitions.
    /// Reconciled with storage at startup. Members/invitations are runtime-only.
    #[serde(default)]
    pub organizations: Option<std::collections::HashMap<String, OrganizationYamlConfig>>,
    /// External IdP federation: per-realm connector definitions + account-
    /// linking policy. Reconciled with storage at startup; runtime-registered
    /// connectors not represented in YAML are removed.
    #[serde(default)]
    pub federation: Option<FederationYamlConfig>,
    /// SAML 2.0 Service Provider registrations (IdP side — Hearth as IdP).
    /// Reconciled at startup; runtime SPs not represented here are removed.
    #[serde(default)]
    pub saml_service_providers: Option<std::collections::HashMap<String, SamlServiceProviderYaml>>,
    /// YAML-authored permission registry.
    #[serde(default)]
    pub permissions: Option<Vec<PermissionYamlConfig>>,
    /// YAML-authored RBAC roles.
    #[serde(default)]
    pub roles: Option<Vec<RoleYamlConfig>>,
    /// Optional realm-level scope bundles.
    #[serde(default)]
    pub scopes: Option<Vec<ScopeBundleYamlConfig>>,
    /// Optional protected-resource registrations with resource-local scopes.
    #[serde(default)]
    pub protected_resources: Option<Vec<ProtectedResourceYamlConfig>>,
    /// Optional claim-profile overrides.
    #[serde(default)]
    pub claims: Option<ClaimsYamlConfig>,
    /// Alias for `applications` matching AUTHZ_EXPANSION terminology.
    #[serde(default)]
    pub oauth_clients: Option<std::collections::HashMap<String, ApplicationYamlConfig>>,
    /// Optional groups declared for this realm.
    #[serde(default)]
    pub groups: Option<Vec<GroupYamlConfig>>,
    /// When set, declares that this realm is the migration destination for the
    /// named archived realm slug.  The orphan-detection pass treats the named
    /// slug as resolved and suppresses its warning banner.  If `copy_from` is
    /// used instead, the source realm is NOT archived after migration.
    #[serde(default)]
    pub migrate_from: Option<String>,
    /// Like `migrate_from` but with copy semantics: the source realm is left
    /// intact after users are copied to this destination.
    #[serde(default)]
    pub copy_from: Option<String>,
    /// Fine-grained migration options. Only meaningful when `migrate_from` or
    /// `copy_from` is set. Defaults apply when the block is absent.
    #[serde(default)]
    pub migrate: Option<RealmMigrateYaml>,
    /// When `true` and the realm slug is re-added to the `realms:` map, the
    /// reconciler skips unarchiving it and the orphan-detection pass treats
    /// the slug as intentionally discarded (suppresses the warning banner).
    /// Has no effect on active realms.
    #[serde(default)]
    pub archive_drop: Option<bool>,
    /// One-shot signing key rotation trigger.
    ///
    /// When `true`, the server generates a new Ed25519 key for this realm,
    /// serves both the old and new keys in JWKS during the grace period, and
    /// records the flag as consumed so the next restart does not re-rotate.
    /// Operators may also call `POST /admin/realms/{id}/rotate-signing-key`
    /// instead of setting this flag.
    #[serde(default)]
    pub rotate_signing_key: Option<bool>,
}

/// YAML for `realms.{name}.scim.*`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RealmScimYaml {
    /// Static bearer token accepted by `/scim/v2/*` for this realm.
    ///
    /// Supports `${ENV_VAR}` substitution. The plaintext token is hashed
    /// before it is persisted into the runtime realm config.
    #[serde(default)]
    pub bearer_token: Option<String>,
}

/// YAML for a single SAML SP registration (Hearth as IdP issues to this SP).
#[derive(Debug, Clone, Deserialize)]
pub struct SamlServiceProviderYaml {
    pub entity_id: String,
    pub acs_url: String,
    #[serde(default)]
    pub slo_url: Option<String>,
    #[serde(default)]
    pub sp_certificate_pem: Option<String>,
    #[serde(default)]
    pub sign_assertions: Option<bool>,
    #[serde(default)]
    pub sign_responses: Option<bool>,
    #[serde(default)]
    pub want_authn_requests_signed: Option<bool>,
    /// One of `emailAddress` / `persistent` / `transient` / `unspecified`.
    #[serde(default)]
    pub nameid_format: Option<String>,
    #[serde(default)]
    pub attribute_map: Option<std::collections::BTreeMap<String, String>>,
}

/// YAML for `realms.{name}.federation.*`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FederationYamlConfig {
    /// How to link external identities that match existing local users
    /// by email: `disabled` / `confirm` / `auto`. Defaults to `confirm`
    /// (Keycloak-equivalent safety posture).
    #[serde(default)]
    pub link_existing_accounts: Option<LinkModeYaml>,
    /// Declarative connector definitions keyed by the operator-assigned
    /// `idp_name` (same string that ends up in `?idp=<name>`).
    #[serde(default)]
    pub providers: std::collections::HashMap<String, FederationProviderYaml>,
}

/// Realm-level federation account-linking mode.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LinkModeYaml {
    /// Never link — always JIT-provision.
    Disabled,
    /// Require local-credential re-auth before linking (default).
    Confirm,
    /// Auto-link on verified email match.
    Auto,
}

impl LinkModeYaml {
    /// Converts to the domain enum.
    pub fn to_domain(self) -> crate::identity::federation::LinkMode {
        match self {
            Self::Disabled => crate::identity::federation::LinkMode::Disabled,
            Self::Confirm => crate::identity::federation::LinkMode::Confirm,
            Self::Auto => crate::identity::federation::LinkMode::Auto,
        }
    }
}

/// YAML for a single federation connector.
///
/// `type` selects the underlying protocol. Four flavors:
///
/// - `oidc` — generic OIDC (operator MUST supply `issuer`,
///   `authorization_endpoint`, `token_endpoint`, `jwks_uri`).
/// - `google` / `microsoft` / `apple` — preset OIDC shapes with
///   issuer/endpoints/scopes prefilled.
/// - `github` — OAuth2 (no OIDC).
#[derive(Debug, Clone, Deserialize)]
pub struct FederationProviderYaml {
    /// Preset or protocol selector (`"oidc"`, `"google"`, `"microsoft"`,
    /// `"apple"`, `"github"`).
    #[serde(rename = "type")]
    pub kind: String,
    /// Optional human-readable label (overrides the preset default).
    #[serde(default)]
    pub display_name: Option<String>,
    /// OIDC issuer override. Required for generic `oidc`; optional for
    /// presets (operators use it to pin to a specific Azure AD tenant).
    #[serde(default)]
    pub issuer: Option<String>,
    /// Authorization endpoint override.
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    /// Token endpoint override.
    #[serde(default)]
    pub token_endpoint: Option<String>,
    /// Userinfo endpoint override.
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    /// JWKS URL override.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// OAuth client id registered at the upstream IdP.
    #[serde(default)]
    pub client_id: Option<String>,
    /// OAuth client secret.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Scopes override. Default is the preset's or `["openid","email","profile"]`.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// Per-claim renames for OIDC/OAuth2 connectors: maps a Hearth field
    /// name (e.g. `"email"`, `"name"`) to the upstream claim name the IdP
    /// actually sends (e.g. `"upn"`, `"preferred_username"`).
    ///
    /// Used for IdPs that don't follow the standard OIDC claim names, such
    /// as Azure AD (`"email": "upn"`) or custom Okta apps.
    /// Ignored for `type: saml` (use `attribute_map` instead).
    #[serde(default)]
    pub claim_mappings: Option<std::collections::BTreeMap<String, String>>,

    // --- SAML-specific fields (when `type: saml`) ---
    /// SAML IdP entity ID (SAML issuer).
    #[serde(default)]
    pub entity_id: Option<String>,
    /// SAML IdP SingleSignOnService URL (HTTP-Redirect binding).
    #[serde(default)]
    pub sso_url: Option<String>,
    /// SAML IdP SingleLogoutService URL.
    #[serde(default)]
    pub slo_url: Option<String>,
    /// SAML IdP signing certificate PEM (inline).
    #[serde(default)]
    pub idp_certificate_pem: Option<String>,
    /// Whether outbound AuthnRequests should be signed.
    #[serde(default)]
    pub sign_authn_requests: Option<bool>,
    /// Whether Hearth requires Assertion-level signatures.
    #[serde(default)]
    pub want_assertions_signed: Option<bool>,
    /// Attribute mapping: Hearth field → SAML attribute URI.
    #[serde(default)]
    pub attribute_map: Option<std::collections::BTreeMap<String, String>>,
}

impl FederationProviderYaml {
    /// Returns a blank OIDC provider config with all optional fields unset.
    pub fn default_oidc() -> Self {
        Self {
            kind: "oidc".to_string(),
            display_name: None,
            issuer: None,
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: None,
            client_id: None,
            client_secret: None,
            scopes: None,
            claim_mappings: None,
            entity_id: None,
            sso_url: None,
            slo_url: None,
            idp_certificate_pem: None,
            sign_authn_requests: None,
            want_assertions_signed: None,
            attribute_map: None,
        }
    }
}

/// Parses a human-readable duration string into microseconds.
///
/// Supported suffixes: `s` (seconds), `m` (minutes), `h` (hours), `d` (days).
///
/// # Errors
///
/// Returns `Err` if the string is empty, has an unknown suffix, or the
/// numeric part cannot be parsed.
pub fn parse_duration_to_micros(s: &str) -> Result<i64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration string".to_string());
    }

    let (num_str, multiplier) = if let Some(n) = s.strip_suffix('d') {
        (n, 86_400_000_000i64)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3_600_000_000i64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60_000_000i64)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1_000_000i64)
    } else {
        return Err(format!(
            "unknown duration suffix in '{s}', expected s/m/h/d"
        ));
    };

    let value: i64 = num_str
        .trim()
        .parse()
        .map_err(|e| format!("invalid duration number '{num_str}': {e}"))?;

    Ok(value * multiplier)
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

impl RealmYamlConfig {
    /// Merges this per-realm config with global auth defaults to produce a
    /// `RealmConfig` suitable for storage.
    ///
    /// Returns `Err(errors)` if any permission names are grammatically
    /// invalid, scope bundle names are malformed, role parent references
    /// are undeclared, cycles exist in the role parent graph, or claim
    /// mappings target Tier 1 (reserved) claim names. All violations are
    /// collected before returning so the caller can surface them at once.
    ///
    /// `web_theme_css` is populated by the caller (main.rs) after reading
    /// the optional CSS file from disk; it is `None` here.
    pub fn to_realm_config(
        &self,
        global: &AuthConfig,
        global_branding: Option<&EmailBranding>,
    ) -> Result<crate::identity::RealmConfig, Vec<crate::rbac::RegistryError>> {
        use crate::rbac::registry::RegistryError;
        use std::collections::HashMap;
        use uuid::Uuid;

        let session_ttl_micros = self
            .session_ttl
            .as_deref()
            .or(global.session_ttl.as_deref())
            .and_then(|s| parse_duration_to_micros(s).ok());

        let password_memory_cost = self.password_memory_cost.or(global.password_memory_cost);
        let password_time_cost = self.password_time_cost.or(global.password_time_cost);

        let email_branding = self
            .email
            .as_ref()
            .and_then(|e| e.branding.clone())
            .or_else(|| global_branding.cloned());

        // Map auth policy fields from the YAML `auth:` block (if present).
        let auth = self.auth.as_ref();
        let scim_bearer_token_hash = self
            .scim
            .as_ref()
            .and_then(|s| s.bearer_token.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(sha256_hex);

        let mfa_required = auth.and_then(|a| a.mfa_required).or(global.mfa_required);
        let mfa_methods = auth.and_then(|a| a.mfa_methods.clone());
        let allowed_auth_methods = auth.and_then(|a| a.allowed_auth_methods.clone());
        let passkey_requires_mfa = auth
            .and_then(|a| a.passkey_requires_mfa)
            .or(global.passkey_requires_mfa);

        let password_policy = auth.and_then(|a| a.password_policy.as_ref()).map(|pp| {
            crate::identity::PasswordPolicy {
                min_length: pp.min_length,
                require_uppercase: pp.require_uppercase,
                require_number: pp.require_number,
                require_special: pp.require_special,
                not_username: pp.not_username,
                not_email: pp.not_email,
                history_depth: pp.history_depth,
                max_age_days: pp.max_age_days,
            }
        });

        let access_token_ttl_micros = auth
            .and_then(|a| a.token.as_ref())
            .and_then(|t| t.access_token_ttl.as_deref())
            .and_then(|s| parse_duration_to_micros(s).ok());

        let refresh_token_ttl_micros = auth
            .and_then(|a| a.token.as_ref())
            .and_then(|t| t.refresh_token_ttl.as_deref())
            .and_then(|s| parse_duration_to_micros(s).ok());

        let password_reset_token_ttl_micros = auth
            .and_then(|a| a.token.as_ref())
            .and_then(|t| t.password_reset_token_ttl.as_deref())
            .and_then(|s| parse_duration_to_micros(s).ok());

        let max_failed_logins = auth
            .and_then(|a| a.rate_limit.as_ref())
            .and_then(|r| r.max_failed_logins);

        let lockout_duration_micros = auth
            .and_then(|a| a.rate_limit.as_ref())
            .and_then(|r| r.lockout_duration.as_deref())
            .and_then(|s| parse_duration_to_micros(s).ok());

        let registration_policy = auth
            .and_then(|a| a.registration.as_ref())
            .map(RegistrationPolicyYaml::to_domain);

        let dcr_policy = auth
            .and_then(|a| a.dcr.as_ref())
            .map(DcrPolicyYaml::to_domain);

        // Accumulate all validation errors upfront so callers see the full
        // set of problems in one pass rather than stopping at the first error.
        let mut errors: Vec<RegistryError> = Vec::new();

        // --- Permissions: grammar-validate each name -----------------------

        let permissions: Vec<PermissionDefinition> = self
            .permissions
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter_map(
                |permission| match Permission::new(permission.name.clone()) {
                    Ok(name) => Some(PermissionDefinition {
                        name,
                        display_name: permission.display_name,
                        description: permission.description,
                        category: permission.category,
                    }),
                    Err(reason) => {
                        errors.push(RegistryError::InvalidPermissionName {
                            name: permission.name,
                            reason,
                        });
                        None
                    }
                },
            )
            .collect();

        // --- Scope bundles: grammar-validate permission names --------------

        let scopes: Vec<ScopeBundle> = self
            .scopes
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|bundle| ScopeBundle {
                name: bundle.name,
                display_name: bundle.display_name,
                description: bundle.description,
                permissions: bundle
                    .permissions
                    .into_iter()
                    .filter_map(|permission| match Permission::new(permission.clone()) {
                        Ok(p) => Some(p),
                        Err(reason) => {
                            errors.push(RegistryError::InvalidPermissionName {
                                name: permission,
                                reason,
                            });
                            None
                        }
                    })
                    .collect(),
            })
            .collect();

        // --- Roles: two-pass to wire up parent_roles by name → ID ---------
        //
        // Pass 1: assign a stable RoleId to each role name.
        // Pass 2: resolve `parents: Vec<String>` to Vec<RoleId>.
        //
        // Roles in the in-memory registry use the nil UUID as the realm_id
        // sentinel — the actual RealmId is applied by the seeding / reconcile
        // path that writes roles into the RBAC engine's storage.

        let yaml_roles = self.roles.clone().unwrap_or_default();
        // Build name → RoleId map first (owned keys avoid a borrow-move conflict
        // when we consume yaml_roles via into_iter() immediately after).
        let name_to_id: HashMap<String, RoleId> = yaml_roles
            .iter()
            .map(|r| (r.name.clone(), RoleId::generate()))
            .collect();

        let roles: Vec<Role> = yaml_roles
            .into_iter()
            .map(|role| {
                let scope_kind = match role.scope_kind.as_deref() {
                    Some("organization") => RoleScopeKind::Organization,
                    Some("any") => RoleScopeKind::Any,
                    _ => RoleScopeKind::Realm,
                };

                let id = name_to_id[role.name.as_str()].clone();

                let role_permissions: Vec<Permission> = role
                    .permissions
                    .into_iter()
                    .filter_map(|permission| match Permission::new(permission.clone()) {
                        Ok(p) => Some(p),
                        Err(reason) => {
                            errors.push(RegistryError::InvalidPermissionName {
                                name: permission,
                                reason,
                            });
                            None
                        }
                    })
                    .collect();

                // Resolve parent names to IDs; unknown names surface as
                // UndeclaredParentRole errors during registry.validate().
                // We store whatever IDs we can resolve here so the
                // structural cycle-detector can run on what's available.
                let parent_roles: Vec<RoleId> = role
                    .parents
                    .into_iter()
                    .filter_map(|parent_name| name_to_id.get(parent_name.as_str()).cloned())
                    .collect();

                Role {
                    id,
                    // Nil UUID sentinel: actual realm ID is injected at
                    // seed/reconcile time, not at YAML parse time.
                    realm_id: crate::core::RealmId::new(Uuid::nil()),
                    name: role.name,
                    description: role.description,
                    permissions: role_permissions,
                    parent_roles,
                    scope_kind,
                    status: crate::rbac::RoleStatus::Active,
                    yaml_managed: true,
                    created_at: crate::core::Timestamp::from_micros(0),
                    updated_at: crate::core::Timestamp::from_micros(0),
                }
            })
            .collect();

        // --- Protected resources: grammar-validate bundle perm names -------

        let protected_resources: Vec<ProtectedResource> = self
            .protected_resources
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|resource| ProtectedResource {
                resource_uri: resource.resource_uri,
                display_name: resource.display_name,
                scopes: resource
                    .scopes
                    .into_iter()
                    .map(|bundle| ScopeBundle {
                        name: bundle.name,
                        display_name: bundle.display_name,
                        description: bundle.description,
                        permissions: bundle
                            .permissions
                            .into_iter()
                            .filter_map(|permission| match Permission::new(permission.clone()) {
                                Ok(p) => Some(p),
                                Err(reason) => {
                                    errors.push(RegistryError::InvalidPermissionName {
                                        name: permission,
                                        reason,
                                    });
                                    None
                                }
                            })
                            .collect(),
                    })
                    .collect(),
            })
            .collect();

        // --- Claim profile -------------------------------------------------

        let claim_profile =
            self.claims
                .clone()
                .map(|claims| crate::identity::claims_config::ClaimProfile {
                    mappings: claims.mappings,
                    updated_at: None,
                });

        // --- Groups --------------------------------------------------------

        let groups: Vec<crate::rbac::Group> = self
            .groups
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|g| crate::rbac::Group {
                id: crate::rbac::GroupId::generate(),
                realm_id: crate::core::RealmId::new(uuid::Uuid::nil()),
                name: g.name.clone(),
                slug: g.slug.unwrap_or_else(|| make_group_slug(&g.name)),
                description: g.description.clone(),
                created_at: crate::core::Timestamp::from_micros(0),
                updated_at: crate::core::Timestamp::from_micros(0),
            })
            .collect();

        // --- Structural validation (cross-references, cycles, Tier 1) ------
        //
        // Bail early on grammar errors before running the structural checks
        // to avoid cascading noise (e.g. an undeclared perm in a role would
        // generate both an InvalidPermissionName AND an UndeclaredPermission
        // error for the same typo).
        if !errors.is_empty() {
            return Err(errors);
        }

        let registry = crate::rbac::registry::RealmPermissionRegistry {
            permissions: permissions.clone(),
            roles: roles.clone(),
            scopes: scopes.clone(),
            protected_resources: protected_resources.clone(),
            claim_profile: claim_profile.clone(),
        };
        registry.validate()?;

        Ok(crate::identity::RealmConfig {
            session_ttl_micros,
            password_memory_cost,
            password_time_cost,
            email_branding,
            // Populated by main.rs after reading the CSS file from disk.
            web_theme_css: None,
            // Mirrors the realm's YAML `web.theme`. Doesn't require disk
            // reads (unlike the CSS body) so we populate it here directly
            // off the parsed YAML rather than deferring to main.rs.
            web_theme_name: self
                .web
                .as_ref()
                .and_then(|w| w.theme.as_ref())
                .map(|t| t.trim().to_string())
                .filter(|s| !s.is_empty()),
            mfa_required,
            mfa_methods,
            allowed_auth_methods,
            password_policy,
            access_token_ttl_micros,
            refresh_token_ttl_micros,
            password_reset_token_ttl_micros,
            max_failed_logins,
            lockout_duration_micros,
            passkey_requires_mfa,
            webauthn_required: None,
            webauthn_resident_key: None,
            webauthn_user_verification: None,
            registration_policy,
            dcr_policy,
            // Realm-level federation link mode. `None` → `Confirm`
            // (Keycloak-equivalent default). Connector records are
            // reconciled separately via `reconcile_federation_for_realm`.
            federation_link_mode: self
                .federation
                .as_ref()
                .and_then(|f| f.link_existing_accounts)
                .map(LinkModeYaml::to_domain),
            permissions,
            roles,
            scopes,
            protected_resources,
            claim_profile,
            groups,
            scim_bearer_token_hash,
            // Per-realm logo and primary color are managed via the admin API,
            // not via hearth.yaml, so they default to None here.
            logo_url: None,
            primary_color: None,
            // Email template overrides are managed via the admin API, not
            // via hearth.yaml; start empty and let the API populate them.
            email_templates: std::collections::HashMap::new(),
        })
    }
}

/// Derives a URL-safe group slug from a display name.
fn make_group_slug(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_hyphen = true;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            last_hyphen = false;
        } else if !last_hyphen {
            out.push('-');
            last_hyphen = true;
        }
    }
    if out.len() > 63 {
        out.truncate(63);
    }
    if out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        out = "group".to_string();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_config_defaults() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.bind_address, "127.0.0.1");
        assert_eq!(cfg.port, 8420);
        assert!(cfg.tls_cert_path.is_none());
        assert!(cfg.tls_key_path.is_none());
    }

    /// Pins REQ-100: `to_realm_config` mirrors `web.theme` from the
    /// realm YAML into `RealmConfig.web_theme_name` so the realm detail
    /// page can show the source theme name without inspecting CSS bytes.
    #[test]
    fn to_realm_config_populates_web_theme_name_from_yaml() {
        let yaml = RealmYamlConfig {
            web: Some(RealmWebYaml {
                theme: Some("ocean".to_string()),
                custom_css: None,
                product_name: None,
            }),
            ..RealmYamlConfig::default()
        };
        let cfg = yaml
            .to_realm_config(&AuthConfig::default(), None)
            .expect("to_realm_config");
        assert_eq!(cfg.web_theme_name.as_deref(), Some("ocean"));
        // The CSS body is populated separately by main.rs from disk.
        assert!(cfg.web_theme_css.is_none());
    }

    /// Whitespace-only or empty `web.theme` values must NOT surface as
    /// `Some("")` — the detail page would render an empty pill, which
    /// is worse than the "Inherits global default" fallback.
    #[test]
    fn to_realm_config_treats_blank_theme_as_unset() {
        let yaml = RealmYamlConfig {
            web: Some(RealmWebYaml {
                theme: Some("   ".to_string()),
                custom_css: None,
                product_name: None,
            }),
            ..RealmYamlConfig::default()
        };
        let cfg = yaml
            .to_realm_config(&AuthConfig::default(), None)
            .expect("to_realm_config");
        assert!(cfg.web_theme_name.is_none());
    }

    /// When the realm has no `web` block at all, `web_theme_name` is `None`.
    #[test]
    fn to_realm_config_no_web_block_yields_none_theme_name() {
        let yaml = RealmYamlConfig::default();
        let cfg = yaml
            .to_realm_config(&AuthConfig::default(), None)
            .expect("to_realm_config");
        assert!(cfg.web_theme_name.is_none());
    }

    #[test]
    fn to_realm_config_hashes_scim_bearer_token() {
        let yaml = RealmYamlConfig {
            scim: Some(RealmScimYaml {
                bearer_token: Some("scim-secret-token".to_string()),
            }),
            ..RealmYamlConfig::default()
        };
        let cfg = yaml
            .to_realm_config(&AuthConfig::default(), None)
            .expect("to_realm_config");
        // deepcode ignore HardcodedNonCryptoSecret: SHA-256 hash of "scim-secret-token" — SCIM bearer roundtrip fixture
        assert_eq!(
            cfg.scim_bearer_token_hash.as_deref(),
            Some("31c5b57bb0a5e7b9a064b0d08eaa2a74d532e36a261d02510120e45466187272")
        );
    }

    #[test]
    fn storage_section_defaults() {
        let cfg = StorageSection::default();
        assert_eq!(cfg.data_dir, "./data");
        assert_eq!(cfg.wal_max_size_bytes, 256 * 1024 * 1024);
        assert_eq!(cfg.memtable_flush_bytes, 64 * 1024 * 1024);
        assert_eq!(cfg.hot_tier_capacity, None);
        assert_eq!(cfg.hot_tier_max_memory, None);
        assert!(cfg.fsync);
    }

    #[test]
    fn observability_config_defaults() {
        let cfg = ObservabilityConfig::default();
        assert_eq!(cfg.log_level, "info");
        assert_eq!(cfg.log_format, "text");
    }

    #[test]
    fn operational_config_defaults() {
        let cfg = OperationalConfig::default();
        assert_eq!(cfg.request_timeout_secs, 30);
        assert_eq!(cfg.shutdown_timeout_secs, 10);
        assert_eq!(cfg.max_connections, 1024);
        assert_eq!(cfg.queue_depth, 4096);
    }

    #[test]
    fn email_config_defaults() {
        let cfg = EmailConfig::default();
        assert_eq!(cfg.transport, EmailTransport::Log);
        assert!(cfg.from.is_none());
    }

    #[test]
    fn onboarding_config_defaults() {
        let cfg = OnboardingConfig::default();
        assert!(cfg.enabled);
        assert!(cfg.base_url.is_none());
    }

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration_to_micros("30s").expect("ok"), 30_000_000);
    }

    #[test]
    fn parse_duration_minutes() {
        assert_eq!(parse_duration_to_micros("5m").expect("ok"), 300_000_000);
    }

    #[test]
    fn parse_duration_hours() {
        assert_eq!(parse_duration_to_micros("24h").expect("ok"), 86_400_000_000);
    }

    #[test]
    fn parse_duration_days() {
        assert_eq!(parse_duration_to_micros("1d").expect("ok"), 86_400_000_000);
    }

    #[test]
    fn parse_duration_invalid_suffix() {
        assert!(parse_duration_to_micros("10x").is_err());
    }

    #[test]
    fn parse_duration_empty() {
        assert!(parse_duration_to_micros("").is_err());
    }

    #[test]
    fn auth_config_yaml_parsing() {
        let yaml = "session_ttl: '24h'\npassword_memory_cost: 65536\n";
        let cfg: AuthConfig = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(cfg.session_ttl.as_deref(), Some("24h"));
        assert_eq!(cfg.password_memory_cost, Some(65536));
    }

    #[test]
    fn realm_yaml_config_merge() {
        let global = AuthConfig {
            session_ttl: Some("24h".to_string()),
            password_memory_cost: Some(65536),
            password_time_cost: Some(3),
            mfa_required: None,
            passkey_requires_mfa: None,
        };
        let realm_cfg = RealmYamlConfig {
            session_ttl: Some("12h".to_string()),
            ..RealmYamlConfig::default()
        };
        let merged = realm_cfg
            .to_realm_config(&global, None)
            .expect("default realm config must be valid");
        // Per-realm TTL overrides global
        assert_eq!(merged.session_ttl_micros, Some(43_200_000_000));
        // Inherited from global
        assert_eq!(merged.password_memory_cost, Some(65536));
        assert_eq!(merged.password_time_cost, Some(3));
    }
}
