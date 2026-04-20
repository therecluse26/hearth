//! Configuration section structs.
//!
//! Each section implements `Default` with production-safe values and
//! `Deserialize` for YAML parsing. `#[serde(default)]` on each section
//! means partial YAML files work seamlessly.

use serde::Deserialize;
use std::path::PathBuf;

use crate::identity::email::EmailBranding;

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
        }
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
    #[serde(default = "StorageSection::default_hot_tier_capacity")]
    pub hot_tier_capacity: usize,
    /// Whether to fsync WAL writes. MUST be true in production.
    #[serde(default = "StorageSection::default_fsync")]
    pub fsync: bool,
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

    const fn default_hot_tier_capacity() -> usize {
        10_000
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
            hot_tier_capacity: Self::default_hot_tier_capacity(),
            fsync: Self::default_fsync(),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EmailTransport {
    /// Write email contents (subject, recipient, verification URL) to the
    /// `tracing` log at WARN level. No external delivery. Default.
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

impl Default for EmailTransport {
    fn default() -> Self {
        Self::Log
    }
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
    /// Global email branding defaults. Per-tenant overrides are stored
    /// in `TenantConfig.email_branding`.
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

/// Per-tenant web branding block in YAML.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TenantWebYaml {
    /// Named theme override for this tenant's UI sessions.
    #[serde(default)]
    pub theme: Option<String>,
    /// Path to a custom CSS file for this tenant's UI sessions.
    #[serde(default)]
    pub custom_css: Option<String>,
}

/// First-run onboarding configuration.
///
/// When `enabled`, Hearth generates a setup token at startup if no tenant
/// exists and logs a one-time setup URL (Jenkins-style).
#[derive(Debug, Clone, Deserialize)]
pub struct OnboardingConfig {
    /// When `true`, the onboarding flow is available at `/ui/setup` until
    /// the first admin is created. Set to `false` to permanently disable.
    #[serde(default = "OnboardingConfig::default_enabled")]
    pub enabled: bool,
    /// Public base URL used in verification-email links (e.g.
    /// `https://auth.example.com`). Falls back to the request `Host`
    /// header when `None`.
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
}

// ===== Auth & Tenant YAML config =====

/// Global authentication defaults in the `auth:` section.
///
/// These apply to all tenants unless overridden per-tenant in the `tenants:` map.
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
}

/// Per-tenant auth policy configuration in YAML.
///
/// These are policy declarations: the config layer stores them in `TenantConfig`,
/// but enforcement (checking MFA on login, validating password complexity, applying
/// rate limits) is a separate concern in the identity engine.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TenantAuthYaml {
    /// Whether MFA is required for all users in this tenant.
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
    /// Per-tenant token TTL overrides.
    #[serde(default)]
    pub token: Option<TenantTokenYaml>,
    /// Per-tenant rate limit overrides.
    #[serde(default)]
    pub rate_limit: Option<RateLimitYaml>,
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
}

/// Per-tenant token TTL overrides in YAML.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TenantTokenYaml {
    /// Access token TTL as a duration string (e.g. `"15m"`).
    #[serde(default)]
    pub access_token_ttl: Option<String>,
    /// Refresh token TTL as a duration string (e.g. `"7d"`).
    #[serde(default)]
    pub refresh_token_ttl: Option<String>,
}

/// Per-tenant rate limit overrides in YAML.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RateLimitYaml {
    /// Maximum failed login attempts before lockout.
    #[serde(default)]
    pub max_failed_logins: Option<u32>,
    /// Lockout duration as a duration string (e.g. `"15m"`).
    #[serde(default)]
    pub lockout_duration: Option<String>,
}

/// YAML declaration for an organization within a tenant.
///
/// Organizations declared under `tenants.<name>.organizations:` are reconciled
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
/// Applications declared under `tenants.<name>.applications:` are reconciled
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
}

/// Per-tenant email branding overrides in YAML.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TenantEmailYaml {
    /// Email branding overrides.
    #[serde(default)]
    pub branding: Option<EmailBranding>,
}

/// Per-tenant YAML configuration block.
///
/// Fields are optional — `None` inherits from global `auth:` defaults.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TenantYamlConfig {
    /// Session TTL override (e.g. "12h").
    #[serde(default)]
    pub session_ttl: Option<String>,
    /// Argon2id memory cost override.
    #[serde(default)]
    pub password_memory_cost: Option<u32>,
    /// Argon2id time cost override.
    #[serde(default)]
    pub password_time_cost: Option<u32>,
    /// Per-tenant email overrides.
    #[serde(default)]
    pub email: Option<TenantEmailYaml>,
    /// Per-tenant web / UI branding overrides.
    #[serde(default)]
    pub web: Option<TenantWebYaml>,
    /// Per-tenant auth policy overrides (MFA, password policy, rate limits, token TTLs).
    #[serde(default)]
    pub auth: Option<TenantAuthYaml>,
    /// Declarative OAuth 2.0 application (client) definitions.
    /// Reconciled with storage at startup.
    #[serde(default)]
    pub applications: Option<std::collections::HashMap<String, ApplicationYamlConfig>>,
    /// Declarative organization definitions.
    /// Reconciled with storage at startup. Members/invitations are runtime-only.
    #[serde(default)]
    pub organizations: Option<std::collections::HashMap<String, OrganizationYamlConfig>>,
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

impl TenantYamlConfig {
    /// Merges this per-tenant config with global auth defaults to produce a
    /// `TenantConfig` suitable for storage.
    ///
    /// `web_theme_css` is populated by the caller (main.rs) after reading
    /// the optional CSS file from disk; it is `None` here.
    pub fn to_tenant_config(
        &self,
        global: &AuthConfig,
        global_branding: Option<&EmailBranding>,
    ) -> crate::identity::TenantConfig {
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

        let mfa_required = auth.and_then(|a| a.mfa_required);
        let mfa_methods = auth.and_then(|a| a.mfa_methods.clone());
        let allowed_auth_methods = auth.and_then(|a| a.allowed_auth_methods.clone());

        let password_policy = auth
            .and_then(|a| a.password_policy.as_ref())
            .map(|pp| crate::identity::PasswordPolicy {
                min_length: pp.min_length,
                require_uppercase: pp.require_uppercase,
                require_number: pp.require_number,
                require_special: pp.require_special,
            });

        let access_token_ttl_micros = auth
            .and_then(|a| a.token.as_ref())
            .and_then(|t| t.access_token_ttl.as_deref())
            .and_then(|s| parse_duration_to_micros(s).ok());

        let refresh_token_ttl_micros = auth
            .and_then(|a| a.token.as_ref())
            .and_then(|t| t.refresh_token_ttl.as_deref())
            .and_then(|s| parse_duration_to_micros(s).ok());

        let max_failed_logins = auth
            .and_then(|a| a.rate_limit.as_ref())
            .and_then(|r| r.max_failed_logins);

        let lockout_duration_micros = auth
            .and_then(|a| a.rate_limit.as_ref())
            .and_then(|r| r.lockout_duration.as_deref())
            .and_then(|s| parse_duration_to_micros(s).ok());

        crate::identity::TenantConfig {
            session_ttl_micros,
            password_memory_cost,
            password_time_cost,
            email_branding,
            // Populated by main.rs after reading the CSS file from disk.
            web_theme_css: None,
            mfa_required,
            mfa_methods,
            allowed_auth_methods,
            password_policy,
            access_token_ttl_micros,
            refresh_token_ttl_micros,
            max_failed_logins,
            lockout_duration_micros,
        }
    }
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

    #[test]
    fn storage_section_defaults() {
        let cfg = StorageSection::default();
        assert_eq!(cfg.data_dir, "./data");
        assert_eq!(cfg.wal_max_size_bytes, 256 * 1024 * 1024);
        assert_eq!(cfg.memtable_flush_bytes, 64 * 1024 * 1024);
        assert_eq!(cfg.hot_tier_capacity, 10_000);
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
    fn tenant_yaml_config_merge() {
        let global = AuthConfig {
            session_ttl: Some("24h".to_string()),
            password_memory_cost: Some(65536),
            password_time_cost: Some(3),
        };
        let tenant_cfg = TenantYamlConfig {
            session_ttl: Some("12h".to_string()),
            ..TenantYamlConfig::default()
        };
        let merged = tenant_cfg.to_tenant_config(&global, None);
        // Per-tenant TTL overrides global
        assert_eq!(merged.session_ttl_micros, Some(43_200_000_000));
        // Inherited from global
        assert_eq!(merged.password_memory_cost, Some(65536));
        assert_eq!(merged.password_time_cost, Some(3));
    }
}
