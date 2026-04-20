use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use hearth::audit::EmbeddedAuditEngine;
use hearth::authz::{AuthorizationEngine, AuthzConfig, EmbeddedAuthzEngine};
use hearth::config::{Config, EmailTransport, EnvVarWarningKind};
use hearth::core::{Clock, SystemClock};
use hearth::identity::email::mailgun::MailgunRegion;
use hearth::identity::email::{
    smtp_sender_from_config, ApiKey, EmailService, LoggingEmailSender, MailgunEmailSender,
    MailtrapEmailSender, PostmarkEmailSender, SendgridEmailSender, SharedEmailSender,
};
use hearth::identity::onboarding::{self, OnboardingService};
use hearth::identity::{
    CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, OidcConfig,
    TokenConfig,
};
use hearth::protocol::http::{self, AppState};
use hearth::protocol::tls::{build_server_config, ReloadableTlsConfig, TlsConfigParams};
use hearth::protocol::web::{self, WebState};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Hearth — a purpose-built identity database.
#[derive(Parser)]
#[command(name = "hearth", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Top-level subcommands.
#[derive(Subcommand)]
enum Commands {
    /// Start the Hearth identity server.
    Serve {
        /// Enable development mode (in-memory storage, relaxed security, debug logging).
        #[arg(long)]
        dev: bool,

        /// Path to configuration file (YAML).
        #[arg(long, short)]
        config: Option<PathBuf>,

        /// Port to listen on (overrides config file).
        #[arg(long)]
        port: Option<u16>,

        /// Address to bind to (overrides config file).
        #[arg(long)]
        bind: Option<String>,
    },
    /// Manage tenants.
    Tenant {
        #[command(subcommand)]
        action: TenantAction,
    },
    /// Manage OAuth 2.0 applications (clients).
    App {
        #[command(subcommand)]
        action: AppAction,
    },
    /// Import data from another identity provider.
    Migrate {
        #[command(subcommand)]
        source: MigrateSource,
    },
}

/// Supported migration sources.
#[derive(Subcommand)]
enum MigrateSource {
    /// Import a Keycloak realm export (JSON).
    Keycloak {
        /// Path to a Keycloak realm export file (JSON).
        #[arg(long)]
        file: PathBuf,

        /// Data directory of the target Hearth store. Required unless
        /// `--dry-run` is set; the store will be created if it does not
        /// exist.
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// Optional tenant UUID to import into. When omitted, the realm
        /// `id` field from the export is used; if that is also missing
        /// or malformed, a fresh UUID is generated.
        #[arg(long)]
        tenant: Option<String>,

        /// Validate the export and print the report without writing any
        /// data. `--data-dir` is not required in this mode.
        #[arg(long)]
        dry_run: bool,
    },
}

/// Tenant management subcommands.
#[derive(Subcommand)]
enum TenantAction {
    /// Create a new tenant (generates a UUID).
    Create,
}

/// Application (OAuth client) management subcommands.
#[derive(Subcommand)]
enum AppAction {
    /// Register a new OAuth 2.0 client against a running Hearth server.
    Create {
        /// URL of the running Hearth server (e.g. `http://127.0.0.1:8080`).
        #[arg(long)]
        server: String,

        /// Tenant UUID to register the application under.
        #[arg(long)]
        tenant_id: String,

        /// Human-readable name for the application.
        #[arg(long)]
        name: String,

        /// OAuth 2.0 redirect URI for the application.
        #[arg(long)]
        redirect_uri: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve {
            dev,
            config: config_path,
            port,
            bind,
        } => {
            if let Err(e) = run_serve(dev, config_path, port, bind).await {
                // Use eprintln! here — tracing may not be initialized yet if
                // the error occurred during config loading.
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        Commands::Tenant { action } => match action {
            TenantAction::Create => run_tenant_create(),
        },
        Commands::App { action } => match action {
            AppAction::Create {
                server,
                tenant_id,
                name,
                redirect_uri,
            } => {
                if let Err(e) = run_app_create(&server, &tenant_id, &name, &redirect_uri) {
                    error!("{e}");
                    std::process::exit(1);
                }
            }
        },
        Commands::Migrate { source } => match source {
            MigrateSource::Keycloak {
                file,
                data_dir,
                tenant,
                dry_run,
            } => {
                if let Err(e) =
                    run_migrate_keycloak(&file, data_dir.as_deref(), tenant.as_deref(), dry_run)
                {
                    error!("{e}");
                    std::process::exit(1);
                }
            }
        },
    }
}

/// Runs the `hearth serve` command.
#[allow(clippy::too_many_lines)]
async fn run_serve(
    dev: bool,
    config_path: Option<PathBuf>,
    port_override: Option<u16>,
    bind_override: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let mut config = load_config(dev, config_path.as_deref())?;

    // Apply CLI overrides
    if let Some(port) = port_override {
        config.server.port = port;
    }
    if let Some(bind) = bind_override {
        config.server.bind_address = bind;
    }

    // Safety-net: print config warnings to stderr before tracing initialises
    // so they are visible even if the subscriber setup fails.
    for w in &config.config_warnings {
        eprintln!(
            "[hearth] config warning: {} — {}",
            w.var_name,
            w.kind_label()
        );
    }

    // Initialize tracing
    let filter = EnvFilter::try_new(&config.observability.log_level)
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Log config warnings through the structured tracing pipeline
    for w in &config.config_warnings {
        match w.kind {
            EnvVarWarningKind::Missing => {
                warn!(var = %w.var_name, "config references unset environment variable — substituted empty string");
            }
            EnvVarWarningKind::Empty => {
                warn!(var = %w.var_name, "environment variable is set but empty — this is likely a misconfiguration");
            }
        }
    }

    info!(
        dev_mode = config.dev_mode,
        port = config.server.port,
        bind = %config.server.bind_address,
        "Hearth identity server starting"
    );

    // Initialize storage engine
    let storage: Arc<EmbeddedStorageEngine> = if config.dev_mode {
        let temp_dir = tempfile::tempdir()?;
        info!(path = %temp_dir.path().display(), "using temporary data directory (dev mode)");
        // Convert to owned path so it outlives the tempdir handle
        let data_path = temp_dir.keep();
        let storage_config = StorageConfig::dev(data_path);
        Arc::new(EmbeddedStorageEngine::open(storage_config)?)
    } else {
        let storage_config = StorageConfig::dev(PathBuf::from(&config.storage.data_dir));
        Arc::new(EmbeddedStorageEngine::open(storage_config)?)
    };

    // Initialize identity engine
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;

    // Build OidcConfig from YAML
    let oidc_config = {
        let mut oc = OidcConfig::default();
        if let Some(issuer) = &config.oidc.issuer {
            oc.issuer.clone_from(issuer);
        }
        if let Some(ttl) = &config.oidc.authorization_code_ttl {
            if let Ok(micros) = hearth::config::parse_duration_to_micros(ttl) {
                oc.authorization_code_ttl_secs = micros / 1_000_000;
            }
        }
        if let Some(enforce) = config.oidc.enforce_nonces {
            oc.enforce_nonces = enforce;
        }
        oc
    };

    // Build TokenConfig from YAML. token.issuer defaults to oidc.issuer when omitted.
    let token_config = {
        let mut tc = TokenConfig::default();
        if let Some(issuer) = &config.token.issuer {
            tc.issuer.clone_from(issuer);
        } else if let Some(issuer) = &config.oidc.issuer {
            tc.issuer.clone_from(issuer);
        }
        if let Some(audience) = &config.token.audience {
            tc.audience.clone_from(audience);
        }
        if let Some(ttl) = &config.token.access_token_ttl {
            if let Ok(micros) = hearth::config::parse_duration_to_micros(ttl) {
                tc.access_token_ttl_secs = micros / 1_000_000;
            }
        }
        if let Some(ttl) = &config.token.refresh_token_ttl {
            if let Ok(micros) = hearth::config::parse_duration_to_micros(ttl) {
                tc.refresh_token_ttl_secs = micros / 1_000_000;
            }
        }
        tc
    };

    let identity_config = if config.dev_mode {
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            oidc: oidc_config,
            token: token_config,
            ..IdentityConfig::default()
        }
    } else {
        IdentityConfig {
            oidc: oidc_config,
            token: token_config,
            ..IdentityConfig::default()
        }
    };

    let identity_engine: Arc<dyn IdentityEngine> = Arc::new(EmbeddedIdentityEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
        identity_config,
    )?);

    // Base URL for email links and onboarding (computed once, reused).
    let base_url = config.onboarding.base_url.clone().unwrap_or_else(|| {
        format!(
            "http://{}:{}",
            config.server.bind_address, config.server.port
        )
    });

    // Email sender + service (default: log transport — stderr at WARN level).
    let email_sender: SharedEmailSender = build_email_sender(&config)?;
    let email_service = Arc::new(build_email_service(email_sender, &config)?);

    // Ensure a first-run setup token exists BEFORE tenant reconciliation.
    // Reconciliation may auto-create tenants from YAML config, which would
    // make is_first_run() return false and prevent the setup URL from being
    // logged on a truly fresh instance.
    let data_dir: PathBuf = if config.dev_mode {
        std::env::temp_dir().join("hearth-dev-onboarding")
    } else {
        PathBuf::from(&config.storage.data_dir)
    };
    if config.onboarding.enabled {
        if let Err(e) = onboarding::ensure_setup_token(
            identity_engine.as_ref(),
            &data_dir,
            Some(&base_url),
            Some(email_service.as_ref()),
            config.onboarding.notification_email.as_deref(),
        ) {
            error!(error = %e, "failed to ensure setup token; onboarding will be unavailable");
        }
    }

    // Reconcile YAML-declared tenants with storage. Runs after setup-token
    // generation so reconciliation-created tenants don't suppress the
    // setup URL on a fresh instance.
    match hearth::identity::reconcile::reconcile_tenants(identity_engine.as_ref(), &config) {
        Ok(report) => {
            if !report.created.is_empty()
                || !report.archived.is_empty()
                || !report.updated.is_empty()
                || !report.unarchived.is_empty()
            {
                info!(
                    created = report.created.len(),
                    updated = report.updated.len(),
                    archived = report.archived.len(),
                    unarchived = report.unarchived.len(),
                    "tenant reconciliation complete"
                );
            }
        }
        Err(e) => {
            error!(error = %e, "tenant reconciliation failed");
        }
    }

    let authz_engine: Arc<dyn AuthorizationEngine> = Arc::new(EmbeddedAuthzEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        AuthzConfig::default(),
    ));

    let audit_engine: Arc<dyn hearth::audit::AuditEngine> = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        clock,
    ));

    let onboarding_service = Arc::new(OnboardingService::new(
        Arc::clone(&identity_engine),
        Arc::clone(&authz_engine),
        Arc::clone(&email_service),
        data_dir.clone(),
    ));

    let app_state = if config.dev_mode {
        Arc::new(AppState::new_dev(
            Arc::clone(&identity_engine),
            Arc::clone(&authz_engine),
            Arc::clone(&audit_engine),
        ))
    } else {
        Arc::new(AppState::new(
            Arc::clone(&identity_engine),
            Arc::clone(&authz_engine),
            Arc::clone(&audit_engine),
        ))
    };

    // Build server address
    let addr: SocketAddr = format!("{}:{}", config.server.bind_address, config.server.port)
        .parse()
        .map_err(|e| format!("invalid bind address: {e}"))?;

    // Compose JSON API router + web UI router.
    //
    // When `branding.logo_url` points to a local file, load it at startup
    // and serve it via `/ui/static/custom-logo` so the browser can fetch it.
    // The email service still receives the original file path — its
    // `resolve_branding()` reads and inlines local SVGs directly.
    let (web_logo_url, custom_logo) = resolve_web_logo(&config);

    let mut web_state = WebState::new(
        Arc::clone(&identity_engine),
        Arc::clone(&authz_engine),
        Arc::clone(&audit_engine),
        Arc::clone(&onboarding_service),
        web::CookieSecret::random(),
        Some(Arc::clone(&email_service)),
    )
    .with_config_warnings(config.config_warnings.clone())
    .with_email_log_transport(config.email.transport == EmailTransport::Log)
    .with_product_name(config.branding.product_name_or_default().to_string())
    .with_logo_url(web_logo_url)
    .with_config(Arc::new(config.clone()));

    if let Some((bytes, content_type)) = custom_logo {
        web_state = web_state.with_custom_logo(bytes, content_type);
    }

    // Build global theme CSS: named theme base + optional operator custom CSS file.
    let named_theme = config.branding.theme.as_deref().unwrap_or("ember");
    let theme_base_css = web::themes::theme_css(named_theme);
    let global_custom_css = config
        .branding
        .custom_css
        .as_deref()
        .map(|path| {
            std::fs::read_to_string(path).unwrap_or_else(|e| {
                warn!(path = %path, error = %e, "failed to read branding custom CSS file");
                String::new()
            })
        })
        .unwrap_or_default();
    if !global_custom_css.is_empty() {
        info!(
            path = %config.branding.custom_css.as_deref().unwrap_or(""),
            bytes = global_custom_css.len(),
            "loaded branding.custom_css"
        );
    }
    let global_theme_css = format!("{theme_base_css}\n{global_custom_css}");

    // Build per-tenant theme CSS map (keyed by tenant UUID string).
    let mut tenant_themes: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for (tenant_name, tenant_yaml) in config.tenants.iter().flatten() {
        let web_cfg = match tenant_yaml.web.as_ref() {
            Some(w) if w.theme.is_some() || w.custom_css.is_some() => w,
            _ => continue,
        };
        let tenant = match identity_engine.get_tenant_by_name(tenant_name) {
            Ok(Some(t)) => t,
            Ok(None) => {
                warn!(name = %tenant_name, "tenant not found in storage, skipping per-tenant theme");
                continue;
            }
            Err(e) => {
                warn!(name = %tenant_name, error = %e, "failed to look up tenant for theme wiring");
                continue;
            }
        };
        let base = web_cfg.theme.as_deref().map_or("", web::themes::theme_css);
        let custom = web_cfg
            .custom_css
            .as_deref()
            .map(|path| {
                std::fs::read_to_string(path).unwrap_or_else(|e| {
                    warn!(path = %path, name = %tenant_name, error = %e, "failed to read tenant custom CSS file");
                    String::new()
                })
            })
            .unwrap_or_default();
        if !custom.is_empty() {
            info!(
                tenant = %tenant_name,
                path = %web_cfg.custom_css.as_deref().unwrap_or(""),
                bytes = custom.len(),
                "loaded tenant custom CSS"
            );
        }
        let combined = format!("{base}\n{custom}");
        if !combined.trim().is_empty() {
            tenant_themes.insert(tenant.id().as_uuid().to_string(), combined);
        }
    }

    web_state = web_state
        .with_theme_css(global_theme_css)
        .with_tenant_themes(tenant_themes);

    let app_router = http::router(Arc::clone(&app_state)).merge(web::router(web_state));

    // Check for TLS configuration
    if let (Some(cert_path), Some(key_path)) =
        (&config.server.tls_cert_path, &config.server.tls_key_path)
    {
        run_serve_tls(addr, &config, app_router, cert_path, key_path).await?;
    } else {
        let shutdown = async {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to install Ctrl+C handler");
            info!("shutdown signal received, stopping server");
        };
        http::serve_router(addr, app_router, shutdown).await?;
    }

    info!("Hearth server stopped");
    Ok(())
}

/// Builds the outbound email sender from configuration.
///
/// Returns the appropriate transport adapter based on the configured
/// `email.transport`. Fails if the transport rejects the configuration
/// at startup — better to fail early than on the first send attempt.
fn build_email_sender(config: &Config) -> Result<SharedEmailSender, Box<dyn std::error::Error>> {
    use hearth::identity::email::http::UreqTransport;

    Ok(match config.email.transport {
        EmailTransport::Log => Arc::new(LoggingEmailSender::new()),
        EmailTransport::Smtp => Arc::new(smtp_sender_from_config(&config.email)?),
        EmailTransport::Sendgrid => {
            let sg = config
                .email
                .sendgrid
                .as_ref()
                .ok_or("email.sendgrid block is required for sendgrid transport")?;
            let from = config
                .email
                .from
                .as_ref()
                .ok_or("email.from is required for sendgrid transport")?;
            Arc::new(SendgridEmailSender::new(
                UreqTransport,
                ApiKey::new(sg.api_key.clone()),
                from.clone(),
            ))
        }
        EmailTransport::Postmark => {
            let pm = config
                .email
                .postmark
                .as_ref()
                .ok_or("email.postmark block is required for postmark transport")?;
            let from = config
                .email
                .from
                .as_ref()
                .ok_or("email.from is required for postmark transport")?;
            Arc::new(PostmarkEmailSender::new(
                UreqTransport,
                ApiKey::new(pm.server_token.clone()),
                from.clone(),
            ))
        }
        EmailTransport::Mailgun => {
            let mg = config
                .email
                .mailgun
                .as_ref()
                .ok_or("email.mailgun block is required for mailgun transport")?;
            let from = config
                .email
                .from
                .as_ref()
                .ok_or("email.from is required for mailgun transport")?;
            let region = match mg.region {
                hearth::config::MailgunRegion::Us => MailgunRegion::Us,
                hearth::config::MailgunRegion::Eu => MailgunRegion::Eu,
            };
            Arc::new(MailgunEmailSender::new(
                UreqTransport,
                ApiKey::new(mg.api_key.clone()),
                mg.domain.clone(),
                from.clone(),
                region,
            ))
        }
        EmailTransport::Mailtrap => {
            let mt = config
                .email
                .mailtrap
                .as_ref()
                .ok_or("email.mailtrap block is required for mailtrap transport")?;
            let from = config
                .email
                .from
                .as_ref()
                .ok_or("email.from is required for mailtrap transport")?;
            Arc::new(MailtrapEmailSender::new(
                UreqTransport,
                ApiKey::new(mt.api_key.clone()),
                from.clone(),
                mt.inbox_id,
            ))
        }
    })
}

/// Builds the email service (orchestration layer) wrapping a sender.
///
/// `product_name` and `logo_url` come from the global `branding:`
/// section. Email-specific settings (accent color, support email,
/// footer text) come from `email.branding:`.
///
/// When no logo URL is configured, the built-in Hearth SVG is inlined
/// directly in the email HTML (no remote fetch needed).
fn build_email_service(
    sender: SharedEmailSender,
    config: &Config,
) -> Result<EmailService, Box<dyn std::error::Error>> {
    let product_name = config.branding.product_name_or_default().to_string();
    let logo_url = config.branding.logo_url.clone();
    let branding = config.email.branding.clone().unwrap_or_default();
    let default_logo_svg = String::from_utf8_lossy(web::HEARTH_WIDE_SVG).into_owned();
    let templates_dir = config
        .email
        .templates_dir
        .as_ref()
        .map(std::path::Path::new);
    Ok(EmailService::new(
        sender,
        product_name,
        logo_url,
        branding,
        default_logo_svg,
        templates_dir,
    )?)
}

/// Runs the HTTPS server with TLS, redirect listener, and SIGHUP cert reload.
async fn run_serve_tls(
    addr: SocketAddr,
    config: &Config,
    app_router: axum::Router,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let reloadable = ReloadableTlsConfig::load(cert_path.to_path_buf(), key_path.to_path_buf())
        .map_err(|e| format!("failed to load TLS certificates: {e}"))?;

    let params = TlsConfigParams {
        resolver: Arc::new(reloadable.resolver()),
        client_ca_path: config.server.tls_client_ca_path.clone(),
        require_client_cert: config.server.tls_require_client_cert,
    };
    let server_config =
        build_server_config(params).map_err(|e| format!("failed to build TLS config: {e}"))?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());

    // Spawn HTTP→HTTPS redirect listener
    let redirect_port = if config.server.port == 443 {
        80
    } else {
        config.server.port.saturating_sub(1)
    };
    let redirect_addr: SocketAddr = format!("{}:{redirect_port}", config.server.bind_address)
        .parse()
        .map_err(|e| format!("invalid redirect bind address: {e}"))?;
    let https_port = config.server.port;
    let mut redirect_shutdown_rx = shutdown_rx.clone();
    let redirect_handle = tokio::spawn(async move {
        let shutdown = async move {
            let _ = redirect_shutdown_rx.changed().await;
        };
        if let Err(e) = http::serve_redirect(redirect_addr, https_port, shutdown).await {
            warn!(error = %e, "HTTP redirect server failed");
        }
    });

    // Register SIGHUP handler for cert hot-reload
    #[cfg(unix)]
    {
        let reloadable = Arc::new(reloadable);
        let reloadable_clone = Arc::clone(&reloadable);
        tokio::spawn(async move {
            let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                .expect("failed to register SIGHUP handler");
            loop {
                sig.recv().await;
                info!("SIGHUP received, reloading TLS certificates");
                if let Err(e) = reloadable_clone.reload() {
                    error!(error = %e, "TLS certificate reload failed, keeping old cert");
                }
            }
        });
    }

    // Set up graceful shutdown on Ctrl+C
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
        info!("shutdown signal received, stopping server");
        drop(shutdown_tx);
    });

    // Start HTTPS server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    http::serve_tls_router(listener, app_router, acceptor, shutdown_rx).await?;

    let _ = redirect_handle.await;
    Ok(())
}

/// Loads configuration from file, dev mode, or defaults.
fn load_config(
    dev: bool,
    config_path: Option<&std::path::Path>,
) -> Result<Config, Box<dyn std::error::Error>> {
    if dev {
        return Ok(Config::dev());
    }

    if let Some(path) = config_path {
        return Ok(Config::from_file(path)?);
    }

    // Try default config file location
    let default_path = std::path::Path::new("hearth.yaml");
    if default_path.exists() {
        return Ok(Config::from_file(default_path)?);
    }

    Ok(Config::default())
}

/// Runs the `hearth tenant create` command.
///
/// Generates a new tenant UUID and prints it as JSON to stdout.
fn run_tenant_create() {
    let tenant_id = uuid::Uuid::new_v4();
    let output = serde_json::json!({ "tenant_id": tenant_id.to_string() });
    println!("{output}");
}

/// Runs the `hearth app create` command.
///
/// Registers an OAuth 2.0 client against a running Hearth server via HTTP.
fn run_app_create(
    server: &str,
    tenant_id: &str,
    name: &str,
    redirect_uri: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{server}/clients");
    let body = serde_json::json!({
        "client_name": name,
        "redirect_uris": [redirect_uri],
    });

    let response: serde_json::Value = ureq::post(&url)
        .header("X-Tenant-ID", tenant_id)
        .header("Content-Type", "application/json")
        .send_json(&body)?
        .body_mut()
        .read_json()?;

    println!("{response}");
    Ok(())
}

/// Runs the `hearth migrate keycloak` command.
///
/// Parses a Keycloak realm export and imports its tenant, users, clients,
/// and realm roles. In dry-run mode no state is written; otherwise a data
/// directory is required.
fn run_migrate_keycloak(
    file: &std::path::Path,
    data_dir: Option<&std::path::Path>,
    tenant: Option<&str>,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use hearth::core::TenantId;
    use hearth::identity::migration::{ImportOptions, KeycloakImporter, KeycloakRealmExport};
    use uuid::Uuid;

    let bytes = std::fs::read(file)?;
    let export: KeycloakRealmExport = KeycloakImporter::parse(&bytes)?;

    let requested_tenant = tenant
        .map(|s| -> Result<TenantId, Box<dyn std::error::Error>> {
            let uuid = Uuid::parse_str(s).map_err(|e| format!("invalid --tenant UUID: {e}"))?;
            Ok(TenantId::new(uuid))
        })
        .transpose()?;

    if dry_run {
        // Dry-run uses a temporary store so the importer still exercises
        // its full validation path (parsing, tuple shape checks) without
        // touching the user's data directory.
        let temp_dir = tempfile::tempdir()?;
        let storage_config = StorageConfig::dev(temp_dir.path().to_path_buf());
        let storage = Arc::new(EmbeddedStorageEngine::open(storage_config)?);
        let (identity, authz) = build_engines(&storage, true)?;
        let importer = KeycloakImporter::new(identity, authz);
        let report =
            importer.import_realm(&export, requested_tenant, &ImportOptions { dry_run: true })?;
        print_migration_report(&report);
        return Ok(());
    }

    let data_dir = data_dir.ok_or(
        "--data-dir is required for a real migration (use --dry-run to validate without writing)",
    )?;
    std::fs::create_dir_all(data_dir)?;
    let storage_config = StorageConfig::dev(data_dir.to_path_buf());
    let storage = Arc::new(EmbeddedStorageEngine::open(storage_config)?);
    let (identity, authz) = build_engines(&storage, false)?;
    let importer = KeycloakImporter::new(identity, authz);

    let report =
        importer.import_realm(&export, requested_tenant, &ImportOptions { dry_run: false })?;
    print_migration_report(&report);
    Ok(())
}

/// Identity + authz pair returned by [`build_engines`].
type AdminEngines = (
    Arc<dyn hearth::identity::IdentityEngine>,
    Arc<dyn hearth::authz::AuthorizationEngine>,
);

/// Builds the identity + authz engine pair used by one-shot admin
/// commands (migrations, etc.). Keeps the wiring in one place.
fn build_engines(
    storage: &Arc<EmbeddedStorageEngine>,
    dev_mode: bool,
) -> Result<AdminEngines, Box<dyn std::error::Error>> {
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let identity_config = if dev_mode {
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        }
    } else {
        IdentityConfig::default()
    };
    let identity = Arc::new(EmbeddedIdentityEngine::new(
        Arc::clone(storage) as Arc<dyn StorageEngine>,
        clock,
        identity_config,
    )?) as Arc<dyn hearth::identity::IdentityEngine>;
    let authz = Arc::new(EmbeddedAuthzEngine::new(
        Arc::clone(storage) as Arc<dyn StorageEngine>,
        AuthzConfig::default(),
    )) as Arc<dyn hearth::authz::AuthorizationEngine>;
    Ok((identity, authz))
}

/// Resolves the logo URL for the web UI.
///
/// When `branding.logo_url` is a local file path (not an HTTP URL and not
/// already pointing at a `/ui/static/` route), the file is read into memory
/// and a MIME type is inferred from the extension. The web UI URL is
/// rewritten to `/ui/static/custom-logo` so the browser can fetch the
/// bytes from [`web::serve_static`].
///
/// Returns `(web_logo_url, Option<(bytes, content_type)>)`.
fn resolve_web_logo(config: &Config) -> (String, Option<(Vec<u8>, &'static str)>) {
    let Some(logo_url) = config.branding.logo_url.as_deref() else {
        return (web::DEFAULT_LOGO_URL.to_string(), None);
    };

    if !is_local_logo_path(logo_url) {
        return (logo_url.to_string(), None);
    }

    let path = std::path::Path::new(logo_url);
    match std::fs::read(path) {
        Ok(bytes) => {
            let content_type = mime_for_logo(path);
            info!(
                path = %path.display(),
                content_type,
                size = bytes.len(),
                "loaded custom logo from local file"
            );
            (
                "/ui/static/custom-logo".to_string(),
                Some((bytes, content_type)),
            )
        }
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "failed to load custom logo file, falling back to default"
            );
            (web::DEFAULT_LOGO_URL.to_string(), None)
        }
    }
}

/// Returns `true` when the logo URL looks like a local filesystem path
/// rather than a remote URL or the built-in static route.
fn is_local_logo_path(s: &str) -> bool {
    !s.starts_with("http://") && !s.starts_with("https://") && !s.starts_with("/ui/static/")
}

/// Infers a MIME content type from a logo file's extension.
fn mime_for_logo(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some(e) if e.eq_ignore_ascii_case("svg") => "image/svg+xml",
        Some(e) if e.eq_ignore_ascii_case("png") => "image/png",
        Some(e) if e.eq_ignore_ascii_case("jpg") || e.eq_ignore_ascii_case("jpeg") => "image/jpeg",
        _ => "application/octet-stream",
    }
}

/// Prints a `MigrationReport` as a human-readable summary.
fn print_migration_report(report: &hearth::identity::MigrationReport) {
    println!("Migration summary:");
    if let Some(tid) = &report.tenant_id {
        println!("  tenant:                {tid}");
    } else {
        println!("  tenant:                <none>");
    }
    println!("  users imported:        {}", report.users_imported);
    println!(
        "  users w/ skipped cred: {}",
        report.users_with_skipped_credentials
    );
    println!("  clients imported:      {}", report.clients_imported);
    println!("  tuples written:        {}", report.tuples_written);
    if !report.warnings.is_empty() {
        println!("Warnings:");
        for w in &report.warnings {
            println!("  - {w}");
        }
    }
}
