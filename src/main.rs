use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use hearth::config::Config;
use hearth::core::{Clock, SystemClock};
use hearth::identity::{CredentialConfig, EmbeddedIdentityEngine, IdentityConfig};
use hearth::protocol::http::{self, AppState};
use hearth::protocol::tls::{build_server_config, ReloadableTlsConfig, TlsConfigParams};
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
                error!("{e}");
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
    }
}

/// Runs the `hearth serve` command.
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

    // Initialize tracing
    let filter = EnvFilter::try_new(&config.observability.log_level)
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

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
    let identity_config = if config.dev_mode {
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        }
    } else {
        IdentityConfig::default()
    };

    let identity_engine = EmbeddedIdentityEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        clock,
        identity_config,
    )?;

    let app_state = Arc::new(AppState {
        identity: Arc::new(identity_engine),
    });

    // Build server address
    let addr: SocketAddr = format!("{}:{}", config.server.bind_address, config.server.port)
        .parse()
        .map_err(|e| format!("invalid bind address: {e}"))?;

    // Check for TLS configuration
    if let (Some(cert_path), Some(key_path)) =
        (&config.server.tls_cert_path, &config.server.tls_key_path)
    {
        run_serve_tls(addr, &config, app_state, cert_path, key_path).await?;
    } else {
        let shutdown = async {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to install Ctrl+C handler");
            info!("shutdown signal received, stopping server");
        };
        http::serve(addr, app_state, shutdown).await?;
    }

    info!("Hearth server stopped");
    Ok(())
}

/// Runs the HTTPS server with TLS, redirect listener, and SIGHUP cert reload.
async fn run_serve_tls(
    addr: SocketAddr,
    config: &Config,
    app_state: Arc<AppState>,
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
    http::serve_tls(listener, app_state, acceptor, shutdown_rx).await?;

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
