use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use hearth::config::Config;
use hearth::core::{Clock, SystemClock};
use hearth::identity::{CredentialConfig, EmbeddedIdentityEngine, IdentityConfig};
use hearth::protocol::http::{self, AppState};
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

    // Set up graceful shutdown on Ctrl+C
    let shutdown = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
        info!("shutdown signal received, stopping server");
    };

    // Start HTTP server
    http::serve(addr, app_state, shutdown).await?;

    info!("Hearth server stopped");
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
