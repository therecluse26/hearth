use std::path::Path;

use tracing::info;
use tracing_subscriber::EnvFilter;

use hearth::config::Config;

#[tokio::main]
async fn main() {
    // Load configuration: file if provided, otherwise defaults
    let config = load_config();

    // Initialize tracing from config
    let filter = EnvFilter::try_new(&config.observability.log_level)
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt().with_env_filter(filter).init();

    info!(
        dev_mode = config.dev_mode,
        port = config.server.port,
        bind = %config.server.bind_address,
        "Hearth identity server starting"
    );
}

/// Loads configuration from the standard file path, falling back to defaults.
fn load_config() -> Config {
    let config_path = Path::new("hearth.yaml");
    if config_path.exists() {
        match Config::from_file(config_path) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("Failed to load configuration: {e}");
                std::process::exit(1);
            }
        }
    } else {
        Config::default()
    }
}
