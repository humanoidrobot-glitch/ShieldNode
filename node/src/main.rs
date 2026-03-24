mod config;
mod crypto;
mod metrics;
mod network;
mod tunnel;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "shieldnode", about = "ShieldNode decentralized VPN relay")]
struct Cli {
    /// Path to TOML configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Override the WireGuard listen port
    #[arg(short, long)]
    listen_port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let mut cfg = config::NodeConfig::load(&cli.config)
        .context("Failed to load configuration file")?;

    if let Some(port) = cli.listen_port {
        cfg.listen_port = port;
    }

    info!(
        listen_port = cfg.listen_port,
        metrics_port = cfg.metrics_port,
        libp2p_port = cfg.libp2p_port,
        exit_mode = cfg.exit_mode,
        "ShieldNode starting"
    );

    // Build shared bandwidth tracker for the metrics API
    let tracker = std::sync::Arc::new(tokio::sync::Mutex::new(
        metrics::bandwidth::BandwidthTracker::new(),
    ));

    // Start the metrics / health HTTP server
    let metrics_addr: std::net::SocketAddr =
        format!("0.0.0.0:{}", cfg.metrics_port).parse()?;
    let app = metrics::api::router(tracker.clone());

    info!(%metrics_addr, "Metrics HTTP server listening");

    axum::serve(
        tokio::net::TcpListener::bind(metrics_addr).await?,
        app.into_make_service(),
    )
    .await
    .context("Metrics HTTP server exited unexpectedly")?;

    Ok(())
}
