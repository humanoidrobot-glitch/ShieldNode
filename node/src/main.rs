mod config;
mod crypto;
mod metrics;
mod network;
mod tunnel;

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use futures::StreamExt;
use tokio::sync::Mutex;
use tracing::info;

use crypto::keys::NodeKeyPair;
use metrics::bandwidth::BandwidthTracker;
use network::heartbeat::HeartbeatService;
use tunnel::listener::TunnelListener;

#[derive(Parser, Debug)]
#[command(name = "shieldnode", about = "ShieldNode decentralized VPN relay")]
struct Cli {
    /// Path to TOML configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Override the WireGuard listen port
    #[arg(short, long)]
    listen_port: Option<u16>,

    /// Generate a new node key and exit
    #[arg(long)]
    generate_key: bool,
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
        .unwrap_or_else(|e| {
            info!("config load failed ({e}), using defaults");
            config::NodeConfig::default()
        });

    if let Some(port) = cli.listen_port {
        cfg.listen_port = port;
    }

    // ── key management ────────────────────────────────────────────────

    let key_path = Path::new(&cfg.node_private_key_path);

    if cli.generate_key {
        let keypair = NodeKeyPair::generate();
        // Ensure parent directory exists.
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        keypair.save_to_file(key_path)?;
        let pub_hex = hex::encode(keypair.public_key().as_bytes());
        info!(path = %key_path.display(), public_key = %pub_hex, "generated new node key");
        return Ok(());
    }

    let keypair = if key_path.exists() {
        let kp = NodeKeyPair::load_from_file(key_path)
            .with_context(|| format!("loading node key from {}", key_path.display()))?;
        info!(
            path = %key_path.display(),
            public_key = %hex::encode(kp.public_key().as_bytes()),
            "loaded existing node key"
        );
        kp
    } else {
        info!("no node key found, generating a new one");
        let kp = NodeKeyPair::generate();
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        kp.save_to_file(key_path)?;
        info!(
            path = %key_path.display(),
            public_key = %hex::encode(kp.public_key().as_bytes()),
            "generated and saved new node key"
        );
        kp
    };

    let private_key_bytes = keypair.secret().to_bytes();

    info!(
        listen_port = cfg.listen_port,
        metrics_port = cfg.metrics_port,
        libp2p_port = cfg.libp2p_port,
        exit_mode = cfg.exit_mode,
        public_key = %hex::encode(keypair.public_key().as_bytes()),
        "ShieldNode starting"
    );

    // ── shared state ──────────────────────────────────────────────────

    let bandwidth = Arc::new(Mutex::new(BandwidthTracker::new()));

    // ── shutdown signal ───────────────────────────────────────────────

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // ── metrics HTTP server ───────────────────────────────────────────

    let metrics_addr: std::net::SocketAddr =
        format!("0.0.0.0:{}", cfg.metrics_port).parse()?;
    let app = metrics::api::router(bandwidth.clone());

    let metrics_handle = tokio::spawn(async move {
        info!(%metrics_addr, "metrics HTTP server listening");
        let listener = tokio::net::TcpListener::bind(metrics_addr)
            .await
            .expect("bind metrics port");
        axum::serve(listener, app.into_make_service())
            .await
            .expect("metrics server");
    });

    // ── heartbeat service ─────────────────────────────────────────────

    let heartbeat = HeartbeatService::new(
        cfg.ethereum_rpc.clone(),
        cfg.stake_address.clone(),
        cfg.heartbeat_interval_secs,
    );
    let heartbeat_handle = heartbeat.spawn(shutdown_rx.clone());

    // ── WireGuard tunnel listener ─────────────────────────────────────

    let mut tunnel_listener = TunnelListener::bind(
        cfg.listen_port,
        private_key_bytes,
        bandwidth.clone(),
        cfg.exit_mode,
    )
    .await
    .context("failed to bind WireGuard listener")?;

    let tunnel_handle = tokio::spawn(async move {
        if let Err(e) = tunnel_listener.run().await {
            tracing::error!(error = %e, "tunnel listener exited with error");
        }
    });

    // ── libp2p discovery (best-effort) ────────────────────────────────

    let libp2p_port = cfg.libp2p_port;
    let discovery_handle = tokio::spawn(async move {
        match network::discovery::DiscoveryService::new(libp2p_port).await {
            Ok(mut svc) => {
                info!(peer_id = %svc.local_peer_id, "libp2p discovery running");
                // Drive the swarm event loop.
                loop {
                    svc.swarm.select_next_some().await;
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "libp2p discovery failed to start (continuing without it)");
            }
        }
    });

    // ── wait for shutdown ─────────────────────────────────────────────

    info!("all services running — press Ctrl+C to stop");

    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for Ctrl+C")?;

    info!("shutdown signal received");
    let _ = shutdown_tx.send(true);

    // Give background tasks a moment to clean up.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Abort remaining tasks.
    metrics_handle.abort();
    heartbeat_handle.abort();
    tunnel_handle.abort();
    discovery_handle.abort();

    info!("ShieldNode stopped");
    Ok(())
}
