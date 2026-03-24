mod config;
mod crypto;
mod metrics;
mod network;
mod tunnel;

use std::path::Path;
use std::sync::Arc;

use alloy::primitives::Address;
use anyhow::{Context, Result};
use clap::Parser;
use futures::StreamExt;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crypto::keys::NodeKeyPair;
use metrics::bandwidth::BandwidthTracker;
use network::chain::ChainService;
use network::heartbeat::HeartbeatService;
use tunnel::listener::TunnelListener;

/// Default Sepolia NodeRegistry contract address.
const DEFAULT_REGISTRY_ADDRESS: &str = "0xC6D9923E54547e0C7c5B456bFf16fEdF2d61df11";

/// Default registration stake: 0.1 ETH in wei.
const DEFAULT_STAKE_WEI: u128 = 100_000_000_000_000_000; // 0.1 ETH

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

    /// Register the node on-chain and exit
    #[arg(long)]
    register: bool,
}

/// Parse a hex-encoded 32-byte private key string into a `[u8; 32]`.
fn parse_hex_private_key(hex_str: &str) -> Result<[u8; 32]> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped).context("invalid hex in operator_private_key")?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "operator_private_key must be 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        );
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Build a `ChainService` from configuration values and the node's public key.
fn build_chain_service(
    cfg: &config::NodeConfig,
    node_id: [u8; 32],
) -> Result<ChainService> {
    let operator_key_hex = cfg
        .operator_private_key
        .as_deref()
        .context("operator_private_key is required for on-chain operations")?;

    let operator_key = parse_hex_private_key(operator_key_hex)?;

    let registry_addr: Address = cfg
        .stake_address
        .as_deref()
        .unwrap_or(DEFAULT_REGISTRY_ADDRESS)
        .parse()
        .context("invalid registry/stake_address")?;

    Ok(ChainService::new(
        cfg.ethereum_rpc.clone(),
        registry_addr,
        node_id,
        operator_key,
    ))
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
        let (keypair, _) = NodeKeyPair::load_or_generate(key_path)
            .context("generating node key")?;
        info!(
            path = %key_path.display(),
            public_key = %hex::encode(keypair.public_key().as_bytes()),
            "node key ready"
        );
        return Ok(());
    }

    let (keypair, was_generated) = NodeKeyPair::load_or_generate(key_path)
        .with_context(|| format!("loading node key from {}", key_path.display()))?;

    if was_generated {
        info!(
            path = %key_path.display(),
            public_key = %hex::encode(keypair.public_key().as_bytes()),
            "generated new node key"
        );
    } else {
        info!(
            path = %key_path.display(),
            public_key = %hex::encode(keypair.public_key().as_bytes()),
            "loaded existing node key"
        );
    }

    let private_key_bytes = keypair.secret().to_bytes();
    let public_key_bytes: [u8; 32] = *keypair.public_key().as_bytes();

    // Use the public key as the node_id (a simple, unique 32-byte identifier).
    let node_id = public_key_bytes;

    // ── --register: on-chain registration then exit ───────────────────

    if cli.register {
        let chain = build_chain_service(&cfg, node_id)
            .context("building ChainService for registration")?;

        let endpoint = format!("0.0.0.0:{}", cfg.listen_port);

        info!(
            endpoint = %endpoint,
            stake_wei = DEFAULT_STAKE_WEI,
            "registering node on-chain"
        );

        let tx_hash = chain
            .register(public_key_bytes, &endpoint, DEFAULT_STAKE_WEI)
            .await
            .context("on-chain registration failed")?;

        info!(tx_hash = %tx_hash, "node registered on-chain");
        println!("Registration tx: {tx_hash}");
        return Ok(());
    }

    // ── normal startup ────────────────────────────────────────────────

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

    let metrics_port = cfg.metrics_port;
    let metrics_bw = bandwidth.clone();
    let metrics_handle = tokio::spawn(async move {
        let addr: std::net::SocketAddr = match format!("0.0.0.0:{metrics_port}").parse() {
            Ok(a) => a,
            Err(e) => { error!(error = %e, "invalid metrics address"); return; }
        };
        let app = metrics::api::router(metrics_bw);
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => { error!(error = %e, port = metrics_port, "failed to bind metrics port"); return; }
        };
        info!(%addr, "metrics HTTP server listening");
        if let Err(e) = axum::serve(listener, app.into_make_service()).await {
            error!(error = %e, "metrics server exited with error");
        }
    });

    // ── chain service (optional) ──────────────────────────────────────

    let chain_service: Option<Arc<ChainService>> =
        if cfg.stake_address.is_some() && cfg.operator_private_key.is_some() {
            match build_chain_service(&cfg, node_id) {
                Ok(svc) => {
                    info!("chain service initialised for on-chain heartbeats");
                    Some(Arc::new(svc))
                }
                Err(e) => {
                    warn!(error = %e, "failed to create chain service — heartbeats will be no-ops");
                    None
                }
            }
        } else {
            None
        };

    // ── heartbeat service ─────────────────────────────────────────────

    let heartbeat = HeartbeatService::new(
        chain_service,
        cfg.heartbeat_interval_secs,
    );
    let heartbeat_handle = heartbeat.spawn(shutdown_rx.clone());

    // ── WireGuard tunnel listener ─────────────────────────────────────

    let tun_config = tunnel::tun_device::TunConfig {
        address: cfg.tun_address.clone(),
        netmask: cfg.tun_netmask,
        name: "shieldnode".to_string(),
    };

    let mut tunnel_listener = TunnelListener::bind(
        cfg.listen_port,
        private_key_bytes,
        bandwidth.clone(),
        cfg.exit_mode,
        tun_config,
    )
    .await
    .context("failed to bind WireGuard listener")?;

    let tunnel_handle = tokio::spawn(async move {
        if let Err(e) = tunnel_listener.run().await {
            error!(error = %e, "tunnel listener exited with error");
        }
    });

    // ── libp2p discovery (best-effort) ────────────────────────────────

    let libp2p_port = cfg.libp2p_port;
    let discovery_handle = tokio::spawn(async move {
        match network::discovery::DiscoveryService::new(libp2p_port).await {
            Ok(mut svc) => {
                info!(peer_id = %svc.local_peer_id, "libp2p discovery running");
                loop {
                    svc.swarm.select_next_some().await;
                }
            }
            Err(e) => {
                warn!(error = %e, "libp2p discovery failed to start (continuing without it)");
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

    // Give tasks a chance to finish gracefully, then abort stragglers.
    let timeout = tokio::time::sleep(std::time::Duration::from_secs(5));
    tokio::select! {
        _ = metrics_handle => {}
        _ = heartbeat_handle => {}
        _ = tunnel_handle => {}
        _ = discovery_handle => {}
        _ = timeout => {
            warn!("graceful shutdown timed out, aborting remaining tasks");
        }
    }

    info!("ShieldNode stopped");
    Ok(())
}
