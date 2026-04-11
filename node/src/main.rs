mod config;
mod crypto;
mod metrics;
mod network;
mod tunnel;

use std::path::Path;
use std::sync::Arc;

use alloy::primitives::{Address, FixedBytes};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use clap::Parser;
use futures::StreamExt;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crypto::keys::NodeKeyPair;
use metrics::bandwidth::BandwidthTracker;
use network::chain::ChainService;
use network::heartbeat::HeartbeatService;
use network::link_padding::{link_padding_loop, LinkPaddingManager};
use network::relay::RelayService;
use network::relay_listener::RelayListener;
use tunnel::listener::TunnelListener;
use tunnel::tun_device::{TunConfig, TunDevice};

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

/// Derive the uncompressed secp256k1 public key (64 bytes: x || y) from a
/// 32-byte private key.  The contract stores these coordinates and verifies
/// that `keccak256(x || y)` matches `msg.sender`.
fn derive_secp256k1_pubkey(private_key: &[u8; 32]) -> Result<[u8; 64]> {
    use k256::ecdsa::SigningKey;

    let signing_key =
        SigningKey::from_bytes(private_key.into()).context("invalid secp256k1 private key")?;
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false); // uncompressed (0x04 || x || y)
    let uncompressed = encoded.as_bytes();
    // Strip the 0x04 prefix — contract expects raw 64-byte x || y.
    let mut out = [0u8; 64];
    out.copy_from_slice(&uncompressed[1..65]);
    Ok(out)
}

/// Build a `ChainService` from configuration values and the node's public key.
fn build_chain_service(cfg: &config::NodeConfig, node_id: [u8; 32]) -> Result<ChainService> {
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

    let mut cfg = config::NodeConfig::load(&cli.config).unwrap_or_else(|e| {
        info!("config load failed ({e}), using defaults");
        config::NodeConfig::default()
    });

    if let Some(port) = cli.listen_port {
        cfg.listen_port = port;
    }

    // ── key management ────────────────────────────────────────────────

    let key_path = Path::new(&cfg.node_private_key_path);

    if cli.generate_key {
        let (keypair, _) =
            NodeKeyPair::load_or_generate(key_path).context("generating node key")?;
        info!(
            path = %key_path.display(),
            public_key = %hex::encode(keypair.public_key_bytes()),
            "node key ready"
        );
        return Ok(());
    }

    let (keypair, was_generated) = NodeKeyPair::load_or_generate(key_path)
        .with_context(|| format!("loading node key from {}", key_path.display()))?;

    if was_generated {
        info!(
            path = %key_path.display(),
            public_key = %hex::encode(keypair.public_key_bytes()),
            "generated new node key"
        );
    } else {
        info!(
            path = %key_path.display(),
            public_key = %hex::encode(keypair.public_key_bytes()),
            "loaded existing node key"
        );
    }

    let private_key_bytes = keypair.secret_kem().to_bytes();
    let public_key_bytes: [u8; 32] = keypair.public_key_bytes();

    // Use the public key as the node_id (a simple, unique 32-byte identifier).
    let node_id = public_key_bytes;

    // ── --register: on-chain registration then exit ───────────────────

    if cli.register {
        // Parse the operator private key once and reuse for both
        // ChainService construction and secp256k1 pubkey derivation.
        let operator_key_hex = cfg
            .operator_private_key
            .as_deref()
            .context("operator_private_key required for registration")?;
        let operator_key = parse_hex_private_key(operator_key_hex)?;

        let registry_addr: Address = cfg
            .stake_address
            .as_deref()
            .unwrap_or(DEFAULT_REGISTRY_ADDRESS)
            .parse()
            .context("invalid registry/stake_address")?;

        let chain = ChainService::new(
            cfg.ethereum_rpc.clone(),
            registry_addr,
            node_id,
            operator_key,
        );

        let endpoint = format!("0.0.0.0:{}", cfg.listen_port);

        // Derive the secp256k1 public key from the already-parsed operator key.
        // The contract verifies keccak256(secp256k1Key) == msg.sender.
        let secp_pubkey = derive_secp256k1_pubkey(&operator_key)?;

        info!(
            endpoint = %endpoint,
            stake_wei = DEFAULT_STAKE_WEI,
            "registering node on-chain"
        );

        let tx_hash = chain
            .register(public_key_bytes, &endpoint, DEFAULT_STAKE_WEI, &secp_pubkey)
            .await
            .context("on-chain registration failed")?;

        info!(tx_hash = %tx_hash, "node registered on-chain");
        println!("Registration tx: {tx_hash}");
        return Ok(());
    }

    // ── UPnP port mapping ──────────────────────────────────────────────

    if cfg.upnp_enabled {
        let mappings = network::nat::relay_port_mappings(
            cfg.listen_port,
            cfg.relay_port,
            cfg.libp2p_port,
        );
        match network::nat::attempt_upnp_mappings(&mappings).await {
            Ok(external_ip) => {
                info!(external_ip = %external_ip, "UPnP port mappings established");
            }
            Err(e) => {
                warn!(error = %e, "UPnP unavailable — ensure ports are manually forwarded");
            }
        }
    }

    // ── normal startup ────────────────────────────────────────────────

    info!(
        listen_port = cfg.listen_port,
        relay_port = cfg.relay_port,
        metrics_port = cfg.metrics_port,
        libp2p_port = cfg.libp2p_port,
        exit_mode = cfg.exit_mode,
        public_key = %hex::encode(keypair.public_key_bytes()),
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
            Err(e) => {
                error!(error = %e, "invalid metrics address");
                return;
            }
        };
        let app = metrics::api::router(metrics_bw);
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                error!(error = %e, port = metrics_port, "failed to bind metrics port");
                return;
            }
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

    let heartbeat = HeartbeatService::new(chain_service, cfg.heartbeat_interval_secs);
    let heartbeat_handle = heartbeat.spawn(shutdown_rx.clone());

    // ── TUN device (shared between tunnel and relay listeners) ─────────

    let tun: Option<Arc<TunDevice>> = if cfg.exit_mode {
        let tun_config = TunConfig {
            address: cfg.tun_address.clone(),
            netmask: cfg.tun_netmask,
            name: "shieldnode".to_string(),
        };
        match TunDevice::create(&tun_config).await {
            Ok(dev) => {
                info!("TUN device ready for exit-mode forwarding");
                Some(Arc::new(dev))
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "failed to create TUN device — exit forwarding disabled. \
                     Run as administrator/root to enable TUN."
                );
                None
            }
        }
    } else {
        None
    };

    // ── WireGuard tunnel listener ─────────────────────────────────────

    let mut tunnel_listener = TunnelListener::bind(
        cfg.listen_port,
        private_key_bytes,
        bandwidth.clone(),
        cfg.exit_mode,
        tun.clone(),
    )
    .await
    .context("failed to bind WireGuard listener")?;

    let tunnel_handle = tokio::spawn(async move {
        if let Err(e) = tunnel_listener.run().await {
            error!(error = %e, "tunnel listener exited with error");
        }
    });

    // ── relay listener (multi-hop forwarding) ─────────────────────────

    let relay_service = Arc::new(tokio::sync::RwLock::new(RelayService::new(bandwidth.clone())));

    let batch_buffer = if cfg.batch_reorder_enabled {
        Some(Arc::new(tokio::sync::Mutex::new(
            network::batch_reorder::BatchBuffer::new(cfg.batch_window_ms),
        )))
    } else {
        None
    };

    let link_padding_mgr = if cfg.link_padding_enabled {
        Some(Arc::new(tokio::sync::Mutex::new(
            LinkPaddingManager::new(cfg.link_padding_pps),
        )))
    } else {
        None
    };

    // Build operator signer and settlement address for EIP-712 receipt
    // co-signing (all three must be present to enable the feature).
    let operator_signer: Option<PrivateKeySigner> = cfg
        .operator_private_key
        .as_deref()
        .and_then(|hex_str| {
            parse_hex_private_key(hex_str)
                .ok()
                .and_then(|key_bytes| {
                    PrivateKeySigner::from_bytes(&FixedBytes::from(key_bytes))
                        .map_err(|e| {
                            warn!(error = %e, "failed to create operator PrivateKeySigner");
                            e
                        })
                        .ok()
                })
        });

    let settlement_address: Option<Address> = cfg
        .settlement_address
        .as_deref()
        .and_then(|s| {
            s.parse::<Address>()
                .map_err(|e| {
                    warn!(error = %e, "invalid settlement_address in config");
                    e
                })
                .ok()
        });

    let (relay_listener, relay_socket) = RelayListener::bind(
        cfg.relay_port,
        relay_service,
        tun,
        bandwidth.clone(),
        operator_signer,
        Some(cfg.chain_id),
        settlement_address,
        link_padding_mgr.clone(),
        batch_buffer.clone(),
    )
    .await
    .context("failed to bind relay listener")?;

    let relay_handle = tokio::spawn(async move {
        if let Err(e) = relay_listener.run().await {
            error!(error = %e, "relay listener exited with error");
        }
    });

    // Clone relay socket for each background task that needs it.
    let socket_for_batch = relay_socket.clone();

    let link_padding_state = if let Some(mgr) = link_padding_mgr {
        let stop = Arc::new(tokio::sync::Notify::new());
        let handle = tokio::spawn(link_padding_loop(stop.clone(), relay_socket, mgr));
        Some((stop, handle))
    } else {
        None
    };

    // ── batch reorder (opt-in timing attack mitigation) ────────────────

    let batch_stop = if let Some(ref bb) = batch_buffer {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_clone = stop.clone();
        let bb_clone = bb.clone();
        tokio::spawn(network::batch_reorder::batch_flush_loop(stop_clone, socket_for_batch, bb_clone));
        info!(window_ms = cfg.batch_window_ms, "batch reorder loop spawned");
        Some(stop)
    } else {
        None
    };

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
    if let Some((ref stop, _)) = link_padding_state {
        stop.notify_one();
    }
    if let Some(ref stop) = batch_stop {
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    // Give tasks a chance to finish gracefully, then abort stragglers.
    let padding_handle = link_padding_state.map(|(_, h)| h);
    let timeout = tokio::time::sleep(std::time::Duration::from_secs(5));
    tokio::select! {
        _ = metrics_handle => {}
        _ = heartbeat_handle => {}
        _ = tunnel_handle => {}
        _ = relay_handle => {}
        _ = discovery_handle => {}
        _ = async { if let Some(h) = padding_handle { let _ = h.await; } } => {}
        _ = timeout => {
            warn!("graceful shutdown timed out, aborting remaining tasks");
        }
    }

    info!("ShieldNode stopped");
    Ok(())
}
