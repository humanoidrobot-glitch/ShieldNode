mod aead;
mod chain;
mod circuit;
mod config;
mod health_monitor;
mod hop_codec;
mod kex;
mod kill_switch;
mod receipts;
mod reputation;
mod sphinx;
mod tunnel;
mod wallet;
mod zk_prove;

use std::sync::{Arc, Mutex};

use alloy::primitives::Address;
use serde::{Deserialize, Serialize};
use tauri::State;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use chain::ChainReader;
use circuit::{CircuitInfo, CircuitState, NodeInfo};
use tunnel::TunnelManager;
use wallet::WalletConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected {
        node_id: String,
        session_id: String,
        bytes_used: u64,
        /// Number of hops in the active circuit (1 = single, 3 = multi-hop).
        hop_count: u32,
        /// How many times the circuit has been rotated since connect.
        rotation_count: u32,
    },
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::Disconnected
    }
}

/// Minimum number of active nodes before the client warns about collusion risk.
const MINIMUM_NETWORK_SIZE: usize = 20;

/// Contract addresses for the ShieldNode protocol on Sepolia.
const REGISTRY_ADDRESS: &str = "0xC6D9923E54547e0C7c5B456bFf16fEdF2d61df11";
const SETTLEMENT_ADDRESS: &str = "0xF32aE5324E3caCCEC4F198FEF783482A0c5eE959";

pub struct AppState {
    pub connection: Arc<Mutex<ConnectionState>>,
    pub circuit: Arc<Mutex<Option<CircuitState>>>,
    pub tunnel: Arc<Mutex<TunnelManager>>,
    pub config: Arc<Mutex<config::ClientConfig>>,
    pub chain_reader: ChainReader,
    /// Cancel token for the background circuit rotation task.
    pub rotation_cancel: Mutex<Option<CancellationToken>>,
    /// Cancel token for the circuit health monitor task.
    pub health_cancel: Mutex<Option<CancellationToken>>,
    /// Local node reputation cache (low-bandwidth flags).
    pub reputation: Arc<Mutex<reputation::ReputationCache>>,
    /// Cached completion rates with TTL (avoids N+1 RPC on every fetch_nodes).
    pub completion_rates_cache: Arc<Mutex<(std::collections::HashMap<String, f64>, std::time::Instant)>>,
}

impl Default for AppState {
    fn default() -> Self {
        let cfg = config::ClientConfig::default();
        let registry: Address = REGISTRY_ADDRESS.parse().expect("invalid registry address");
        let settlement: Address = SETTLEMENT_ADDRESS.parse().expect("invalid settlement address");
        Self {
            chain_reader: ChainReader::new(cfg.rpc_url.clone(), registry, settlement),
            connection: Arc::new(Mutex::new(ConnectionState::default())),
            circuit: Arc::new(Mutex::new(None)),
            tunnel: Arc::new(Mutex::new(TunnelManager::new())),
            config: Arc::new(Mutex::new(cfg)),
            rotation_cancel: Mutex::new(None),
            health_cancel: Mutex::new(None),
            reputation: Arc::new(Mutex::new(reputation::ReputationCache::new())),
            completion_rates_cache: Arc::new(Mutex::new((
                std::collections::HashMap::new(),
                std::time::Instant::now() - std::time::Duration::from_secs(600),
            ))),
        }
    }
}

impl AppState {
    fn wallet_config(&self) -> Result<WalletConfig, String> {
        let cfg = self.config.lock().map_err(|e| format!("lock error: {e}"))?;
        Ok(WalletConfig {
            rpc_url: cfg.rpc_url.clone(),
            chain_id: cfg.chain_id,
            private_key: cfg.operator_private_key.clone(),
            settlement_address: SETTLEMENT_ADDRESS.to_string(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkHealth {
    pub node_count: usize,
    pub minimum_threshold: usize,
    pub below_threshold: bool,
    pub estimated_collusion_risk_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub node_id: String,
    pub bytes_used: u64,
    pub connected_since: u64,
}

#[tauri::command]
async fn connect(state: State<'_, AppState>) -> Result<String, String> {
    let nodes = fetch_nodes(&state).await;

    // Minimum network size guard: warn if <20 nodes.
    if nodes.len() < MINIMUM_NETWORK_SIZE {
        warn!(
            count = nodes.len(),
            threshold = MINIMUM_NETWORK_SIZE,
            "network size below safety threshold — collusion risk is elevated"
        );
    }

    {
        let mut conn = state.connection.lock().map_err(|e| format!("lock error: {e}"))?;
        *conn = ConnectionState::Connecting;
    }

    // Read config values needed for connect (single lock acquisition).
    let (pinned, kill_switch_enabled) = {
        let cfg = state.config.lock().map_err(|e| format!("lock error: {e}"))?;
        (cfg.preferred_nodes.clone(), cfg.kill_switch)
    };
    let pin_entry = pinned.first().map(|s| s.as_str()).unwrap_or("");
    let pin_relay = pinned.get(1).map(|s| s.as_str()).unwrap_or("");
    let pin_exit = pinned.get(2).map(|s| s.as_str()).unwrap_or("");

    // Decide between 3-hop and single-hop based on available nodes.
    let (entry_node_id, hop_count) = if nodes.len() >= 3 {
        // ── 3-hop circuit ────────────────────────────────────────────
        let selected = circuit::select_circuit_with_pins(
            &nodes,
            &[],
            &[pin_entry, pin_relay, pin_exit],
        )?;
        info!(
            entry = %selected[0].node_id,
            relay = %selected[1].node_id,
            exit  = %selected[2].node_id,
            "selected 3-hop circuit"
        );

        let circuit_state = circuit::build_circuit(&selected)?;

        // Start tunnel to the entry node.
        {
            let mut tun = state.tunnel.lock().map_err(|e| format!("lock error: {e}"))?;
            tun.start_tunnel(&selected[0].endpoint, &selected[0].public_key)?;
        }

        // Register session keys on each relay node via UDP control messages.
        tunnel::register_sessions(&circuit_state).await?;

        let entry_id = selected[0].node_id.clone();

        // Store circuit state (with session keys) in backend-only state.
        {
            let mut circ = state.circuit.lock().map_err(|e| format!("lock error: {e}"))?;
            *circ = Some(circuit_state);
        }

        (entry_id, 3u32)
    } else {
        // ── single-hop fallback ──────────────────────────────────────
        let node = circuit::select_single_node(&nodes)?;
        info!(node_id = %node.node_id, endpoint = %node.endpoint, "connecting single-hop (fewer than 3 nodes)");

        {
            let mut tun = state.tunnel.lock().map_err(|e| format!("lock error: {e}"))?;
            tun.start_tunnel(&node.endpoint, &node.public_key)?;
        }

        // Clear any stale circuit state.
        {
            let mut circ = state.circuit.lock().map_err(|e| format!("lock error: {e}"))?;
            *circ = None;
        }

        (node.node_id.clone(), 1u32)
    };

    let wallet_cfg = state.wallet_config()?;

    // Open on-chain session (0.001 ETH deposit = minimum).
    let (tx_hash, session_id) = wallet::open_session(
        &wallet_cfg,
        &entry_node_id,
        1_000_000_000_000_000, // 0.001 ETH
    ).await?;

    let session_id_str = session_id.to_string();

    {
        let mut conn = state.connection.lock().map_err(|e| format!("lock error: {e}"))?;
        *conn = ConnectionState::Connected {
            node_id: entry_node_id.clone(),
            session_id: session_id_str.clone(),
            bytes_used: 0,
            hop_count,
            rotation_count: 0,
        };
    }

    // Activate kill switch if enabled — blocks non-VPN traffic to prevent IP leaks.
    if kill_switch_enabled {
        let entry_endpoint = {
            let circ = state.circuit.lock().map_err(|e| format!("lock error: {e}"))?;
            circ.as_ref()
                .map(|c| c.entry.endpoint.clone())
                .unwrap_or_else(|| entry_node_id.clone())
        };
        if let Err(e) = kill_switch::activate(&entry_endpoint) {
            warn!(error = %e, "kill switch activation failed (continuing without)");
        }
    }

    // Spawn circuit health monitor.
    {
        let cancel = CancellationToken::new();
        {
            let mut hc = state.health_cancel.lock().map_err(|e| format!("lock error: {e}"))?;
            *hc = Some(cancel.clone());
        }
        tokio::spawn(health_monitor::health_monitor_loop(
            cancel,
            Arc::clone(&state.connection),
            Arc::clone(&state.circuit),
            Arc::clone(&state.tunnel),
            state.chain_reader.clone(),
        ));
        info!("circuit health monitor started");
    }

    // Spawn circuit auto-rotation background task if enabled and multi-hop.
    if hop_count == 3 {
        let (auto_rotate, interval_secs) = {
            let cfg = state.config.lock().map_err(|e| format!("lock error: {e}"))?;
            (cfg.auto_rotate, cfg.circuit_rotation_interval_secs)
        };

        if auto_rotate && interval_secs > 0 {
            let cancel = CancellationToken::new();
            {
                let mut rc = state.rotation_cancel.lock().map_err(|e| format!("lock error: {e}"))?;
                *rc = Some(cancel.clone());
            }

            let connection = Arc::clone(&state.connection);
            let circuit = Arc::clone(&state.circuit);
            let tunnel = Arc::clone(&state.tunnel);
            let chain_reader = state.chain_reader.clone();

            tokio::spawn(rotation_loop(
                cancel,
                interval_secs,
                connection,
                circuit,
                tunnel,
                chain_reader,
            ));

            info!(interval_secs, "circuit auto-rotation enabled");
        }
    }

    info!(session_id, tx = %tx_hash, hop_count, "connected — session opened on-chain");
    Ok(session_id_str)
}

#[tauri::command]
async fn disconnect(state: State<'_, AppState>) -> Result<String, String> {
    // 0. Cancel background tasks (rotation + health monitor).
    stop_rotation(&state)?;
    stop_health_monitor(&state)?;

    // 1. Get session state (session_id, bytes_used) and exit endpoint.
    let (session_id_str, bytes_used, exit_endpoint) = {
        let conn = state.connection.lock().map_err(|e| format!("lock error: {e}"))?;
        match &*conn {
            ConnectionState::Connected { session_id, bytes_used, node_id, .. } => {
                // Determine exit endpoint from circuit state or fall back to node_id's endpoint.
                let circ = state.circuit.lock().map_err(|e| format!("lock error: {e}"))?;
                let endpoint = circ
                    .as_ref()
                    .map(|c| c.exit.endpoint.clone())
                    .unwrap_or_else(|| node_id.clone());
                (session_id.clone(), *bytes_used, endpoint)
            }
            _ => return Err("not connected".to_string()),
        }
    };

    let session_id: u64 = session_id_str
        .parse()
        .map_err(|e| format!("invalid session id: {e}"))?;

    // 2. Create a BandwidthReceipt with the current timestamp.
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    info!(
        session_id,
        bytes_used,
        timestamp,
        "preparing EIP-712 bandwidth receipt for settlement"
    );

    // 3. Parse the client's private key and sign the EIP-712 digest.
    let (wallet_cfg, chain_id) = {
        let cfg = state.config.lock().map_err(|e| format!("lock error: {e}"))?;
        let wc = state.wallet_config()?;
        (wc, cfg.chain_id)
    };

    let signer = wallet_cfg.parse_signer()?;

    let settlement_address: Address = SETTLEMENT_ADDRESS
        .parse()
        .map_err(|e| format!("invalid settlement address: {e}"))?;

    let domain_sep = receipts::compute_domain_separator(chain_id, settlement_address);
    let digest =
        receipts::compute_receipt_digest(&domain_sep, session_id, bytes_used, timestamp);
    let client_sig = receipts::sign_receipt(&digest, &signer).await?;

    info!(
        session_id,
        client_sig_len = client_sig.len(),
        "client EIP-712 signature produced, requesting node co-signature"
    );

    // 4. Send to exit node for co-signing.
    let node_sig = tunnel::request_receipt_cosign(
        &exit_endpoint,
        session_id,
        bytes_used,
        timestamp,
        &client_sig,
    )
    .await?;

    info!(
        session_id,
        node_sig_len = node_sig.len(),
        "received node co-signature"
    );

    // 5. ABI-encode the dual-signed receipt.
    let receipt_data = receipts::encode_settlement_receipt(
        session_id,
        bytes_used,
        timestamp,
        &client_sig,
        &node_sig,
    );

    // 6. Stop the tunnel before the on-chain call.
    {
        let mut tun = state.tunnel.lock().map_err(|e| format!("lock error: {e}"))?;
        tun.stop_tunnel()?;
    }

    // 7. Call settle_session with the real receipt.
    let tx_hash = wallet::settle_session(&wallet_cfg, session_id, receipt_data).await?;

    // Capture circuit node IDs for reputation tracking before clearing.
    let circuit_node_ids: Vec<String> = {
        let circ = state.circuit.lock().map_err(|e| format!("lock error: {e}"))?;
        circ.as_ref()
            .map(|c| vec![c.entry.node_id.clone(), c.relay.node_id.clone(), c.exit.node_id.clone()])
            .unwrap_or_default()
    };

    // Clear circuit state.
    {
        let mut circ = state.circuit.lock().map_err(|e| format!("lock error: {e}"))?;
        *circ = None;
    }

    {
        let mut conn = state.connection.lock().map_err(|e| format!("lock error: {e}"))?;
        *conn = ConnectionState::Disconnected;
    }

    // Record session outcome for local reputation tracking.
    if !circuit_node_ids.is_empty() {
        let session_duration = std::time::Duration::from_secs(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .saturating_sub(timestamp)
        );
        if let Ok(mut rep) = state.reputation.lock() {
            rep.record_session(&circuit_node_ids, bytes_used, session_duration);
        }
    }

    // Deactivate kill switch — restore normal traffic.
    if let Err(e) = kill_switch::deactivate() {
        warn!(error = %e, "kill switch deactivation failed");
    }

    info!(tx = %tx_hash, "disconnected and session settled with EIP-712 receipt");
    Ok(tx_hash)
}

/// Return the current connection status.
#[tauri::command]
async fn get_status(state: State<'_, AppState>) -> Result<ConnectionState, String> {
    let conn = state
        .connection
        .lock()
        .map_err(|e| format!("lock error: {e}"))?;
    Ok(conn.clone())
}

#[tauri::command]
async fn get_nodes(state: State<'_, AppState>) -> Result<Vec<NodeInfo>, String> {
    Ok(fetch_nodes(&state).await)
}

/// Return information about the active session, if any.
#[tauri::command]
async fn get_session(state: State<'_, AppState>) -> Result<Option<SessionInfo>, String> {
    let conn = state
        .connection
        .lock()
        .map_err(|e| format!("lock error: {e}"))?;

    match &*conn {
        ConnectionState::Connected {
            node_id,
            session_id,
            bytes_used,
            ..
        } => Ok(Some(SessionInfo {
            session_id: session_id.clone(),
            node_id: node_id.clone(),
            bytes_used: *bytes_used,
            connected_since: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })),
        _ => Ok(None),
    }
}

/// Return sanitised circuit info (no session keys) for the frontend.
#[tauri::command]
async fn get_circuit(state: State<'_, AppState>) -> Result<Option<CircuitInfo>, String> {
    let circ = state
        .circuit
        .lock()
        .map_err(|e| format!("lock error: {e}"))?;
    Ok(circ.as_ref().map(|c| c.to_info()))
}

/// Return the current network gas price in Gwei.
///
/// Fetches the real gas price from the RPC provider. Falls back to the
/// wallet stub if the on-chain read fails.
#[tauri::command]
async fn get_gas_price(state: State<'_, AppState>) -> Result<u64, String> {
    match state.chain_reader.get_gas_price().await {
        Ok(gwei) => Ok(gwei),
        Err(e) => {
            warn!(error = %e, "on-chain gas price fetch failed, using wallet fallback");
            let rpc_url = {
                let cfg = state
                    .config
                    .lock()
                    .map_err(|e| format!("lock error: {e}"))?;
                cfg.rpc_url.clone()
            };
            wallet::get_gas_price(&rpc_url).await
        }
    }
}

/// Return network health: node count, safety threshold, and estimated collusion risk.
#[tauri::command]
async fn get_network_health(state: State<'_, AppState>) -> Result<NetworkHealth, String> {
    let nodes = fetch_nodes(&state).await;
    let n = nodes.len() as f64;
    // Probability of a single attacker node capturing both entry+exit: (1/n)².
    // With diversity constraints this is a lower bound; real risk is lower.
    let collusion_risk = if n >= 3.0 { (1.0 / n).powi(2) * 100.0 } else { 100.0 };
    Ok(NetworkHealth {
        node_count: nodes.len(),
        minimum_threshold: MINIMUM_NETWORK_SIZE,
        below_threshold: nodes.len() < MINIMUM_NETWORK_SIZE,
        estimated_collusion_risk_pct: collusion_risk,
    })
}

/// Return the current settings (excludes private key).
#[tauri::command]
async fn get_settings(state: State<'_, AppState>) -> Result<config::SettingsPayload, String> {
    let cfg = state.config.lock().map_err(|e| format!("lock error: {e}"))?;
    Ok(config::SettingsPayload::from(&*cfg))
}

/// Update settings from the frontend. Changes take effect on next connect().
#[tauri::command]
async fn update_settings(
    state: State<'_, AppState>,
    settings: config::SettingsPayload,
) -> Result<(), String> {
    // Apply settings and clone for disk persistence, then drop the lock
    // before doing blocking I/O.
    let snapshot = {
        let mut cfg = state.config.lock().map_err(|e| format!("lock error: {e}"))?;
        cfg.apply_settings(&settings);
        cfg.clone()
    };

    // Persist to disk (best-effort, outside the lock).
    let config_path = std::env::current_dir()
        .unwrap_or_default()
        .join("shieldnode-client.json");
    if let Err(e) = snapshot.save(&config_path) {
        warn!(error = %e, "failed to persist settings to disk");
    }

    info!("settings updated");
    Ok(())
}

/// Send a raw IP packet through the 3-hop Sphinx circuit.
///
/// The packet is wrapped in three Sphinx onion layers and sent to the entry
/// node's relay port over UDP.  This is a test command — full system-wide
/// traffic capture (TUN integration) comes later.
#[tauri::command]
async fn send_packet(
    state: State<'_, AppState>,
    packet: Vec<u8>,
) -> Result<String, String> {
    let circuit_state = {
        let circ = state.circuit.lock().map_err(|e| format!("lock error: {e}"))?;
        circ.clone().ok_or_else(|| "no active circuit".to_string())?
    };

    // Check if we already have a cached socket.
    let existing = {
        let tun = state.tunnel.lock().map_err(|e| format!("lock error: {e}"))?;
        tun.relay_socket.clone()
    };
    let socket = match existing {
        Some(s) => s,
        None => {
            let sock = Arc::new(
                tokio::net::UdpSocket::bind("0.0.0.0:0").await
                    .map_err(|e| format!("failed to bind relay socket: {e}"))?
            );
            let mut tun = state.tunnel.lock().map_err(|e| format!("lock error: {e}"))?;
            tun.relay_socket = Some(Arc::clone(&sock));
            sock
        }
    };

    let route = circuit_state.build_sphinx_route();
    let sphinx_pkt = sphinx::SphinxPacket::create(&route, &packet)?;
    let sphinx_bytes = sphinx_pkt.to_bytes();

    tunnel::send_sphinx_packet(
        &socket,
        &circuit_state.entry.endpoint,
        circuit_state.entry.session_id,
        &sphinx_bytes,
    )
    .await?;

    Ok(format!("sent {} bytes through circuit", sphinx_bytes.len()))
}

// ── Circuit rotation ──────────────────────────────────────────────────────

/// Cancel the background rotation task, if any.
fn stop_rotation(state: &AppState) -> Result<(), String> {
    let mut rc = state
        .rotation_cancel
        .lock()
        .map_err(|e| format!("lock error: {e}"))?;
    if let Some(token) = rc.take() {
        token.cancel();
        info!("circuit rotation task cancelled");
    }
    Ok(())
}

/// Cancel the background health monitor task, if any.
fn stop_health_monitor(state: &AppState) -> Result<(), String> {
    let mut hc = state
        .health_cancel
        .lock()
        .map_err(|e| format!("lock error: {e}"))?;
    if let Some(token) = hc.take() {
        token.cancel();
        info!("health monitor task cancelled");
    }
    Ok(())
}

/// Background loop that rotates the circuit on a fixed interval.
async fn rotation_loop(
    cancel: CancellationToken,
    interval_secs: u64,
    connection: Arc<Mutex<ConnectionState>>,
    circuit: Arc<Mutex<Option<CircuitState>>>,
    tunnel: Arc<Mutex<TunnelManager>>,
    chain_reader: ChainReader,
) {
    let interval = std::time::Duration::from_secs(interval_secs);
    let mut count: u32 = 0;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("rotation loop cancelled");
                return;
            }
            _ = tokio::time::sleep(interval) => {}
        }

        info!("circuit rotation triggered");

        // 1. Teardown old sessions.
        let old_circuit = {
            let Ok(circ) = circuit.lock() else {
                warn!("circuit mutex poisoned, stopping rotation");
                return;
            };
            circ.clone()
        };
        if let Some(ref old) = old_circuit {
            tunnel::teardown_sessions(old).await;
        }

        // 2. Fetch nodes.
        let nodes = match chain_reader.get_active_nodes().await {
            Ok(on_chain) if on_chain.len() >= 3 => {
                on_chain.into_iter().map(map_on_chain_node).collect::<Vec<_>>()
            }
            Ok(_) => {
                warn!("fewer than 3 nodes available, skipping rotation");
                continue;
            }
            Err(e) => {
                warn!(error = %e, "failed to fetch nodes for rotation, skipping");
                continue;
            }
        };

        // 3. Build exclude list from old circuit.
        let exclude_ids: Vec<&str> = old_circuit
            .as_ref()
            .map(|c| vec![
                c.entry.node_id.as_str(),
                c.relay.node_id.as_str(),
                c.exit.node_id.as_str(),
            ])
            .unwrap_or_default();

        let selected = match circuit::select_circuit(&nodes, &exclude_ids) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "failed to select rotation circuit, skipping");
                continue;
            }
        };

        info!(
            entry = %selected[0].node_id,
            relay = %selected[1].node_id,
            exit  = %selected[2].node_id,
            "selected new circuit for rotation"
        );

        // 4. Build new circuit and register sessions.
        let new_circuit = match circuit::build_circuit(&selected) {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "failed to build rotation circuit, skipping");
                continue;
            }
        };

        if let Err(e) = tunnel::register_sessions(&new_circuit).await {
            warn!(error = %e, "failed to register sessions on new circuit, skipping");
            continue;
        }

        // 5. Reconnect tunnel to new entry node.
        {
            let Ok(mut tun) = tunnel.lock() else {
                warn!("tunnel mutex poisoned, stopping rotation");
                return;
            };
            if let Err(e) = tun.start_tunnel(&selected[0].endpoint, &selected[0].public_key) {
                warn!(error = %e, "failed to start tunnel to new entry, skipping rotation");
                continue;
            }
        }

        // 6. Swap circuit state.
        {
            let Ok(mut circ) = circuit.lock() else {
                warn!("circuit mutex poisoned, stopping rotation");
                return;
            };
            *circ = Some(new_circuit);
        }

        // 7. Update rotation count.
        count += 1;
        {
            let Ok(mut conn) = connection.lock() else {
                warn!("connection mutex poisoned, stopping rotation");
                return;
            };
            if let ConnectionState::Connected {
                ref mut node_id,
                ref mut rotation_count,
                ..
            } = *conn
            {
                *node_id = selected[0].node_id.clone();
                *rotation_count = count;
            }
        }

        info!(
            rotation_count = count,
            entry = %selected[0].node_id,
            "circuit rotation complete"
        );
    }
}

// Helpers
// ──────────────────────────────────────────────────────────────────────────

/// Convert an on-chain node record to the client's internal `NodeInfo`.
pub(crate) fn map_on_chain_node(n: chain::OnChainNodeInfo) -> NodeInfo {
    NodeInfo {
        node_id: n.node_id,
        public_key: decode_hex_bytes(&n.public_key),
        endpoint: n.endpoint,
        stake: (n.stake * 1e18) as u64,
        uptime: n.uptime,
        price_per_byte: n.price_per_byte as u64,
        slash_count: n.slash_count,
        completion_rate: 1.0,
        operator_address: String::new(), // populated when owner is read from registry
        asn: None,
        region: None,
    }
}

/// Completion rate cache TTL (10 minutes).
const COMPLETION_RATE_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// Fetch nodes from on-chain registry, falling back to mock data.
/// Enriches nodes with completion rates (cached) and local reputation penalties.
async fn fetch_nodes(state: &AppState) -> Vec<NodeInfo> {
    // Use cached completion rates if fresh; otherwise refresh.
    let cached = {
        let cache = state.completion_rates_cache.lock().ok();
        cache.and_then(|c| {
            if c.1.elapsed() < COMPLETION_RATE_TTL {
                Some(c.0.clone())
            } else {
                None
            }
        })
    };
    let completion_rates = match cached {
        Some(rates) => rates,
        None => {
            let fresh = state
                .chain_reader
                .get_completion_rates()
                .await
                .unwrap_or_default();
            if let Ok(mut cache) = state.completion_rates_cache.lock() {
                *cache = (fresh.clone(), std::time::Instant::now());
            }
            fresh
        }
    };

    // Evict stale reputation flags and run stake concentration analysis.
    if let Ok(mut rep) = state.reputation.lock() {
        rep.evict_stale();
    }

    let mut nodes = match state.chain_reader.get_active_nodes().await {
        Ok(on_chain) if !on_chain.is_empty() => {
            info!(count = on_chain.len(), "fetched on-chain nodes");
            on_chain
                .into_iter()
                .map(|n| {
                    let mut node = map_on_chain_node(n);
                    if let Some(&rate) = completion_rates.get(&node.node_id) {
                        node.completion_rate = rate;
                    }
                    node
                })
                .collect::<Vec<_>>()
        }
        Ok(_) => {
            warn!("on-chain registry empty, using mock data");
            mock_nodes()
        }
        Err(e) => {
            warn!(error = %e, "on-chain read failed, using mock data");
            mock_nodes()
        }
    };

    // Run stake concentration analysis (brief lock for detection).
    if let Ok(mut rep) = state.reputation.lock() {
        let flagged = rep.detect_stake_clusters(&nodes);
        if !flagged.is_empty() {
            info!(count = flagged.len(), "stake concentration clusters detected");
        }
    }

    // Apply reputation penalties (separate brief lock).
    if let Ok(rep) = state.reputation.lock() {
        for node in &mut nodes {
            if rep.score_penalty(&node.node_id) > 0.0 {
                node.completion_rate = 0.0;
            }
        }
    }

    nodes
}

/// Decode a 0x-prefixed hex string into bytes. Returns empty vec on failure.
fn decode_hex_bytes(hex_str: &str) -> Vec<u8> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if stripped.len() % 2 != 0 { return Vec::new(); }
    let mut out = Vec::with_capacity(stripped.len() / 2);
    for chunk in stripped.as_bytes().chunks(2) {
        if let Ok(s) = std::str::from_utf8(chunk) {
            if let Ok(byte) = u8::from_str_radix(s, 16) {
                out.push(byte);
            } else {
                return Vec::new();
            }
        }
    }
    out
}

// Mock helpers
// ──────────────────────────────────────────────────────────────────────────

/// Generate a small set of mock nodes for development / testing.
/// Stakes are in wei (1 ETH = 1e18 wei).
fn mock_nodes() -> Vec<NodeInfo> {
    const ETH: u64 = 1_000_000_000_000_000_000; // 1e18
    vec![
        NodeInfo {
            node_id: "node-alpha-001".to_string(),
            public_key: vec![1u8; 32],
            endpoint: "203.0.113.10:51820".to_string(),
            stake: ETH,
            uptime: 0.995,
            price_per_byte: 10,
            slash_count: 0,
            completion_rate: 1.0,
            operator_address: "0xOp1".to_string(),
            asn: Some(13335),
            region: Some("EU-WEST".to_string()),
        },
        NodeInfo {
            node_id: "node-beta-002".to_string(),
            public_key: vec![2u8; 32],
            endpoint: "198.51.100.20:51820".to_string(),
            stake: ETH * 3 / 4,
            uptime: 0.980,
            price_per_byte: 15,
            slash_count: 0,
            completion_rate: 1.0,
            operator_address: "0xOp2".to_string(),
            asn: Some(16509),
            region: Some("US-EAST".to_string()),
        },
        NodeInfo {
            node_id: "node-gamma-003".to_string(),
            public_key: vec![3u8; 32],
            endpoint: "192.0.2.30:51820".to_string(),
            stake: ETH / 2,
            uptime: 0.960,
            price_per_byte: 8,
            slash_count: 1,
            completion_rate: 0.7,
            operator_address: "0xOp3".to_string(),
            asn: Some(20473),
            region: Some("EU-CENTRAL".to_string()),
        },
        NodeInfo {
            node_id: "node-delta-004".to_string(),
            public_key: vec![4u8; 32],
            endpoint: "198.51.100.40:51820".to_string(),
            stake: ETH * 2,
            uptime: 0.999,
            price_per_byte: 20,
            slash_count: 0,
            completion_rate: 1.0,
            operator_address: "0xOp4".to_string(),
            asn: Some(14618),
            region: Some("ASIA-EAST".to_string()),
        },
        NodeInfo {
            node_id: "node-epsilon-005".to_string(),
            public_key: vec![5u8; 32],
            endpoint: "203.0.113.50:51820".to_string(),
            stake: ETH / 10,
            uptime: 0.850,
            price_per_byte: 5,
            slash_count: 2,
            completion_rate: 0.4,
            operator_address: "0xOp5".to_string(),
            asn: Some(24940),
            region: Some("US-WEST".to_string()),
        },
    ]
}

//Tauri entry point
// ──────────────────────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            connect,
            disconnect,
            get_status,
            get_nodes,
            get_session,
            get_circuit,
            get_gas_price,
            get_network_health,
            get_settings,
            update_settings,
            send_packet,
        ])
        .run(tauri::generate_context!())
        .expect("error while running ShieldNode client");
}
