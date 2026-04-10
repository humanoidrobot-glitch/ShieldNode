mod aead;
mod chain;
pub mod circuit;
mod config;
mod cover_traffic;
mod health_monitor;
mod hop_codec;
mod kex;
mod kill_switch;
mod receipts;
pub mod reputation;
mod settlement;
mod sphinx;
mod tunnel;
mod wallet;
mod watchlist;
mod zk_merkle;
mod zk_prove;
mod zk_witness;

use std::sync::{Arc, Mutex};

use alloy::primitives::Address;
use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
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
        /// Original deposit amount in wei (for ZK settlement).
        deposit_wei: u128,
        /// Deposit ID from ZKSettlement.deposit() (None if ZK not used).
        #[serde(skip)]
        zk_deposit_id: Option<[u8; 32]>,
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
    /// Cancel token for the cover traffic generator.
    pub cover_cancel: Mutex<Option<CancellationToken>>,
    /// Real packet counter (shared with cover traffic generator).
    pub real_packet_counter: Arc<std::sync::atomic::AtomicU64>,
    /// Cached completion rates with TTL (avoids N+1 RPC on every fetch_nodes).
    pub completion_rates_cache: Arc<Mutex<(std::collections::HashMap<String, f64>, std::time::Instant)>>,
    /// Cached node list with TTL (avoids RPC on every UI poll).
    pub node_list_cache: Arc<Mutex<(Vec<NodeInfo>, std::time::Instant)>>,
    /// Community watchlist manager.
    pub watchlists: Arc<Mutex<watchlist::WatchlistManager>>,
    /// Poseidon Merkle tree built from registered node secp256k1 pubkeys.
    pub merkle_tree: Arc<Mutex<Option<zk_merkle::PoseidonMerkleTree>>>,
    /// Registry root read from ZKSettlement at connect time.
    pub zk_registry_root: Arc<Mutex<Option<String>>>,
    /// Node secp256k1 pubkeys (node_id hex → 65-byte uncompressed key).
    pub node_pubkeys: Arc<Mutex<std::collections::HashMap<String, Vec<u8>>>>,
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
            node_list_cache: Arc::new(Mutex::new((
                Vec::new(),
                std::time::Instant::now() - std::time::Duration::from_secs(60),
            ))),
            cover_cancel: Mutex::new(None),
            real_packet_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            watchlists: Arc::new(Mutex::new(watchlist::WatchlistManager::new())),
            merkle_tree: Arc::new(Mutex::new(None)),
            zk_registry_root: Arc::new(Mutex::new(None)),
            node_pubkeys: Arc::new(Mutex::new(std::collections::HashMap::new())),
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
            zk_settlement_address: None, // TODO: add ZK_SETTLEMENT_ADDRESS constant
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
    // Read config values needed for connect (single lock acquisition).
    let (pinned, kill_switch_enabled, strict_network) = {
        let cfg = state.config.lock().map_err(|e| format!("lock error: {e}"))?;
        (cfg.preferred_nodes.clone(), cfg.kill_switch, cfg.strict_network_size)
    };

    let nodes = fetch_nodes(&state).await;

    // Build Poseidon Merkle tree from secp256k1 pubkeys (for ZK settlement).
    // Uses get_active_nodes_with_pubkeys() which shares the same RPC fetch.
    {
        let settlement_mode = state.config.lock()
            .map(|cfg| cfg.settlement_mode)
            .unwrap_or(settlement::SettlementMode::Auto);

        if settlement_mode != settlement::SettlementMode::Plaintext {
            match state.chain_reader.get_active_nodes_with_pubkeys().await {
                Ok((_nodes, pubkey_map)) => {
                    // Collect pubkeys in deterministic order (sorted by node_id).
                    let mut sorted_ids: Vec<&String> = pubkey_map.keys().collect();
                    sorted_ids.sort();
                    let ordered_keys: Vec<Vec<u8>> = sorted_ids.iter()
                        .map(|id| pubkey_map[*id].clone())
                        .collect();

                    match zk_merkle::PoseidonMerkleTree::from_pubkeys(&ordered_keys) {
                        Ok(tree) => {
                            info!(count = tree.count(), root = %tree.root(), "built Poseidon Merkle tree");
                            if let Ok(mut t) = state.merkle_tree.lock() { *t = Some(tree); }
                        }
                        Err(e) => warn!(error = %e, "failed to build Merkle tree"),
                    }

                    if let Ok(mut pk) = state.node_pubkeys.lock() { *pk = pubkey_map; }

                    // Read registry root from ZKSettlement.
                    match wallet::read_registry_root(
                        &state.chain_reader.rpc_url_str(),
                        SETTLEMENT_ADDRESS, // TODO: use ZK_SETTLEMENT_ADDRESS when configured
                    ).await {
                        Ok(root) => {
                            if let Ok(mut r) = state.zk_registry_root.lock() { *r = Some(root); }
                        }
                        Err(e) => warn!(error = %e, "failed to read registry root"),
                    }
                }
                Err(e) => warn!(error = %e, "failed to fetch secp256k1 pubkeys"),
            }
        }
    }

    // Minimum network size guard.
    if nodes.len() < MINIMUM_NETWORK_SIZE {
        if strict_network {
            return Err(format!(
                "strict mode: refusing to connect — only {} active nodes (minimum {})",
                nodes.len(),
                MINIMUM_NETWORK_SIZE
            ));
        }
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
    let deposit_wei: u128 = 1_000_000_000_000_000; // 0.001 ETH
    let (tx_hash, session_id) = wallet::open_session(
        &wallet_cfg,
        &entry_node_id,
        deposit_wei,
    ).await?;

    let session_id_str = session_id.to_string();

    // Make ZK deposit if settlement mode may use ZK.
    let zk_deposit_id = {
        let mode = state.config.lock().map_err(|e| format!("lock error: {e}"))?.settlement_mode;
        if mode != settlement::SettlementMode::Plaintext {
            match wallet::zk_deposit(&wallet_cfg, deposit_wei).await {
                Ok(id) => {
                    info!(deposit_id = %hex::encode(&id), "ZK deposit successful");
                    Some(id)
                }
                Err(e) => {
                    warn!(error = %e, "ZK deposit failed, ZK settlement will be unavailable");
                    None
                }
            }
        } else {
            None
        }
    };

    {
        let mut conn = state.connection.lock().map_err(|e| format!("lock error: {e}"))?;
        *conn = ConnectionState::Connected {
            node_id: entry_node_id.clone(),
            session_id: session_id_str.clone(),
            bytes_used: 0,
            hop_count,
            rotation_count: 0,
            deposit_wei,
            zk_deposit_id,
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

    // Spawn cover traffic generator (only if not Off).
    {
        let cover_level = {
            let cfg = state.config.lock().map_err(|e| format!("lock error: {e}"))?;
            cfg.cover_traffic
        };
        if cover_level != cover_traffic::CoverLevel::Off {
            let cancel = CancellationToken::new();
            {
                let mut cc = state.cover_cancel.lock().map_err(|e| format!("lock error: {e}"))?;
                *cc = Some(cancel.clone());
            }
            tokio::spawn(cover_traffic::cover_traffic_loop(
                cancel,
                cover_level,
                Arc::clone(&state.circuit),
                Arc::clone(&state.real_packet_counter),
            ));
        }
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
    // 0. Cancel background tasks.
    stop_rotation(&state)?;
    stop_health_monitor(&state)?;
    stop_cover_traffic(&state)?;

    // 1. Get session state (session_id, bytes_used, deposit, deposit_id) and exit endpoint.
    let (session_id_str, bytes_used, exit_endpoint, deposit_wei, zk_deposit_id) = {
        let conn = state.connection.lock().map_err(|e| format!("lock error: {e}"))?;
        match &*conn {
            ConnectionState::Connected { session_id, bytes_used, node_id, deposit_wei, zk_deposit_id, .. } => {
                let circ = state.circuit.lock().map_err(|e| format!("lock error: {e}"))?;
                let endpoint = circ
                    .as_ref()
                    .map(|c| c.exit.endpoint.clone())
                    .unwrap_or_else(|| node_id.clone());
                (session_id.clone(), *bytes_used, endpoint, *deposit_wei, *zk_deposit_id)
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

    // 3. Read all config values in a single lock acquisition (avoids deadlock
    //    from wallet_config() re-locking, and reads settlement_mode atomically).
    let (wallet_cfg, chain_id, settlement_mode) = {
        let cfg = state.config.lock().map_err(|e| format!("lock error: {e}"))?;
        let wc = WalletConfig {
            rpc_url: cfg.rpc_url.clone(),
            chain_id: cfg.chain_id,
            private_key: cfg.operator_private_key.clone(),
            settlement_address: SETTLEMENT_ADDRESS.to_string(),
            zk_settlement_address: None,
        };
        let mode = cfg.settlement_mode;
        (wc, cfg.chain_id, mode)
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

    // 4. Send to exit node for co-signing (with signature verification).
    let exit_operator = {
        let circ = state.circuit.lock().map_err(|e| format!("lock error: {e}"))?;
        circ.as_ref().map(|c| c.exit.operator_address.clone()).unwrap_or_default()
    };
    let node_sig = tunnel::request_receipt_cosign(
        &exit_endpoint,
        session_id,
        bytes_used,
        timestamp,
        &client_sig,
        &digest.0,
        &exit_operator,
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

    // 7. Build ZK session data if settlement mode may use ZK.
    let client_addr = alloy::signers::Signer::address(&signer);
    let zk_data = if settlement_mode != settlement::SettlementMode::Plaintext {
        build_zk_session_data(
            &state, session_id, bytes_used, timestamp, deposit_wei,
            &domain_sep, &digest, &client_sig, &node_sig, &client_addr,
            zk_deposit_id,
        )
    } else {
        None
    };

    // 8. Settle via configured mode (ZK or plaintext).
    let result = settlement::settle_session(
        settlement_mode,
        &wallet_cfg,
        session_id,
        receipt_data,
        zk_data,
    )
    .await?;
    let tx_hash = result.tx_hash;
    info!(method = result.method, "session settled via {}", result.method);

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

/// Build ZK session data from current state for ZK settlement.
/// Returns None if the circuit state is unavailable or data is incomplete.
fn build_zk_session_data(
    state: &AppState,
    session_id: u64,
    bytes_used: u64,
    timestamp: u64,
    deposit_wei: u128,
    domain_sep: &alloy::primitives::B256,
    digest: &alloy::primitives::B256,
    client_sig: &[u8],
    node_sig: &[u8],
    client_addr: &alloy::primitives::Address,
    deposit_id: Option<[u8; 32]>,
) -> Option<zk_witness::ZkSessionData> {
    // Extract circuit data under a scoped lock.
    let (exit_price, entry_addr_hex, relay_addr_hex, exit_addr_hex,
         entry_node_id, relay_node_id, exit_node_id) = {
        let circ = state.circuit.lock().ok()?;
        let c = circ.as_ref()?;
        (
            c.exit.price_per_byte,
            c.entry.operator_address.clone(),
            c.relay.operator_address.clone(),
            c.exit.operator_address.clone(),
            c.entry.node_id.clone(),
            c.relay.node_id.clone(),
            c.exit.node_id.clone(),
        )
    };

    let parse_addr = |hex: &str| -> Option<[u8; 20]> {
        let stripped = hex.strip_prefix("0x").unwrap_or(hex);
        let bytes = hex::decode(stripped).ok()?;
        if bytes.len() != 20 { return None; }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        Some(arr)
    };

    let mut client_address = [0u8; 20];
    client_address.copy_from_slice(client_addr.as_slice());

    // Get Merkle tree, pubkeys, and registry root from AppState.
    let tree = state.merkle_tree.lock().ok()?;
    let pubkeys = state.node_pubkeys.lock().ok()?;
    let registry_root = state.zk_registry_root.lock().ok()?.clone()
        .unwrap_or_else(|| "0".to_string());

    // Look up secp256k1 pubkeys for entry and relay nodes.
    let entry_pk = pubkeys.get(&entry_node_id).cloned().unwrap_or_default();
    let relay_pk = pubkeys.get(&relay_node_id).cloned().unwrap_or_default();
    let exit_pk = pubkeys.get(&exit_node_id).cloned().unwrap_or_default();

    // Extract Merkle proofs if tree is available.
    let (exit_proof, entry_proof, relay_proof) = if let Some(ref t) = *tree {
        let exit_idx = t.find_index(&exit_pk).ok();
        let entry_idx = t.find_index(&entry_pk).ok();
        let relay_idx = t.find_index(&relay_pk).ok();

        (
            exit_idx.and_then(|i| t.proof(i).ok()),
            entry_idx.and_then(|i| t.proof(i).ok()),
            relay_idx.and_then(|i| t.proof(i).ok()),
        )
    } else {
        (None, None, None)
    };

    let depth = zk_merkle::MERKLE_DEPTH;
    let empty_proof = || vec!["0".to_string(); depth];

    Some(zk_witness::ZkSessionData {
        session_id,
        cumulative_bytes: bytes_used,
        timestamp,
        price_per_byte: exit_price,
        deposit: deposit_wei,
        domain_separator: domain_sep.0,
        digest: digest.0,
        receipt_typehash: receipts::receipt_typehash().0,
        deposit_id: deposit_id.unwrap_or([0u8; 32]),

        client_sig: client_sig.to_vec(),
        node_sig: node_sig.to_vec(),

        client_address,
        entry_address: parse_addr(&entry_addr_hex)?,
        relay_address: parse_addr(&relay_addr_hex)?,
        exit_address: parse_addr(&exit_addr_hex)?,

        exit_merkle_proof: exit_proof.as_ref().map(|p| p.siblings.clone()).unwrap_or_else(empty_proof),
        exit_merkle_index: exit_proof.as_ref().map(|p| p.index).unwrap_or(0),
        entry_merkle_proof: entry_proof.as_ref().map(|p| p.siblings.clone()).unwrap_or_else(empty_proof),
        entry_merkle_index: entry_proof.as_ref().map(|p| p.index).unwrap_or(0),
        relay_merkle_proof: relay_proof.as_ref().map(|p| p.siblings.clone()).unwrap_or_else(empty_proof),
        relay_merkle_index: relay_proof.as_ref().map(|p| p.index).unwrap_or(0),

        entry_secp256k1_pubkey: entry_pk,
        relay_secp256k1_pubkey: relay_pk,

        registry_root,
    })
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
async fn get_gas_price(state: State<'_, AppState>) -> Result<f64, String> {
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
    app: tauri::AppHandle,
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

    // Persist to OS-appropriate config directory.
    let config_dir = app
        .path()
        .app_config_dir()
        .map_err(|e| format!("failed to get config dir: {e}"))?;
    let config_path = config_dir.join("shieldnode-client.json");
    if let Err(e) = snapshot.save(&config_path) {
        warn!(error = %e, "failed to persist settings to disk");
    }

    info!("settings updated");
    Ok(())
}

// ── Watchlist commands ───────────────────────────────────────────────────

/// Return summaries of all loaded watchlists plus the subscription config.
#[tauri::command]
async fn get_watchlists(
    state: State<'_, AppState>,
) -> Result<watchlist::WatchlistInfo, String> {
    let subscriptions = {
        let cfg = state.config.lock().map_err(|e| format!("lock error: {e}"))?;
        cfg.watchlist_subscriptions.clone()
    };
    let summaries = {
        let mgr = state.watchlists.lock().map_err(|e| format!("lock error: {e}"))?;
        mgr.summaries()
    };
    Ok(watchlist::WatchlistInfo {
        subscriptions,
        loaded: summaries,
    })
}

/// Add a new watchlist subscription. Fetches it immediately.
#[tauri::command]
async fn add_watchlist(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    url: String,
) -> Result<(), String> {
    let sub = watchlist::WatchlistSubscription {
        url,
        enabled: true,
        label: String::new(),
    };

    // Add to config and persist.
    let subs = {
        let mut cfg = state.config.lock().map_err(|e| format!("lock error: {e}"))?;
        // Avoid duplicates.
        if cfg.watchlist_subscriptions.iter().any(|s| s.url == sub.url) {
            return Err("watchlist already subscribed".to_string());
        }
        cfg.watchlist_subscriptions.push(sub);
        let snapshot = cfg.clone();
        let config_dir = app
            .path()
            .app_config_dir()
            .map_err(|e| format!("config dir: {e}"))?;
        let _ = snapshot.save(&config_dir.join("shieldnode-client.json"));
        cfg.watchlist_subscriptions.clone()
    };

    // Refresh all watchlists (no lock held across await).
    let fetched = watchlist::fetch_all_watchlists(&subs).await;
    {
        let mut mgr = state.watchlists.lock().map_err(|e| format!("lock error: {e}"))?;
        mgr.apply_fetched(fetched);
    }

    // Invalidate node list cache so next fetch applies watchlist penalties.
    if let Ok(mut cache) = state.node_list_cache.lock() {
        cache.1 = std::time::Instant::now() - std::time::Duration::from_secs(60);
    }

    info!("watchlist subscription added");
    Ok(())
}

/// Remove a watchlist subscription by URL.
#[tauri::command]
async fn remove_watchlist(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    url: String,
) -> Result<(), String> {
    {
        let mut cfg = state.config.lock().map_err(|e| format!("lock error: {e}"))?;
        cfg.watchlist_subscriptions.retain(|s| s.url != url);
        let snapshot = cfg.clone();
        let config_dir = app
            .path()
            .app_config_dir()
            .map_err(|e| format!("config dir: {e}"))?;
        let _ = snapshot.save(&config_dir.join("shieldnode-client.json"));
    }

    // Refresh loaded lists (no lock held across await).
    let subs = state.config.lock().map_err(|e| format!("lock error: {e}"))?.watchlist_subscriptions.clone();
    let fetched = watchlist::fetch_all_watchlists(&subs).await;
    {
        let mut mgr = state.watchlists.lock().map_err(|e| format!("lock error: {e}"))?;
        mgr.apply_fetched(fetched);
    }

    if let Ok(mut cache) = state.node_list_cache.lock() {
        cache.1 = std::time::Instant::now() - std::time::Duration::from_secs(60);
    }

    info!(url = %url, "watchlist removed");
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

/// Cancel the background cover traffic task, if any.
fn stop_cover_traffic(state: &AppState) -> Result<(), String> {
    let mut cc = state
        .cover_cancel
        .lock()
        .map_err(|e| format!("lock error: {e}"))?;
    if let Some(token) = cc.take() {
        token.cancel();
        info!("cover traffic task cancelled");
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

        // 2. Build exclude list from old circuit.
        let exclude_ids: Vec<&str> = old_circuit
            .as_ref()
            .map(|c| vec![
                c.entry.node_id.as_str(),
                c.relay.node_id.as_str(),
                c.exit.node_id.as_str(),
            ])
            .unwrap_or_default();

        // 3. Fetch nodes, select, build, register, reconnect, swap circuit.
        let selected = match rebuild_circuit(
            &chain_reader,
            &exclude_ids,
            &circuit,
            &tunnel,
        ).await {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "circuit rotation failed, skipping");
                continue;
            }
        };

        info!(
            entry = %selected[0].node_id,
            relay = %selected[1].node_id,
            exit  = %selected[2].node_id,
            "selected new circuit for rotation"
        );

        // 4. Update rotation count.
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
        operator_address: String::new(),
        asn: None,
        region: None,
        tee_attested: false, // enriched by attestation verification
    }
}

/// Shared circuit rebuild logic: fetch nodes, select circuit, build, register
/// sessions, reconnect tunnel, and swap circuit state.
///
/// Returns the selected `NodeInfo` triple so callers can update connection
/// state as needed (e.g. rotation count).
pub(crate) async fn rebuild_circuit(
    chain_reader: &ChainReader,
    exclude_ids: &[&str],
    circuit_state: &Arc<Mutex<Option<CircuitState>>>,
    tunnel: &Arc<Mutex<TunnelManager>>,
) -> Result<Vec<NodeInfo>, String> {
    let nodes = chain_reader.get_active_nodes().await
        .map_err(|e| format!("failed to fetch nodes: {e}"))?;

    if nodes.len() < 3 {
        return Err("fewer than 3 nodes available".to_string());
    }

    let node_infos: Vec<NodeInfo> = nodes
        .into_iter()
        .map(map_on_chain_node)
        .collect();

    let selected = circuit::select_circuit(&node_infos, exclude_ids)?;
    let new_circuit = circuit::build_circuit(&selected)?;
    tunnel::register_sessions(&new_circuit).await?;

    // Reconnect tunnel to new entry.
    {
        let mut tun = tunnel.lock().map_err(|e| format!("lock error: {e}"))?;
        tun.start_tunnel(&selected[0].endpoint, &selected[0].public_key)?;
    }

    // Swap circuit state.
    {
        let mut circ = circuit_state.lock().map_err(|e| format!("lock error: {e}"))?;
        *circ = Some(new_circuit);
    }

    Ok(selected.to_vec())
}

/// Completion rate cache TTL (10 minutes).
const COMPLETION_RATE_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// Node list cache TTL (30 seconds — short enough for timely updates,
/// long enough to avoid redundant RPC on rapid UI polls).
const NODE_LIST_TTL: std::time::Duration = std::time::Duration::from_secs(30);

/// Fetch nodes from on-chain registry, falling back to mock data.
/// Enriches nodes with completion rates (cached) and local reputation penalties.
/// Results are cached for NODE_LIST_TTL to avoid redundant RPC calls from UI polling.
async fn fetch_nodes(state: &AppState) -> Vec<NodeInfo> {
    // Return cached node list if fresh.
    {
        if let Ok(cache) = state.node_list_cache.lock() {
            if cache.1.elapsed() < NODE_LIST_TTL && !cache.0.is_empty() {
                return cache.0.clone();
            }
        }
    }

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

    // Refresh watchlists if stale (no lock held across await).
    {
        let needs_refresh = state
            .watchlists
            .lock()
            .map(|mgr| mgr.needs_refresh())
            .unwrap_or(false);
        if needs_refresh {
            let subs = state
                .config
                .lock()
                .map(|cfg| cfg.watchlist_subscriptions.clone())
                .unwrap_or_default();
            if !subs.is_empty() {
                let fetched = watchlist::fetch_all_watchlists(&subs).await;
                if let Ok(mut mgr) = state.watchlists.lock() {
                    mgr.apply_fetched(fetched);
                }
            }
        }
    }

    // Apply reputation + watchlist penalties (single lock each).
    {
        let penalized: std::collections::HashSet<String> = state
            .reputation
            .lock()
            .map(|rep| {
                nodes
                    .iter()
                    .filter(|n| rep.score_penalty(&n.node_id) > 0.0)
                    .map(|n| n.node_id.clone())
                    .collect()
            })
            .unwrap_or_default();
        let wl_flagged = state
            .watchlists
            .lock()
            .map(|mgr| mgr.flagged_node_ids())
            .unwrap_or_default();

        for node in &mut nodes {
            if penalized.contains(&node.node_id) || wl_flagged.contains(&node.node_id) {
                node.completion_rate = 0.0;
            }
        }
    }

    // Cache the enriched node list.
    if let Ok(mut cache) = state.node_list_cache.lock() {
        *cache = (nodes.clone(), std::time::Instant::now());
    }

    nodes
}

/// Decode a 0x-prefixed hex string into bytes. Returns empty vec on failure.
fn decode_hex_bytes(hex_str: &str) -> Vec<u8> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(stripped).unwrap_or_default()
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
            tee_attested: true,
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
            tee_attested: false,
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
            tee_attested: false,
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
            tee_attested: true,
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
            tee_attested: false,
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
            get_watchlists,
            add_watchlist,
            remove_watchlist,
            send_packet,
        ])
        .run(tauri::generate_context!())
        .expect("error while running ShieldNode client");
}
