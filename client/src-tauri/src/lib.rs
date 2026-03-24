mod chain;
mod circuit;
mod config;
mod receipts;
mod tunnel;
mod wallet;

use std::sync::Mutex;

use alloy::primitives::Address;
use serde::{Deserialize, Serialize};
use tauri::State;
use tracing::{info, warn};

use chain::ChainReader;
use circuit::NodeInfo;
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
    },
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::Disconnected
    }
}

/// Contract addresses for the ShieldNode protocol on Sepolia.
const REGISTRY_ADDRESS: &str = "0xC6D9923E54547e0C7c5B456bFf16fEdF2d61df11";
const SETTLEMENT_ADDRESS: &str = "0xF32aE5324E3caCCEC4F198FEF783482A0c5eE959";

pub struct AppState {
    pub connection: Mutex<ConnectionState>,
    pub tunnel: Mutex<TunnelManager>,
    pub config: Mutex<config::ClientConfig>,
    pub chain_reader: ChainReader,
}

impl Default for AppState {
    fn default() -> Self {
        let cfg = config::ClientConfig::default();
        let registry: Address = REGISTRY_ADDRESS.parse().expect("invalid registry address");
        let settlement: Address = SETTLEMENT_ADDRESS.parse().expect("invalid settlement address");
        Self {
            chain_reader: ChainReader::new(cfg.rpc_url.clone(), registry, settlement),
            connection: Mutex::new(ConnectionState::default()),
            tunnel: Mutex::new(TunnelManager::new()),
            config: Mutex::new(cfg),
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
pub struct SessionInfo {
    pub session_id: String,
    pub node_id: String,
    pub bytes_used: u64,
    pub connected_since: u64,
}

#[tauri::command]
async fn connect(state: State<'_, AppState>) -> Result<String, String> {
    // Try on-chain nodes first, fall back to mock.
    let nodes = match state.chain_reader.get_active_nodes().await {
        Ok(on_chain) if !on_chain.is_empty() => {
            on_chain.into_iter().map(|n| {
                let pk_bytes = decode_hex_32(&n.public_key);
                NodeInfo {
                    node_id: n.node_id,
                    public_key: pk_bytes,
                    endpoint: n.endpoint,
                    stake: (n.stake * 1e18) as u64,
                    uptime: n.uptime,
                    price_per_byte: n.price_per_byte as u64,
                    slash_count: n.slash_count,
                }
            }).collect()
        }
        _ => mock_nodes(),
    };
    let node = circuit::select_single_node(&nodes)?;

    {
        let mut conn = state.connection.lock().map_err(|e| format!("lock error: {e}"))?;
        *conn = ConnectionState::Connecting;
    }

    info!(node_id = %node.node_id, endpoint = %node.endpoint, "connecting to node");

    {
        let mut tun = state.tunnel.lock().map_err(|e| format!("lock error: {e}"))?;
        tun.start_tunnel(&node.endpoint, &node.public_key)?;
    }

    let wallet_cfg = state.wallet_config()?;

    // Open on-chain session (0.001 ETH deposit = minimum).
    let (tx_hash, session_id) = wallet::open_session(
        &wallet_cfg,
        &node.node_id,
        1_000_000_000_000_000, // 0.001 ETH
    ).await?;

    let session_id_str = session_id.to_string();

    {
        let mut conn = state.connection.lock().map_err(|e| format!("lock error: {e}"))?;
        *conn = ConnectionState::Connected {
            node_id: node.node_id.clone(),
            session_id: session_id_str.clone(),
            bytes_used: 0,
        };
    }

    info!(session_id, tx = %tx_hash, "connected — session opened on-chain");
    Ok(session_id_str)
}

#[tauri::command]
async fn disconnect(state: State<'_, AppState>) -> Result<String, String> {
    let (session_id_str, bytes_used) = {
        let conn = state.connection.lock().map_err(|e| format!("lock error: {e}"))?;
        match &*conn {
            ConnectionState::Connected { session_id, bytes_used, .. } => {
                (session_id.clone(), *bytes_used)
            }
            _ => return Err("not connected".to_string()),
        }
    };

    {
        let mut tun = state.tunnel.lock().map_err(|e| format!("lock error: {e}"))?;
        tun.stop_tunnel()?;
    }

    let session_id: u64 = session_id_str.parse()
        .map_err(|e| format!("invalid session id: {e}"))?;

    let wallet_cfg = state.wallet_config()?;
    let tx_hash = wallet::settle_session(&wallet_cfg, session_id, bytes_used).await?;

    {
        let mut conn = state.connection.lock().map_err(|e| format!("lock error: {e}"))?;
        *conn = ConnectionState::Disconnected;
    }

    info!(tx = %tx_hash, "disconnected and session settled");
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

/// Return the list of available nodes.
///
/// Attempts to read from the on-chain NodeRegistry first; falls back to mock
/// data when the registry is empty or the RPC call fails (useful during
/// local development).
#[tauri::command]
async fn get_nodes(state: State<'_, AppState>) -> Result<Vec<NodeInfo>, String> {
    match state.chain_reader.get_active_nodes().await {
        Ok(on_chain) if !on_chain.is_empty() => {
            info!(count = on_chain.len(), "serving on-chain nodes");
            // Convert OnChainNodeInfo -> circuit::NodeInfo so existing scoring
            // and circuit-selection logic keeps working.
            let nodes = on_chain
                .into_iter()
                .map(|n| {
                    // Decode public_key hex back to [u8; 32].
                    let pk_bytes = decode_hex_32(&n.public_key);
                    NodeInfo {
                        node_id: n.node_id,
                        public_key: pk_bytes,
                        endpoint: n.endpoint,
                        stake: (n.stake * 1e18) as u64, // back to wei for scoring
                        uptime: n.uptime,
                        price_per_byte: n.price_per_byte as u64,
                        slash_count: n.slash_count,
                    }
                })
                .collect();
            Ok(nodes)
        }
        Ok(_empty) => {
            warn!("on-chain registry returned 0 nodes, falling back to mock data");
            Ok(mock_nodes())
        }
        Err(e) => {
            warn!(error = %e, "on-chain read failed, falling back to mock data");
            Ok(mock_nodes())
        }
    }
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

// Helpers
// ──────────────────────────────────────────────────────────────────────────

/// Decode a 0x-prefixed hex string into a fixed-size 32-byte array.
/// Returns `[0u8; 32]` on any parse failure (non-critical path).
fn decode_hex_32(hex_str: &str) -> [u8; 32] {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let mut out = [0u8; 32];
    if stripped.len() != 64 {
        return out;
    }
    for (i, chunk) in stripped.as_bytes().chunks(2).enumerate() {
        if i >= 32 {
            break;
        }
        if let Ok(byte) = u8::from_str_radix(
            std::str::from_utf8(chunk).unwrap_or("00"),
            16,
        ) {
            out[i] = byte;
        }
    }
    out
}

// Mock helpers
// ──────────────────────────────────────────────────────────────────────────

/// Generate a small set of mock nodes for development / testing.
fn mock_nodes() -> Vec<NodeInfo> {
    vec![
        NodeInfo {
            node_id: "node-alpha-001".to_string(),
            public_key: [1u8; 32],
            endpoint: "203.0.113.10:51820".to_string(),
            stake: 100_000,
            uptime: 0.995,
            price_per_byte: 10,
            slash_count: 0,
        },
        NodeInfo {
            node_id: "node-beta-002".to_string(),
            public_key: [2u8; 32],
            endpoint: "198.51.100.20:51820".to_string(),
            stake: 75_000,
            uptime: 0.980,
            price_per_byte: 15,
            slash_count: 0,
        },
        NodeInfo {
            node_id: "node-gamma-003".to_string(),
            public_key: [3u8; 32],
            endpoint: "192.0.2.30:51820".to_string(),
            stake: 50_000,
            uptime: 0.960,
            price_per_byte: 8,
            slash_count: 1,
        },
        NodeInfo {
            node_id: "node-delta-004".to_string(),
            public_key: [4u8; 32],
            endpoint: "198.51.100.40:51820".to_string(),
            stake: 120_000,
            uptime: 0.999,
            price_per_byte: 20,
            slash_count: 0,
        },
        NodeInfo {
            node_id: "node-epsilon-005".to_string(),
            public_key: [5u8; 32],
            endpoint: "203.0.113.50:51820".to_string(),
            stake: 30_000,
            uptime: 0.850,
            price_per_byte: 5,
            slash_count: 2,
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
            get_gas_price,
        ])
        .run(tauri::generate_context!())
        .expect("error while running ShieldNode client");
}
