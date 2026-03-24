mod circuit;
mod config;
mod receipts;
mod tunnel;
mod wallet;

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::State;
use tracing::info;

use circuit::NodeInfo;
use tunnel::TunnelManager;
use wallet::WalletConfig;

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

/// Top-level connection state exposed to the frontend.
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

/// Shared application state managed by Tauri.
pub struct AppState {
    pub connection: Mutex<ConnectionState>,
    pub tunnel: Mutex<TunnelManager>,
    pub config: Mutex<config::ClientConfig>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            connection: Mutex::new(ConnectionState::default()),
            tunnel: Mutex::new(TunnelManager::new()),
            config: Mutex::new(config::ClientConfig::default()),
        }
    }
}

// ---------------------------------------------------------------------------
// Serialisable types returned to the frontend
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub node_id: String,
    pub bytes_used: u64,
    pub connected_since: u64,
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

/// Connect to the VPN through the best available node.
#[tauri::command]
async fn connect(state: State<'_, AppState>) -> Result<String, String> {
    // Fetch the mock node list and pick the best one.
    let nodes = mock_nodes();
    let node = circuit::select_single_node(&nodes)?;

    // Transition to Connecting.
    {
        let mut conn = state
            .connection
            .lock()
            .map_err(|e| format!("lock error: {e}"))?;
        *conn = ConnectionState::Connecting;
    }

    info!(node_id = %node.node_id, endpoint = %node.endpoint, "connecting to node");

    // Start the (stub) tunnel.
    {
        let mut tun = state
            .tunnel
            .lock()
            .map_err(|e| format!("lock error: {e}"))?;
        tun.start_tunnel(&node.endpoint, &node.public_key)?;
    }

    // Open an on-chain session (stub).
    let wallet_cfg = {
        let cfg = state
            .config
            .lock()
            .map_err(|e| format!("lock error: {e}"))?;
        WalletConfig {
            rpc_url: cfg.rpc_url.clone(),
            chain_id: cfg.chain_id,
        }
    };

    let session_id =
        wallet::open_session(&wallet_cfg, &[node.node_id.clone()], 1_000_000_000_000_000)?;

    // Transition to Connected.
    {
        let mut conn = state
            .connection
            .lock()
            .map_err(|e| format!("lock error: {e}"))?;
        *conn = ConnectionState::Connected {
            node_id: node.node_id.clone(),
            session_id: session_id.clone(),
            bytes_used: 0,
        };
    }

    info!(session_id = %session_id, "connected");
    Ok(session_id)
}

/// Disconnect from the VPN and settle the session on-chain.
#[tauri::command]
async fn disconnect(state: State<'_, AppState>) -> Result<String, String> {
    // Grab the current session info before we reset state.
    let (session_id, bytes_used) = {
        let conn = state
            .connection
            .lock()
            .map_err(|e| format!("lock error: {e}"))?;
        match &*conn {
            ConnectionState::Connected {
                session_id,
                bytes_used,
                ..
            } => (session_id.clone(), *bytes_used),
            _ => return Err("not connected".to_string()),
        }
    };

    // Stop the tunnel.
    {
        let mut tun = state
            .tunnel
            .lock()
            .map_err(|e| format!("lock error: {e}"))?;
        tun.stop_tunnel()?;
    }

    // Settle on-chain (stub).
    let wallet_cfg = {
        let cfg = state
            .config
            .lock()
            .map_err(|e| format!("lock error: {e}"))?;
        WalletConfig {
            rpc_url: cfg.rpc_url.clone(),
            chain_id: cfg.chain_id,
        }
    };

    let tx_hash = wallet::settle_session(&wallet_cfg, &session_id, bytes_used)?;

    // Reset state.
    {
        let mut conn = state
            .connection
            .lock()
            .map_err(|e| format!("lock error: {e}"))?;
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

/// Return the list of available nodes (mock data for Phase 1).
#[tauri::command]
async fn get_nodes() -> Result<Vec<NodeInfo>, String> {
    Ok(mock_nodes())
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

/// Return the current network gas price (mock for Phase 1).
#[tauri::command]
async fn get_gas_price(state: State<'_, AppState>) -> Result<u64, String> {
    let rpc_url = {
        let cfg = state
            .config
            .lock()
            .map_err(|e| format!("lock error: {e}"))?;
        cfg.rpc_url.clone()
    };

    wallet::get_gas_price(&rpc_url)
}

// ---------------------------------------------------------------------------
// Mock helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Tauri entry point
// ---------------------------------------------------------------------------

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
