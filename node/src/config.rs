use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

/// Top-level configuration loaded from a TOML file.
#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    /// WireGuard UDP listen port.
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,

    /// HTTP port for the metrics / health API.
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,

    /// Optional on-chain stake / registry contract address.
    #[serde(default)]
    pub stake_address: Option<String>,

    /// Ethereum JSON-RPC endpoint.
    #[serde(default = "default_ethereum_rpc")]
    pub ethereum_rpc: String,

    /// Seconds between on-chain heartbeat transactions.
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,

    /// Path to the node's persistent private key file.
    #[serde(default = "default_node_private_key_path")]
    pub node_private_key_path: String,

    /// libp2p swarm listen port.
    #[serde(default = "default_libp2p_port")]
    pub libp2p_port: u16,

    /// When `true` the node acts as an exit node; otherwise relay-only.
    #[serde(default)]
    pub exit_mode: bool,

    /// Price per byte forwarded, denominated in wei-equivalent units.
    #[serde(default = "default_price_per_byte")]
    pub price_per_byte: u64,

    /// Directory for persistent data (keys, state, etc.).
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
}

// ── serde default helpers ──────────────────────────────────────────────

fn default_listen_port() -> u16 {
    51820
}
fn default_metrics_port() -> u16 {
    9090
}
fn default_ethereum_rpc() -> String {
    "https://eth-sepolia.g.alchemy.com/v2/demo".to_string()
}
fn default_heartbeat_interval_secs() -> u64 {
    21600
}
fn default_node_private_key_path() -> String {
    "node_key.bin".to_string()
}
fn default_libp2p_port() -> u16 {
    4001
}
fn default_price_per_byte() -> u64 {
    2000
}
fn default_data_dir() -> String {
    "./data".to_string()
}

// ── impl ───────────────────────────────────────────────────────────────

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen_port: default_listen_port(),
            metrics_port: default_metrics_port(),
            stake_address: None,
            ethereum_rpc: default_ethereum_rpc(),
            heartbeat_interval_secs: default_heartbeat_interval_secs(),
            node_private_key_path: default_node_private_key_path(),
            libp2p_port: default_libp2p_port(),
            exit_mode: false,
            price_per_byte: default_price_per_byte(),
            data_dir: default_data_dir(),
        }
    }
}

impl NodeConfig {
    /// Read a TOML file at `path` and deserialise it into [`NodeConfig`].
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let text = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("reading config file {:?}", path.as_ref()))?;
        let cfg: NodeConfig =
            toml::from_str(&text).context("parsing TOML config")?;
        Ok(cfg)
    }
}
