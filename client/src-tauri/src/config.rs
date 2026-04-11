use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::cover_traffic::CoverLevel;
use crate::settlement::SettlementMode;
use crate::watchlist::WatchlistSubscription;

/// Client-side configuration for the ShieldNode VPN client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// JSON-RPC URL for the blockchain backend.
    pub rpc_url: String,

    /// Chain ID of the target network.
    pub chain_id: u64,

    /// Whether to automatically rotate circuits during a session.
    pub auto_rotate: bool,

    /// Interval in seconds between circuit rotations (default: 600 = 10 min).
    pub circuit_rotation_interval_secs: u64,

    /// Kill-switch: block all traffic when tunnel drops unexpectedly.
    pub kill_switch: bool,

    /// Maximum gas price (in gwei) the client is willing to pay.
    pub gas_price_ceiling_gwei: f64,

    /// Refuse to connect if active node count is below the safety threshold.
    pub strict_network_size: bool,

    /// Cover traffic level.
    pub cover_traffic: CoverLevel,

    /// Settlement mode.
    pub settlement_mode: SettlementMode,

    /// Node IDs the user prefers to connect through.
    pub preferred_nodes: Vec<String>,

    /// Hex-encoded private key for signing on-chain transactions.
    /// Stored in OS keychain when available, NOT serialized to JSON.
    /// Falls back to plaintext JSON if keychain is unavailable.
    #[serde(default, skip_serializing)]
    pub operator_private_key: Option<String>,

    /// Community watchlist subscriptions.
    #[serde(default)]
    pub watchlist_subscriptions: Vec<WatchlistSubscription>,

    /// Wallet mode: "local" (OS keychain) or "walletconnect" (delegated signing).
    #[serde(default)]
    pub wallet_mode: WalletMode,

    /// WalletConnect-paired address (hex, set by frontend on pairing).
    #[serde(default)]
    pub wc_address: Option<String>,
}

/// How the client signs transactions and EIP-712 messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WalletMode {
    /// Sign locally using the operator private key from OS keychain.
    Local,
    /// Delegate signing to a connected wallet via WalletConnect v2.
    #[serde(rename = "walletconnect")]
    WalletConnect,
}

impl Default for WalletMode {
    fn default() -> Self {
        Self::Local
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://configure-rpc.shieldnode.invalid".to_string(), // Must be configured by user
            chain_id: 11155111, // Sepolia
            auto_rotate: false,
            circuit_rotation_interval_secs: 600,
            kill_switch: true,
            gas_price_ceiling_gwei: 5.0,
            strict_network_size: false,
            cover_traffic: CoverLevel::Low,
            settlement_mode: SettlementMode::Auto,
            preferred_nodes: Vec::new(),
            operator_private_key: None,
            watchlist_subscriptions: Vec::new(),
            wallet_mode: WalletMode::default(),
            wc_address: None,
        }
    }
}

/// Frontend-safe settings payload. Excludes sensitive fields like private keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsPayload {
    pub rpc_url: String,
    pub chain_id: u64,
    pub auto_rotate: bool,
    pub circuit_rotation_interval_secs: u64,
    pub kill_switch: bool,
    pub gas_price_ceiling_gwei: f64,
    pub strict_network_size: bool,
    pub cover_traffic: CoverLevel,
    pub settlement_mode: SettlementMode,
    pub preferred_nodes: Vec<String>,
    pub watchlist_subscriptions: Vec<WatchlistSubscription>,
}

impl From<&ClientConfig> for SettingsPayload {
    fn from(cfg: &ClientConfig) -> Self {
        Self {
            rpc_url: cfg.rpc_url.clone(),
            chain_id: cfg.chain_id,
            auto_rotate: cfg.auto_rotate,
            circuit_rotation_interval_secs: cfg.circuit_rotation_interval_secs,
            kill_switch: cfg.kill_switch,
            gas_price_ceiling_gwei: cfg.gas_price_ceiling_gwei,
            strict_network_size: cfg.strict_network_size,
            cover_traffic: cfg.cover_traffic,
            settlement_mode: cfg.settlement_mode,
            preferred_nodes: cfg.preferred_nodes.clone(),
            watchlist_subscriptions: cfg.watchlist_subscriptions.clone(),
        }
    }
}

impl ClientConfig {
    /// Merge a SettingsPayload into this config, updating non-sensitive fields.
    pub fn apply_settings(&mut self, s: &SettingsPayload) {
        self.rpc_url = s.rpc_url.clone();
        self.chain_id = s.chain_id;
        self.auto_rotate = s.auto_rotate;
        self.circuit_rotation_interval_secs = s.circuit_rotation_interval_secs;
        self.kill_switch = s.kill_switch;
        self.gas_price_ceiling_gwei = s.gas_price_ceiling_gwei;
        self.strict_network_size = s.strict_network_size;
        self.cover_traffic = s.cover_traffic;
        self.settlement_mode = s.settlement_mode;
        self.preferred_nodes = s.preferred_nodes.clone();
        self.watchlist_subscriptions = s.watchlist_subscriptions.clone();
    }

    /// Load configuration from a JSON file on disk.
    /// Retrieves the private key from OS keychain if available.
    pub fn load(path: &Path) -> Result<Self, String> {
        let mut cfg = if path.exists() {
            let data = std::fs::read_to_string(path)
                .map_err(|e| format!("failed to read config file: {e}"))?;
            serde_json::from_str(&data)
                .map_err(|e| format!("failed to parse config file: {e}"))?
        } else {
            Self::default()
        };

        // Try loading private key from OS keychain.
        if cfg.operator_private_key.is_none() {
            cfg.operator_private_key = load_key_from_keychain();
        }

        Ok(cfg)
    }

    /// Persist the current configuration to a JSON file.
    /// Stores the private key in OS keychain (not in JSON).
    pub fn save(&self, path: &Path) -> Result<(), String> {
        // Store private key in keychain before saving config.
        if let Some(ref key) = self.operator_private_key {
            save_key_to_keychain(key);
        }

        // Private key excluded from JSON via #[serde(skip_serializing)].
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize config: {e}"))?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create config directory: {e}"))?;
        }

        std::fs::write(path, json)
            .map_err(|e| format!("failed to write config file: {e}"))
    }
}

const KEYCHAIN_SERVICE: &str = "shieldnode";
const KEYCHAIN_USER: &str = "operator-private-key";

/// Store the private key in the OS keychain. Silently fails if unavailable.
fn save_key_to_keychain(key: &str) {
    match keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_USER) {
        Ok(entry) => {
            if let Err(e) = entry.set_password(key) {
                tracing::warn!(error = %e, "failed to store key in OS keychain (falling back to config)");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "OS keychain unavailable");
        }
    }
}

/// Load the private key from the OS keychain. Returns None if unavailable.
fn load_key_from_keychain() -> Option<String> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_USER).ok()?;
    entry.get_password().ok()
}
