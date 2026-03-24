use serde::{Deserialize, Serialize};
use std::path::Path;

/// Client-side configuration for the ShieldNode VPN client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// JSON-RPC URL for the blockchain backend.
    pub rpc_url: String,

    /// Chain ID of the target network.
    pub chain_id: u64,

    /// Whether to automatically rotate exit nodes during a session.
    pub auto_rotate: bool,

    /// Kill-switch: block all traffic when tunnel drops unexpectedly.
    pub kill_switch: bool,

    /// Maximum gas price (in gwei) the client is willing to pay.
    pub gas_price_ceiling_gwei: f64,

    /// Node IDs the user prefers to connect through.
    pub preferred_nodes: Vec<String>,

    /// Hex-encoded private key for signing on-chain transactions.
    /// In production this would be replaced by WalletConnect / injected wallet.
    #[serde(default)]
    pub operator_private_key: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://eth-sepolia.g.alchemy.com/v2/demo".to_string(),
            chain_id: 11155111, // Sepolia
            auto_rotate: false,
            kill_switch: true,
            gas_price_ceiling_gwei: 5.0,
            preferred_nodes: Vec::new(),
            operator_private_key: None,
        }
    }
}

impl ClientConfig {
    /// Load configuration from a JSON file on disk.
    /// Returns `Default` values if the file does not exist.
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let data = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config file: {e}"))?;

        serde_json::from_str(&data)
            .map_err(|e| format!("failed to parse config file: {e}"))
    }

    /// Persist the current configuration to a JSON file.
    pub fn save(&self, path: &Path) -> Result<(), String> {
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
