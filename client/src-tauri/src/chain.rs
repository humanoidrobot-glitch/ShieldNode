use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::sol;
use serde::Serialize;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
//  ABI definitions via sol! macro
// ---------------------------------------------------------------------------

sol! {
    #[sol(rpc)]
    interface INodeRegistry {
        struct NodeInfo {
            address owner;
            bytes32 publicKey;
            string  endpoint;
            uint256 stake;
            uint256 registeredAt;
            uint256 lastHeartbeat;
            uint256 slashCount;
            bool    isActive;
            uint256 pricePerByte;
            bytes32 commitment;
        }

        function getActiveNodes(uint256 offset, uint256 limit)
            external view returns (bytes32[] memory nodeIds);

        function getNode(bytes32 nodeId)
            external view returns (NodeInfo memory);

        function isNodeActive(bytes32 nodeId)
            external view returns (bool active);
    }

    #[sol(rpc)]
    interface ISessionSettlement {
        struct SessionInfo {
            address    client;
            bytes32[3] nodeIds;
            uint256    deposit;
            uint256    startBlock;
            bool       settled;
            uint256    cumulativeBytes;
        }

        event SessionOpened(uint256 indexed sessionId, address indexed client, bytes32[3] nodeIds, uint256 deposit);
        event SessionSettled(uint256 indexed sessionId, address indexed client, uint256 cumulativeBytes, uint256 totalPaid);

        function openSession(bytes32[3] calldata nodeIds) external payable;
        function settleSession(uint256 sessionId, bytes calldata signedReceipt) external;

        function getSession(uint256 sessionId)
            external view returns (SessionInfo memory);

        function nextSessionId() external view returns (uint256);
    }
}

// ---------------------------------------------------------------------------
//  Rust-side types returned to the frontend
// ---------------------------------------------------------------------------

/// A node as read from the on-chain NodeRegistry, serialised for the UI.
#[derive(Debug, Clone, Serialize)]
pub struct OnChainNodeInfo {
    /// bytes32 node ID as a 0x-prefixed hex string.
    pub node_id: String,
    /// bytes32 Curve25519 public key as a 0x-prefixed hex string.
    pub public_key: String,
    /// WireGuard endpoint (host:port).
    pub endpoint: String,
    /// Stake denominated in ETH (converted from wei).
    pub stake: f64,
    /// Uptime score 0.0 .. 1.0, derived from heartbeat freshness.
    pub uptime: f64,
    /// Price per byte denominated as a float (converted from wei).
    pub price_per_byte: f64,
    /// Number of times this node has been slashed.
    pub slash_count: u32,
}

// ---------------------------------------------------------------------------
//  ChainReader
// ---------------------------------------------------------------------------

/// Read-only interface to on-chain ShieldNode contracts.
#[derive(Clone)]
pub struct ChainReader {
    rpc_url: String,
    registry_address: Address,
    settlement_address: Address,
}

impl ChainReader {
    pub fn new(
        rpc_url: String,
        registry_address: Address,
        settlement_address: Address,
    ) -> Self {
        Self {
            rpc_url,
            registry_address,
            settlement_address,
        }
    }

    /// Fetch all active nodes from the NodeRegistry contract.
    ///
    /// Calls `getActiveNodes(0, 100)` to obtain the list of active node IDs,
    /// then calls `getNode(id)` for each one to retrieve full metadata.
    pub async fn get_active_nodes(&self) -> Result<Vec<OnChainNodeInfo>, String> {
        let url: url::Url = self
            .rpc_url
            .parse()
            .map_err(|e| format!("invalid RPC URL: {e}"))?;

        let provider = ProviderBuilder::new().connect_http(url);

        let registry =
            INodeRegistry::new(self.registry_address, &provider);

        // Fetch up to 100 active node IDs.
        let node_ids = registry
            .getActiveNodes(alloy::primitives::U256::from(0), alloy::primitives::U256::from(100))
            .call()
            .await
            .map_err(|e| format!("getActiveNodes call failed: {e}"))?;
        info!(count = node_ids.len(), "fetched active node IDs from registry");

        if node_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut nodes = Vec::with_capacity(node_ids.len());

        // Current timestamp for uptime calculation.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for id in &node_ids {
            match registry.getNode(*id).call().await {
                Ok(node_info) => {
                    let info = node_info;

                    // Convert stake from wei to ETH (1 ETH = 1e18 wei).
                    let stake_eth = wei_to_eth(info.stake);

                    // Derive an uptime score from heartbeat freshness.
                    // If the heartbeat is less than 5 minutes old  -> 1.0
                    // If the heartbeat is more than 1 hour old     -> 0.0
                    // Linear interpolation in between.
                    let last_hb: u64 = info
                        .lastHeartbeat
                        .try_into()
                        .unwrap_or(0);
                    let uptime = heartbeat_to_uptime(last_hb, now);

                    // slash count (u256 -> u32, clamped)
                    let slash_count: u32 = info
                        .slashCount
                        .try_into()
                        .unwrap_or(u32::MAX);

                    // price per byte as f64 (wei)
                    let price_per_byte: f64 = u128_from_u256(info.pricePerByte) as f64;

                    nodes.push(OnChainNodeInfo {
                        node_id: format!("0x{}", hex::encode(id.as_slice())),
                        public_key: format!("0x{}", hex::encode(info.publicKey.as_slice())),
                        endpoint: info.endpoint,
                        stake: stake_eth,
                        uptime,
                        price_per_byte,
                        slash_count,
                    });
                }
                Err(e) => {
                    warn!(node_id = %format!("0x{}", hex::encode(id.as_slice())), error = %e, "failed to fetch node info, skipping");
                }
            }
        }

        info!(count = nodes.len(), "fetched full node info from registry");
        Ok(nodes)
    }

    /// Fetch the current gas price from the RPC provider and return it in
    /// Gwei (rounded down).
    pub async fn get_gas_price(&self) -> Result<u64, String> {
        let url: url::Url = self
            .rpc_url
            .parse()
            .map_err(|e| format!("invalid RPC URL: {e}"))?;

        let provider = ProviderBuilder::new().connect_http(url);

        let gas_price_wei = provider
            .get_gas_price()
            .await
            .map_err(|e| format!("get_gas_price RPC failed: {e}"))?;

        // Convert wei to gwei (1 gwei = 1e9 wei).
        let gas_price_gwei = gas_price_wei / 1_000_000_000;

        info!(gas_price_gwei, gas_price_wei, "fetched gas price from RPC");
        Ok(gas_price_gwei as u64)
    }

    /// Fetch per-node session completion rates from on-chain settlement events.
    ///
    /// Reads settled sessions and computes, for each node that participated,
    /// the fraction of sessions where >1MB was transferred (a "completed"
    /// session vs one abandoned with near-zero bytes).
    ///
    /// Returns a map of node_id hex string → completion rate (0.0–1.0).
    pub async fn get_completion_rates(&self) -> Result<std::collections::HashMap<String, f64>, String> {
        let url: url::Url = self
            .rpc_url
            .parse()
            .map_err(|e| format!("invalid RPC URL: {e}"))?;

        let provider = ProviderBuilder::new().connect_http(url);
        let settlement = ISessionSettlement::new(self.settlement_address, &provider);

        // Get total session count.
        let next_id: u64 = settlement
            .nextSessionId()
            .call()
            .await
            .map_err(|e| format!("nextSessionId failed: {e}"))?
            .try_into()
            .unwrap_or(0);

        if next_id == 0 {
            return Ok(std::collections::HashMap::new());
        }

        // Scan recent sessions (last 200 max to limit RPC calls).
        let start = next_id.saturating_sub(200);
        let mut node_stats: std::collections::HashMap<String, (u64, u64)> = std::collections::HashMap::new();

        for session_id in start..next_id {
            let session = match settlement
                .getSession(alloy::primitives::U256::from(session_id))
                .call()
                .await
            {
                Ok(s) => s,
                Err(_) => continue,
            };

            if !session.settled {
                continue;
            }

            let cum_bytes: u64 = session.cumulativeBytes.try_into().unwrap_or(0);
            let completed = cum_bytes > 1_000_000; // >1MB = completed

            // Credit all 3 nodes in the session.
            for node_id in &session.nodeIds {
                let key = format!("0x{}", hex::encode(node_id.as_slice()));
                let entry = node_stats.entry(key).or_insert((0, 0));
                entry.0 += 1; // total sessions
                if completed {
                    entry.1 += 1; // completed sessions
                }
            }
        }

        let rates: std::collections::HashMap<String, f64> = node_stats
            .into_iter()
            .map(|(id, (total, completed))| {
                let rate = if total > 0 {
                    completed as f64 / total as f64
                } else {
                    1.0
                };
                (id, rate)
            })
            .collect();

        info!(nodes = rates.len(), "computed completion rates from on-chain data");
        Ok(rates)
    }

    /// Expose the settlement address for other modules if needed.
    #[allow(dead_code)]
    pub fn settlement_address(&self) -> Address {
        self.settlement_address
    }
}

// ---------------------------------------------------------------------------
//  Helpers
// ---------------------------------------------------------------------------

/// Convert a U256 wei amount to a floating-point ETH value.
fn wei_to_eth(wei: alloy::primitives::U256) -> f64 {
    let val = u128_from_u256(wei);
    val as f64 / 1e18
}

/// Extract a u128 from a U256 (saturating if the value is larger).
fn u128_from_u256(v: alloy::primitives::U256) -> u128 {
    v.try_into().unwrap_or(u128::MAX)
}

/// Derive an uptime score (0.0 – 1.0) from the last heartbeat timestamp.
///
/// - heartbeat <= 5 min ago  => 1.0
/// - heartbeat >= 60 min ago => 0.0
/// - linearly interpolated otherwise
fn heartbeat_to_uptime(last_heartbeat: u64, now: u64) -> f64 {
    if last_heartbeat == 0 || last_heartbeat > now {
        return 0.0;
    }

    let age_secs = now - last_heartbeat;
    const FRESH: u64 = 5 * 60;     // 5 minutes
    const STALE: u64 = 60 * 60;    // 1 hour

    if age_secs <= FRESH {
        1.0
    } else if age_secs >= STALE {
        0.0
    } else {
        1.0 - ((age_secs - FRESH) as f64 / (STALE - FRESH) as f64)
    }
}

/// Tiny hex-encoding helper so we don't need the `hex` crate as a top-level
/// dependency (alloy re-exports it, but access varies by version).
mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX_CHARS[(b >> 4) as usize] as char);
            s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
        }
        s
    }
}
