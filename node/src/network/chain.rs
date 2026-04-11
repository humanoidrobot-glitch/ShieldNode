use alloy::{
    primitives::{Address, Bytes, FixedBytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use thiserror::Error;
use tracing::info;

// ── ABI definition via sol! ────────────────────────────────────────────

sol! {
    #[sol(rpc)]
    contract NodeRegistry {
        function register(bytes32 nodeId, bytes32 publicKey, string endpoint, bytes secp256k1Key) external payable;
        function heartbeat(bytes32 nodeId) external;
        function updateEndpoint(bytes32 nodeId, string newEndpoint) external;

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
            bytes32 secp256k1X;
            bytes32 secp256k1Y;
        }

        function getNode(bytes32 nodeId) external view returns (NodeInfo memory);
    }
}

// ── errors ─────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ChainError {
    #[error("invalid RPC URL: {0}")]
    InvalidUrl(String),

    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),

    #[error("transaction failed: {0}")]
    TransactionFailed(String),

    #[error("contract error: {0}")]
    Contract(String),
}

// ── service ────────────────────────────────────────────────────────────

/// Handles all on-chain interactions with the NodeRegistry contract.
pub struct ChainService {
    rpc_url: String,
    registry_address: Address,
    node_id: [u8; 32],
    private_key: [u8; 32],
}

impl ChainService {
    /// Create a new `ChainService`.
    ///
    /// * `rpc_url` – Ethereum JSON-RPC endpoint (e.g. an Alchemy Sepolia URL).
    /// * `registry_address` – deployed NodeRegistry contract address.
    /// * `node_id` – 32-byte identifier for this node.
    /// * `private_key` – 32-byte operator/deployer wallet private key used
    ///   to sign transactions (NOT the node's X25519 key).
    pub fn new(
        rpc_url: String,
        registry_address: Address,
        node_id: [u8; 32],
        private_key: [u8; 32],
    ) -> Self {
        Self {
            rpc_url,
            registry_address,
            node_id,
            private_key,
        }
    }

    /// Build a provider with the operator wallet attached for signing.
    fn build_provider(
        &self,
    ) -> Result<impl Provider<alloy::network::Ethereum> + Clone, ChainError> {
        let signer = PrivateKeySigner::from_bytes(&FixedBytes::from(self.private_key))
            .map_err(|e| ChainError::InvalidPrivateKey(e.to_string()))?;

        let wallet = alloy::network::EthereumWallet::from(signer);

        let url = self
            .rpc_url
            .parse()
            .map_err(|e| ChainError::InvalidUrl(format!("{e}")))?;

        let provider = ProviderBuilder::new().wallet(wallet).connect_http(url);

        Ok(provider)
    }

    /// Register this node on-chain.
    ///
    /// Sends `stake_wei` as `msg.value` alongside the call.
    /// `secp256k1_pubkey` is the 64-byte uncompressed public key (x || y)
    /// derived from the operator's private key — the contract verifies
    /// `keccak256(key) == msg.sender`.
    /// Returns the transaction hash as a hex string.
    pub async fn register(
        &self,
        public_key: [u8; 32],
        endpoint: &str,
        stake_wei: u128,
        secp256k1_pubkey: &[u8; 64],
    ) -> Result<String, ChainError> {
        let provider = self.build_provider()?;

        let contract = NodeRegistry::new(self.registry_address, &provider);

        let node_id = FixedBytes::from(self.node_id);
        let pub_key = FixedBytes::from(public_key);
        let secp_key = Bytes::from(secp256k1_pubkey.to_vec());

        info!(
            node_id = %node_id,
            endpoint = %endpoint,
            stake_wei = %stake_wei,
            "sending register transaction"
        );

        let call = contract
            .register(node_id, pub_key, endpoint.to_string(), secp_key)
            .value(U256::from(stake_wei));

        let pending = call
            .send()
            .await
            .map_err(|e| ChainError::Contract(e.to_string()))?;

        let tx_hash = format!("{:?}", pending.tx_hash());

        info!(tx_hash = %tx_hash, "register transaction sent");
        Ok(tx_hash)
    }

    /// Send an on-chain heartbeat proving liveness.
    /// Returns the transaction hash as a hex string.
    pub async fn heartbeat(&self) -> Result<String, ChainError> {
        let provider = self.build_provider()?;

        let contract = NodeRegistry::new(self.registry_address, &provider);

        let node_id = FixedBytes::from(self.node_id);

        info!(node_id = %node_id, "sending heartbeat transaction");

        let pending = contract
            .heartbeat(node_id)
            .send()
            .await
            .map_err(|e| ChainError::Contract(e.to_string()))?;

        let tx_hash = format!("{:?}", pending.tx_hash());

        info!(tx_hash = %tx_hash, "heartbeat transaction sent");
        Ok(tx_hash)
    }

    /// Update the node's advertised endpoint on-chain.
    /// Returns the transaction hash as a hex string.
    pub async fn update_endpoint(&self, endpoint: &str) -> Result<String, ChainError> {
        let provider = self.build_provider()?;

        let contract = NodeRegistry::new(self.registry_address, &provider);

        let node_id = FixedBytes::from(self.node_id);

        info!(
            node_id = %node_id,
            endpoint = %endpoint,
            "sending updateEndpoint transaction"
        );

        let pending = contract
            .updateEndpoint(node_id, endpoint.to_string())
            .send()
            .await
            .map_err(|e| ChainError::Contract(e.to_string()))?;

        let tx_hash = format!("{:?}", pending.tx_hash());

        info!(tx_hash = %tx_hash, "updateEndpoint transaction sent");
        Ok(tx_hash)
    }
}
