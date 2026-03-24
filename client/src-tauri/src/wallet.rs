use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::network::EthereumWallet;
use alloy::sol;
use serde::{Deserialize, Serialize};
use tracing::info;

sol! {
    #[sol(rpc)]
    interface ISessionSettlement {
        function openSession(bytes32[3] calldata nodeIds) external payable;
        function settleSession(uint256 sessionId, bytes calldata signedReceipt) external;
        function getSession(uint256 sessionId) external view returns (
            address client,
            bytes32[3] nodeIds,
            uint256 deposit,
            uint256 startBlock,
            bool settled,
            uint256 cumulativeBytes
        );
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    pub rpc_url: String,
    pub chain_id: u64,
    pub private_key: Option<String>,
    pub settlement_address: String,
}

fn parse_private_key(hex_key: &str) -> Result<PrivateKeySigner, String> {
    let stripped = hex_key.strip_prefix("0x").unwrap_or(hex_key);
    stripped.parse::<PrivateKeySigner>()
        .map_err(|e| format!("invalid private key: {e}"))
}

/// Open a 3-hop session on the SessionSettlement contract.
///
/// For Phase 1 single-hop, the same node_id is used for all 3 slots.
pub async fn open_session(
    wallet: &WalletConfig,
    node_id_hex: &str,
    deposit_wei: u128,
) -> Result<(String, u64), String> {
    let pk = wallet.private_key.as_deref()
        .ok_or("no private key configured — set operator_private_key in settings")?;
    let signer = parse_private_key(pk)?;
    let eth_wallet = EthereumWallet::from(signer);

    let url: url::Url = wallet.rpc_url.parse()
        .map_err(|e| format!("invalid RPC URL: {e}"))?;
    let provider = ProviderBuilder::new()
        .wallet(eth_wallet)
        .connect_http(url);

    let settlement: Address = wallet.settlement_address.parse()
        .map_err(|e| format!("invalid settlement address: {e}"))?;

    // Parse the node_id hex string into a bytes32.
    let node_id_stripped = node_id_hex.strip_prefix("0x").unwrap_or(node_id_hex);
    let node_id_bytes: [u8; 32] = hex_to_bytes32(node_id_stripped)?;
    let node_id = FixedBytes::from(node_id_bytes);

    // For Phase 1, use the same node for all 3 circuit positions.
    let node_ids: [FixedBytes<32>; 3] = [node_id, node_id, node_id];

    info!(
        node_id = node_id_hex,
        deposit_wei,
        "opening on-chain session"
    );

    let contract = ISessionSettlement::new(settlement, &provider);
    let call = contract.openSession(node_ids).value(U256::from(deposit_wei));
    let pending = call.send().await
        .map_err(|e| format!("openSession tx failed: {e}"))?;

    let tx_hash = format!("{:?}", pending.tx_hash());

    // Get the session ID from the next session counter.
    // The contract increments nextSessionId, so the new session is (next - 1).
    // For now, we read the receipt's logs to find the SessionOpened event.
    let receipt = pending.get_receipt().await
        .map_err(|e| format!("failed to get tx receipt: {e}"))?;

    // Parse session ID from the first log (SessionOpened event).
    // The sessionId is the first indexed topic (topic[1]).
    let session_id = receipt.inner.logs().first()
        .and_then(|log| log.topics().get(1))
        .map(|topic| {
            let bytes = topic.0;
            // Convert bytes32 to u64 (session IDs are small numbers).
            u64::from_be_bytes(bytes[24..32].try_into().unwrap_or([0u8; 8]))
        })
        .unwrap_or(0);

    info!(tx = %tx_hash, session_id, "session opened on-chain");
    Ok((tx_hash, session_id))
}

/// Settle a session on-chain. For Phase 1, we use an empty receipt
/// (no bandwidth billing — just close the session and refund deposit).
pub async fn settle_session(
    wallet: &WalletConfig,
    session_id: u64,
    _bytes_used: u64,
) -> Result<String, String> {
    let pk = wallet.private_key.as_deref()
        .ok_or("no private key configured")?;
    let signer = parse_private_key(pk)?;
    let eth_wallet = EthereumWallet::from(signer);

    let url: url::Url = wallet.rpc_url.parse()
        .map_err(|e| format!("invalid RPC URL: {e}"))?;
    let provider = ProviderBuilder::new()
        .wallet(eth_wallet)
        .connect_http(url);

    let settlement: Address = wallet.settlement_address.parse()
        .map_err(|e| format!("invalid settlement address: {e}"))?;

    info!(session_id, "settling on-chain session");

    let contract = ISessionSettlement::new(settlement, &provider);

    // For Phase 1: encode a minimal receipt with 0 bytes and dummy signatures.
    // A real implementation would have co-signed EIP-712 receipts.
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let receipt_data = alloy::sol_types::SolValue::abi_encode(&(
        U256::from(session_id),
        U256::from(0u64),        // cumulativeBytes
        U256::from(timestamp),
        vec![0u8; 65],           // client signature placeholder
        vec![0u8; 65],           // node signature placeholder
    ));

    let call = contract.settleSession(U256::from(session_id), receipt_data.into());
    let pending = call.send().await
        .map_err(|e| format!("settleSession tx failed: {e}"))?;

    let tx_hash = format!("{:?}", pending.tx_hash());
    info!(tx = %tx_hash, "session settled on-chain");
    Ok(tx_hash)
}

/// Fetch the current gas price in Gwei.
pub async fn get_gas_price(rpc_url: &str) -> Result<u64, String> {
    let url: url::Url = rpc_url.parse()
        .map_err(|e| format!("invalid RPC URL: {e}"))?;
    let provider = ProviderBuilder::new().connect_http(url);

    match provider.get_gas_price().await {
        Ok(gas_price_wei) => {
            let gwei = gas_price_wei / 1_000_000_000;
            Ok(gwei as u64)
        }
        Err(e) => {
            info!(error = %e, "RPC gas price fetch failed, returning fallback");
            Ok(20)
        }
    }
}

fn hex_to_bytes32(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|e| format!("invalid utf8: {e}"))?;
        out[i] = u8::from_str_radix(s, 16).map_err(|e| format!("invalid hex: {e}"))?;
    }
    Ok(out)
}
