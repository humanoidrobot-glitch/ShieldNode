use alloy::providers::Provider;
use serde::{Deserialize, Serialize};
use tracing::info;

/// Blockchain wallet / RPC configuration used for on-chain interactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    pub rpc_url: String,
    pub chain_id: u64,
}

/// Open a bandwidth session on-chain by depositing funds into the payment
/// channel smart contract.
///
/// **Phase 1 stub** — returns a mock transaction hash.
pub fn open_session(
    wallet: &WalletConfig,
    node_ids: &[String],
    deposit_wei: u64,
) -> Result<String, String> {
    info!(
        chain_id = wallet.chain_id,
        rpc = %wallet.rpc_url,
        nodes = ?node_ids,
        deposit_wei,
        "opening on-chain session (stub)"
    );

    // TODO: build + sign + broadcast a real transaction via alloy / ethers
    let mock_tx_hash =
        "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string();

    info!(tx = %mock_tx_hash, "session opened (mock)");
    Ok(mock_tx_hash)
}

/// Settle (close) a session on-chain, reporting the total bytes consumed.
///
/// **Phase 1 stub** — returns a mock transaction hash.
pub fn settle_session(
    wallet: &WalletConfig,
    session_id: &str,
    bytes_used: u64,
) -> Result<String, String> {
    info!(
        chain_id = wallet.chain_id,
        rpc = %wallet.rpc_url,
        session_id,
        bytes_used,
        "settling on-chain session (stub)"
    );

    let mock_tx_hash =
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string();

    info!(tx = %mock_tx_hash, "session settled (mock)");
    Ok(mock_tx_hash)
}

/// Fetch the current gas price from the RPC endpoint and return it in Gwei.
///
/// Uses an alloy HTTP provider to query `eth_gasPrice`, then converts from
/// wei to gwei.  Falls back to a hard-coded 20 gwei if the RPC call fails.
pub async fn get_gas_price(rpc_url: &str) -> Result<u64, String> {
    info!(rpc = rpc_url, "fetching gas price via alloy provider");

    let url: url::Url = rpc_url
        .parse()
        .map_err(|e| format!("invalid RPC URL: {e}"))?;

    let provider = alloy::providers::ProviderBuilder::new().connect_http(url);

    match provider.get_gas_price().await {
        Ok(gas_price_wei) => {
            let gwei = gas_price_wei / 1_000_000_000;
            info!(gas_price_gwei = gwei, gas_price_wei, "gas price fetched");
            Ok(gwei as u64)
        }
        Err(e) => {
            info!(error = %e, "RPC gas price fetch failed, returning fallback 20 gwei");
            Ok(20)
        }
    }
}
