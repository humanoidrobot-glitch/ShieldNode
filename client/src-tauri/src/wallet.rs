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

/// Fetch the current gas price from the RPC endpoint.
///
/// **Phase 1 stub** — returns a hard-coded mock value (20 gwei in wei).
pub fn get_gas_price(rpc_url: &str) -> Result<u64, String> {
    info!(rpc = rpc_url, "fetching gas price (stub)");

    // 20 gwei = 20_000_000_000 wei
    let mock_gas_price: u64 = 20_000_000_000;

    info!(gas_price_wei = mock_gas_price, "gas price fetched (mock)");
    Ok(mock_gas_price)
}
