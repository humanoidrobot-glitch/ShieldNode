use alloy::primitives::{Address, FixedBytes, U256};
use alloy::sol_types::SolEvent;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::network::EthereumWallet;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::chain::ISessionSettlement;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    pub rpc_url: String,
    pub chain_id: u64,
    pub private_key: Option<String>,
    pub settlement_address: String,
}

impl WalletConfig {
    pub(crate) fn parse_signer(&self) -> Result<PrivateKeySigner, String> {
        let pk = self.private_key.as_deref()
            .ok_or("no private key configured - set operator_private_key in settings")?;
        let stripped = pk.strip_prefix("0x").unwrap_or(pk);
        stripped.parse::<PrivateKeySigner>()
            .map_err(|e| format!("invalid private key: {e}"))
    }

    fn parse_url(&self) -> Result<url::Url, String> {
        self.rpc_url.parse().map_err(|e| format!("invalid RPC URL: {e}"))
    }

    fn parse_settlement(&self) -> Result<Address, String> {
        self.settlement_address.parse()
            .map_err(|e| format!("invalid settlement address: {e}"))
    }
}

/// Open a 3-hop session on the SessionSettlement contract.
/// For Phase 1 single-hop, the same node_id is used for all 3 slots.
pub async fn open_session(
    wallet: &WalletConfig,
    node_id_hex: &str,
    deposit_wei: u128,
) -> Result<(String, u64), String> {
    let signer = wallet.parse_signer()?;
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(wallet.parse_url()?);
    let settlement = wallet.parse_settlement()?;

    let node_id = parse_bytes32(node_id_hex)?;
    let node_ids: [FixedBytes<32>; 3] = [node_id, node_id, node_id];

    info!(node_id = node_id_hex, deposit_wei, "opening on-chain session");

    let contract = ISessionSettlement::new(settlement, &provider);
    let pending = contract.openSession(node_ids)
        .value(U256::from(deposit_wei))
        .send().await
        .map_err(|e| format!("openSession tx failed: {e}"))?;

    let tx_hash = format!("{:?}", pending.tx_hash());

    let receipt = pending.get_receipt().await
        .map_err(|e| format!("failed to get tx receipt: {e}"))?;

    // Parse session ID from SessionOpened event.
    // Scan all logs for the matching event signature rather than assuming it's the first.
    let session_opened_sig = ISessionSettlement::SessionOpened::SIGNATURE_HASH;
    let session_id: u64 = receipt.inner.logs().iter()
        .find(|log| log.topics().first() == Some(&session_opened_sig))
        .and_then(|log| log.topics().get(1))
        .map(|topic| {
            u64::from_be_bytes(
                topic.0[24..32].try_into().unwrap_or([0u8; 8])
            )
        })
        .ok_or("no SessionOpened event found in openSession receipt")?;

    info!(tx = %tx_hash, session_id, "session opened on-chain");
    Ok((tx_hash, session_id))
}

/// Settle a session on-chain with a fully ABI-encoded, dual-signed receipt.
///
/// `receipt_data` should come from `receipts::encode_settlement_receipt()` and
/// contains the sessionId, cumulativeBytes, timestamp, clientSig, and nodeSig.
pub async fn settle_session(
    wallet: &WalletConfig,
    session_id: u64,
    receipt_data: Vec<u8>,
) -> Result<String, String> {
    let signer = wallet.parse_signer()?;
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(wallet.parse_url()?);
    let settlement = wallet.parse_settlement()?;

    info!(session_id, receipt_len = receipt_data.len(), "settling on-chain session with signed receipt");

    let contract = ISessionSettlement::new(settlement, &provider);
    let pending = contract
        .settleSession(U256::from(session_id), receipt_data.into())
        .send()
        .await
        .map_err(|e| format!("settleSession tx failed: {e}"))?;

    let tx_hash = format!("{:?}", pending.tx_hash());
    info!(tx = %tx_hash, "session settled on-chain");
    Ok(tx_hash)
}

/// Fetch the current gas price in Gwei.
pub async fn get_gas_price(rpc_url: &str) -> Result<f64, String> {
    let url: url::Url = rpc_url.parse()
        .map_err(|e| format!("invalid RPC URL: {e}"))?;
    let provider = ProviderBuilder::new().connect_http(url);

    match provider.get_gas_price().await {
        Ok(gas_price_wei) => Ok(gas_price_wei as f64 / 1e9),
        Err(e) => {
            info!(error = %e, "RPC gas price fetch failed, returning fallback");
            Ok(20.0)
        }
    }
}

fn parse_bytes32(hex_str: &str) -> Result<FixedBytes<32>, String> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if stripped.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", stripped.len()));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in stripped.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|e| format!("invalid hex: {e}"))?;
        out[i] = u8::from_str_radix(s, 16).map_err(|e| format!("invalid hex: {e}"))?;
    }
    Ok(FixedBytes::from(out))
}

