use alloy::primitives::{Address, FixedBytes, U256};
use alloy::sol;
use alloy::sol_types::SolEvent;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::network::EthereumWallet;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::chain::ISessionSettlement;

sol! {
    #[sol(rpc)]
    interface IZKSettlement {
        event DepositMade(bytes32 indexed depositId, address indexed depositor, uint256 amount);

        function deposit() external payable returns (bytes32 depositId);
        function registryRoot() external view returns (uint256);

        function settleWithProof(
            uint256[2] calldata proof_a,
            uint256[2][2] calldata proof_b,
            uint256[2] calldata proof_c,
            uint256[13] calldata pubSignals,
            bytes32 nullifier,
            bytes32 depositId,
            address payable entryAddr,
            address payable relayAddr,
            address payable exitAddr,
            address payable refundAddr
        ) external;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    pub rpc_url: String,
    pub chain_id: u64,
    pub private_key: Option<String>,
    pub settlement_address: String,
    #[serde(default)]
    pub zk_settlement_address: Option<String>,
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

/// Call ZKSettlement.deposit{value: amount}() and return the depositId.
pub async fn zk_deposit(wallet: &WalletConfig, amount: u128) -> Result<[u8; 32], String> {
    let signer = wallet.parse_signer()?;
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(wallet.parse_url()?);

    let zk_addr: Address = wallet.zk_settlement_address.as_deref()
        .unwrap_or(&wallet.settlement_address)
        .parse()
        .map_err(|e| format!("invalid ZK settlement address: {e}"))?;

    let contract = IZKSettlement::new(zk_addr, &provider);
    let pending = contract.deposit()
        .value(U256::from(amount))
        .send().await
        .map_err(|e| format!("ZKSettlement.deposit tx failed: {e}"))?;

    let receipt = pending.get_receipt().await
        .map_err(|e| format!("failed to get deposit receipt: {e}"))?;

    // Parse depositId from the DepositMade event (first indexed topic).
    use alloy::sol_types::SolEvent;
    let deposit_id: [u8; 32] = receipt.inner.logs().iter()
        .find(|log| log.topics().first() == Some(&IZKSettlement::DepositMade::SIGNATURE_HASH))
        .and_then(|log| log.topics().get(1))
        .map(|topic| topic.0)
        .ok_or("no DepositMade event found in deposit receipt")?;

    info!(deposit_id = %hex::encode(&deposit_id), "ZK deposit made");
    Ok(deposit_id)
}

/// Read the current registryRoot from ZKSettlement (view call, no signing needed).
pub async fn read_registry_root(rpc_url: &str, zk_settlement_addr: &str) -> Result<String, String> {
    let url: url::Url = rpc_url.parse().map_err(|e| format!("invalid RPC URL: {e}"))?;
    let provider = ProviderBuilder::new().connect_http(url);
    let addr: Address = zk_settlement_addr.parse()
        .map_err(|e| format!("invalid ZK settlement address: {e}"))?;

    let contract = IZKSettlement::new(addr, &provider);
    let result = contract.registryRoot().call().await
        .map_err(|e| format!("registryRoot call failed: {e}"))?;

    Ok(result.to_string())
}

/// Submit a ZK proof to ZKSettlement.settleWithProof.
pub async fn settle_zk_session(
    wallet: &WalletConfig,
    proof: &crate::zk_prove::ZkProof,
    data: &crate::zk_witness::ZkSessionData,
) -> Result<String, String> {
    let signer = wallet.parse_signer()?;
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(wallet.parse_url()?);

    // ZKSettlement is at a separate address from SessionSettlement.
    // For now, use the same settlement_address config field.
    // TODO: Add zk_settlement_address to WalletConfig when deployed separately.
    let zk_settlement: Address = wallet.parse_settlement()?;

    // Parse proof components into contract types.
    let proof_a: [U256; 2] = [
        proof.pi_a[0].parse::<U256>().map_err(|e| format!("pi_a[0]: {e}"))?,
        proof.pi_a[1].parse::<U256>().map_err(|e| format!("pi_a[1]: {e}"))?,
    ];
    let proof_b: [[U256; 2]; 2] = [
        [
            proof.pi_b[0][0].parse::<U256>().map_err(|e| format!("pi_b[0][0]: {e}"))?,
            proof.pi_b[0][1].parse::<U256>().map_err(|e| format!("pi_b[0][1]: {e}"))?,
        ],
        [
            proof.pi_b[1][0].parse::<U256>().map_err(|e| format!("pi_b[1][0]: {e}"))?,
            proof.pi_b[1][1].parse::<U256>().map_err(|e| format!("pi_b[1][1]: {e}"))?,
        ],
    ];
    let proof_c: [U256; 2] = [
        proof.pi_c[0].parse::<U256>().map_err(|e| format!("pi_c[0]: {e}"))?,
        proof.pi_c[1].parse::<U256>().map_err(|e| format!("pi_c[1]: {e}"))?,
    ];

    let pub_signals: [U256; 13] = {
        let mut arr = [U256::ZERO; 13];
        for (i, s) in proof.public_signals.iter().enumerate().take(13) {
            arr[i] = s.parse::<U256>().map_err(|e| format!("pubSignal[{i}]: {e}"))?;
        }
        arr
    };

    let nullifier = FixedBytes::from(data.deposit_id); // nullifier binding
    let deposit_id = FixedBytes::from(data.deposit_id);
    let entry_addr = Address::from(data.entry_address);
    let relay_addr = Address::from(data.relay_address);
    let exit_addr = Address::from(data.exit_address);
    let refund_addr = Address::from(data.client_address);

    info!("submitting ZK proof to ZKSettlement.settleWithProof");

    let contract = IZKSettlement::new(zk_settlement, &provider);
    let pending = contract
        .settleWithProof(
            proof_a, proof_b, proof_c, pub_signals,
            nullifier, deposit_id,
            entry_addr, relay_addr, exit_addr, refund_addr,
        )
        .send()
        .await
        .map_err(|e| format!("settleWithProof tx failed: {e}"))?;

    let tx_hash = format!("{:?}", pending.tx_hash());
    info!(tx = %tx_hash, "ZK session settled on-chain");
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
    let bytes = hex::decode(stripped).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(FixedBytes::from(out))
}

