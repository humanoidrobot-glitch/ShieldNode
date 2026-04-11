use std::sync::Arc;

use alloy::primitives::{Address, FixedBytes, U256};
use alloy::sol;
use alloy::sol_types::SolEvent;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::network::EthereumWallet;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::chain::ISessionSettlement;
use crate::config::WalletMode;
use crate::wallet_bridge::{self, SigningRequest, SigningResponse, WalletBridge};

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

/// Context for wallet operations — bundles mode, config, and bridge.
pub struct WalletContext {
    pub config: WalletConfig,
    pub mode: WalletMode,
    pub bridge: Arc<WalletBridge>,
    /// Tauri app handle for emitting signing events to the frontend.
    pub app_handle: Option<tauri::AppHandle>,
}

impl WalletContext {
    /// Sign an EIP-712 digest. In Local mode, uses the private key directly.
    /// In WalletConnect mode, delegates to the frontend via the bridge.
    pub async fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, String> {
        match self.mode {
            WalletMode::Local => {
                let signer = self.config.parse_signer()?;
                let digest_b256 = alloy::primitives::B256::from(*digest);
                let sig = signer.sign_hash(&digest_b256).await
                    .map_err(|e| format!("local signing failed: {e}"))?;
                Ok(sig.as_bytes().to_vec())
            }
            WalletMode::WalletConnect => {
                let request_id = format!("sign-{}", rand::random::<u32>());
                let request = SigningRequest::SignTypedData {
                    digest: format!("0x{}", hex::encode(digest)),
                    description: "Sign bandwidth receipt".to_string(),
                    request_id: request_id.clone(),
                };

                // Emit the request to the frontend.
                if let Some(ref handle) = self.app_handle {
                    use tauri::Emitter;
                    handle.emit("signing-request", &request)
                        .map_err(|e| format!("failed to emit signing request: {e}"))?;
                } else {
                    return Err("WalletConnect mode requires an app handle".to_string());
                }

                // Wait for the frontend to resolve it.
                let response = self.bridge.request_signing(120).await?;
                match response {
                    SigningResponse::Signature { signature, .. } => {
                        let stripped = signature.strip_prefix("0x").unwrap_or(&signature);
                        hex::decode(stripped)
                            .map_err(|e| format!("invalid signature hex: {e}"))
                    }
                    SigningResponse::Error { message, .. } => {
                        Err(format!("wallet rejected: {message}"))
                    }
                    _ => Err("unexpected response type from wallet".to_string()),
                }
            }
        }
    }
}

impl WalletContext {
    /// Send a transaction via the WalletConnect bridge (WC mode only).
    /// Encodes the calldata, emits a signing request, and awaits the tx hash.
    pub async fn send_transaction_wc(
        &self,
        to: Address,
        calldata: &[u8],
        value: U256,
    ) -> Result<String, String> {
        let request_id = format!("tx-{}", rand::random::<u32>());
        let request = SigningRequest::SendTransaction {
            to: format!("{to:?}"),
            data: format!("0x{}", hex::encode(calldata)),
            value: format!("{value:#x}"),
            request_id: request_id.clone(),
        };

        if let Some(ref handle) = self.app_handle {
            use tauri::Emitter;
            handle.emit("signing-request", &request)
                .map_err(|e| format!("failed to emit tx request: {e}"))?;
        } else {
            return Err("WalletConnect mode requires an app handle".to_string());
        }

        let response = self.bridge.request_signing(120).await?;
        match response {
            SigningResponse::TransactionSent { tx_hash, .. } => Ok(tx_hash),
            SigningResponse::Error { message, .. } => {
                Err(format!("wallet rejected transaction: {message}"))
            }
            _ => Err("unexpected response type from wallet".to_string()),
        }
    }

    /// Check if this context is using WalletConnect mode.
    pub fn is_walletconnect(&self) -> bool {
        self.mode == WalletMode::WalletConnect
    }
}

/// Open a 3-hop session on the SessionSettlement contract.
pub async fn open_session(
    ctx: &WalletContext,
    node_id_hex: &str,
    deposit_wei: u128,
) -> Result<(String, u64), String> {
    let settlement = ctx.config.parse_settlement()?;
    let node_id = parse_bytes32(node_id_hex)?;
    let node_ids: [FixedBytes<32>; 3] = [node_id, node_id, node_id];

    info!(node_id = node_id_hex, deposit_wei, "opening on-chain session");

    if ctx.is_walletconnect() {
        // WC mode: encode calldata, delegate to frontend.
        use alloy::sol_types::SolCall;
        let calldata = ISessionSettlement::openSessionCall { nodeIds: node_ids }.abi_encode();
        let tx_hash = ctx.send_transaction_wc(settlement, &calldata, U256::from(deposit_wei)).await?;
        // WC mode cannot easily poll for receipt from backend.
        // Return tx_hash with session_id = 0 — frontend will parse the event.
        warn!(tx = %tx_hash, "WC mode: session_id must be parsed by frontend");
        return Ok((tx_hash, 0));
    }

    // Local mode: use Alloy contract API directly.
    let signer = ctx.config.parse_signer()?;
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(ctx.config.parse_url()?);

    let contract = ISessionSettlement::new(settlement, &provider);
    let pending = contract.openSession(node_ids)
        .value(U256::from(deposit_wei))
        .send().await
        .map_err(|e| format!("openSession tx failed: {e}"))?;

    let tx_hash = format!("{:?}", pending.tx_hash());
    let receipt = pending.get_receipt().await
        .map_err(|e| format!("failed to get tx receipt: {e}"))?;

    let session_opened_sig = ISessionSettlement::SessionOpened::SIGNATURE_HASH;
    let session_id: u64 = receipt.inner.logs().iter()
        .find(|log| log.topics().first() == Some(&session_opened_sig))
        .and_then(|log| log.topics().get(1))
        .map(|topic| u64::from_be_bytes(topic.0[24..32].try_into().unwrap_or([0u8; 8])))
        .ok_or("no SessionOpened event found in openSession receipt")?;

    info!(tx = %tx_hash, session_id, "session opened on-chain");
    Ok((tx_hash, session_id))
}

/// Settle a session on-chain with a dual-signed receipt.
pub async fn settle_session(
    ctx: &WalletContext,
    session_id: u64,
    receipt_data: Vec<u8>,
) -> Result<String, String> {
    let settlement = ctx.config.parse_settlement()?;
    info!(session_id, receipt_len = receipt_data.len(), "settling on-chain session");

    if ctx.is_walletconnect() {
        use alloy::sol_types::SolCall;
        let calldata = ISessionSettlement::settleSessionCall {
            sessionId: U256::from(session_id),
            signedReceipt: receipt_data.into(),
        }.abi_encode();
        let tx_hash = ctx.send_transaction_wc(settlement, &calldata, U256::ZERO).await?;
        info!(tx = %tx_hash, "session settled via WalletConnect");
        return Ok(tx_hash);
    }

    let signer = ctx.config.parse_signer()?;
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(ctx.config.parse_url()?);

    let contract = ISessionSettlement::new(settlement, &provider);
    let pending = contract
        .settleSession(U256::from(session_id), receipt_data.into())
        .send().await
        .map_err(|e| format!("settleSession tx failed: {e}"))?;

    let tx_hash = format!("{:?}", pending.tx_hash());
    info!(tx = %tx_hash, "session settled on-chain");
    Ok(tx_hash)
}

/// Call ZKSettlement.deposit{value: amount}() and return the depositId.
pub async fn zk_deposit(ctx: &WalletContext, amount: u128) -> Result<[u8; 32], String> {
    let zk_addr: Address = ctx.config.zk_settlement_address.as_deref()
        .unwrap_or(&ctx.config.settlement_address)
        .parse()
        .map_err(|e| format!("invalid ZK settlement address: {e}"))?;

    if ctx.is_walletconnect() {
        use alloy::sol_types::SolCall;
        let calldata = IZKSettlement::depositCall {}.abi_encode();
        let tx_hash = ctx.send_transaction_wc(zk_addr, &calldata, U256::from(amount)).await?;
        // WC mode: return a dummy deposit_id. Frontend must parse the event.
        warn!(tx = %tx_hash, "WC mode: deposit_id must be parsed by frontend");
        return Ok([0u8; 32]);
    }

    let signer = ctx.config.parse_signer()?;
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(ctx.config.parse_url()?);

    let contract = IZKSettlement::new(zk_addr, &provider);
    let pending = contract.deposit()
        .value(U256::from(amount))
        .send().await
        .map_err(|e| format!("ZKSettlement.deposit tx failed: {e}"))?;

    let receipt = pending.get_receipt().await
        .map_err(|e| format!("failed to get deposit receipt: {e}"))?;

    let deposit_id: [u8; 32] = receipt.inner.logs().iter()
        .find(|log| log.topics().first() == Some(&IZKSettlement::DepositMade::SIGNATURE_HASH))
        .and_then(|log| log.topics().get(1))
        .map(|topic| topic.0)
        .ok_or("no DepositMade event found in deposit receipt")?;

    info!(deposit_id = %hex::encode(deposit_id), "ZK deposit made");
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
    ctx: &WalletContext,
    proof: &crate::zk_prove::ZkProof,
    data: &crate::zk_witness::ZkSessionData,
) -> Result<String, String> {
    let zk_settlement: Address = ctx.config.zk_settlement_address.as_deref()
        .unwrap_or(&ctx.config.settlement_address)
        .parse()
        .map_err(|e| format!("invalid ZK settlement address: {e}"))?;

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

    if ctx.is_walletconnect() {
        use alloy::sol_types::SolCall;
        let calldata = IZKSettlement::settleWithProofCall {
            proof_a, proof_b, proof_c, pubSignals: pub_signals,
            nullifier, depositId: deposit_id,
            entryAddr: entry_addr, relayAddr: relay_addr,
            exitAddr: exit_addr, refundAddr: refund_addr,
        }.abi_encode();
        let tx_hash = ctx.send_transaction_wc(zk_settlement, &calldata, U256::ZERO).await?;
        info!(tx = %tx_hash, "ZK session settled via WalletConnect");
        return Ok(tx_hash);
    }

    let signer = ctx.config.parse_signer()?;
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(ctx.config.parse_url()?);

    let contract = IZKSettlement::new(zk_settlement, &provider);
    let pending = contract
        .settleWithProof(
            proof_a, proof_b, proof_c, pub_signals,
            nullifier, deposit_id,
            entry_addr, relay_addr, exit_addr, refund_addr,
        )
        .send().await
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

