//! Settlement path selection: ZK (privacy-preserving) or plaintext (legacy).

use tracing::{info, warn};

use crate::zk_prove::{self, CircuitArtifacts};
use crate::zk_witness::{self, ZkSessionData};
use crate::wallet::{self, WalletContext};

/// Settlement mode.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SettlementMode {
    Zk,
    Plaintext,
    Auto,
}

impl Default for SettlementMode {
    fn default() -> Self {
        Self::Auto
    }
}

fn default_artifacts() -> CircuitArtifacts {
    CircuitArtifacts {
        wasm_path: "circuits/build/circuit_js/circuit.wasm".to_string(),
        r1cs_path: "circuits/build/circuit.r1cs".to_string(),
        zkey_path: "circuits/trusted_setup/circuit_final.zkey".to_string(),
    }
}

pub struct SettlementResult {
    pub tx_hash: String,
    pub method: &'static str,
}

/// Settle a session using the configured mode.
pub async fn settle_session(
    mode: SettlementMode,
    ctx: &WalletContext,
    session_id: u64,
    receipt_data: Vec<u8>,
    zk_data: Option<ZkSessionData>,
) -> Result<SettlementResult, String> {
    match mode {
        SettlementMode::Plaintext => {
            let tx_hash = wallet::settle_session(ctx, session_id, receipt_data).await?;
            Ok(SettlementResult { tx_hash, method: "plaintext" })
        }
        SettlementMode::Zk => {
            let data = zk_data.ok_or("ZK mode requires session data")?;
            settle_zk(ctx, &data).await
        }
        SettlementMode::Auto => {
            if let Some(ref data) = zk_data {
                match settle_zk(ctx, data).await {
                    Ok(result) => return Ok(result),
                    Err(e) => {
                        warn!(error = %e, "ZK settlement failed, falling back to plaintext");
                    }
                }
            }
            let tx_hash = wallet::settle_session(ctx, session_id, receipt_data).await?;
            Ok(SettlementResult { tx_hash, method: "plaintext" })
        }
    }
}

async fn settle_zk(
    ctx: &WalletContext,
    session_data: &ZkSessionData,
) -> Result<SettlementResult, String> {
    let artifacts = default_artifacts();

    if !zk_prove::artifacts_exist(&artifacts) {
        return Err("ZK circuit artifacts not found".to_string());
    }

    info!(session_id = session_data.session_id, "building ZK witness");
    let (witness, public) = zk_witness::build_witness(session_data)?;

    info!("generating Groth16 proof");
    let proof = zk_prove::generate_proof(&artifacts, &witness, &public)?;

    let tx_hash = wallet::settle_zk_session(ctx, &proof, session_data).await?;
    Ok(SettlementResult { tx_hash, method: "zk" })
}
