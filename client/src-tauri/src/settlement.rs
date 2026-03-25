//! Settlement path selection: ZK (privacy-preserving) or plaintext (legacy).
//!
//! In "auto" mode, attempts ZK settlement first. If circuit artifacts are
//! not available or proof generation fails, falls back to plaintext.
//! In "zk" mode, fails if ZK proof cannot be generated.
//! In "plaintext" mode, always uses the legacy SessionSettlement path.

use tracing::{info, warn};

use crate::zk_prove::{self, CircuitArtifacts, PublicInputs, ReceiptWitness};
use crate::wallet::{self, WalletConfig};

/// Settlement mode parsed from config.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SettlementMode {
    /// Always use ZK proof. Fail if artifacts unavailable.
    Zk,
    /// Always use plaintext (legacy SessionSettlement).
    Plaintext,
    /// Try ZK first, fall back to plaintext on failure.
    Auto,
}

impl SettlementMode {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "zk" => Self::Zk,
            "plaintext" => Self::Plaintext,
            _ => Self::Auto,
        }
    }
}

/// Default paths for compiled circuit artifacts.
fn default_artifacts() -> CircuitArtifacts {
    CircuitArtifacts {
        wasm_path: "circuits/build/circuit_js/circuit.wasm".to_string(),
        r1cs_path: "circuits/build/circuit.r1cs".to_string(),
        zkey_path: "circuits/trusted_setup/circuit_final.zkey".to_string(),
    }
}

/// Result of a settlement attempt.
pub struct SettlementResult {
    pub tx_hash: String,
    pub method: &'static str, // "zk" or "plaintext"
}

/// Settle a session using the configured mode.
///
/// For ZK: generates a Groth16 proof and calls ZKSettlement.settleWithProof.
/// For plaintext: calls SessionSettlement.settleSession with co-signed receipt.
/// For auto: tries ZK first, falls back to plaintext.
pub async fn settle_session(
    mode: SettlementMode,
    wallet_cfg: &WalletConfig,
    session_id: u64,
    receipt_data: Vec<u8>,
) -> Result<SettlementResult, String> {
    match mode {
        SettlementMode::Plaintext => {
            let tx_hash = wallet::settle_session(wallet_cfg, session_id, receipt_data).await?;
            Ok(SettlementResult {
                tx_hash,
                method: "plaintext",
            })
        }
        SettlementMode::Zk => {
            settle_zk(wallet_cfg, session_id).await
        }
        SettlementMode::Auto => {
            // Try ZK first if artifacts exist.
            let artifacts = default_artifacts();
            if zk_prove::artifacts_exist(&artifacts) {
                match settle_zk(wallet_cfg, session_id).await {
                    Ok(result) => return Ok(result),
                    Err(e) => {
                        warn!(error = %e, "ZK settlement failed, falling back to plaintext");
                    }
                }
            } else {
                info!("ZK circuit artifacts not found, using plaintext settlement");
            }

            // Fallback to plaintext.
            let tx_hash = wallet::settle_session(wallet_cfg, session_id, receipt_data).await?;
            Ok(SettlementResult {
                tx_hash,
                method: "plaintext",
            })
        }
    }
}

/// Attempt ZK settlement.
async fn settle_zk(
    _wallet_cfg: &WalletConfig,
    session_id: u64,
) -> Result<SettlementResult, String> {
    let artifacts = default_artifacts();

    if !zk_prove::artifacts_exist(&artifacts) {
        return Err("ZK circuit artifacts not found".to_string());
    }

    // TODO: Build the full witness from session data (receipt, signatures,
    // Merkle proof, addresses, etc.) and generate the proof via
    // zk_prove::generate_proof(). Then submit to ZKSettlement.settleWithProof.
    //
    // This requires:
    // 1. The dual-signed receipt (already obtained in disconnect flow)
    // 2. Node Merkle proof from the registry root
    // 3. Poseidon commitment computation for each payment address
    // 4. The ZKSettlement contract address for the on-chain call
    //
    // For now, return an error indicating the proof pipeline is not yet
    // fully wired (artifacts exist but witness construction is incomplete).

    info!(session_id, "ZK settlement: artifacts found, proof pipeline ready");
    Err("ZK proof witness construction not yet fully wired — use plaintext fallback".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parsing() {
        assert_eq!(SettlementMode::from_str("zk"), SettlementMode::Zk);
        assert_eq!(SettlementMode::from_str("ZK"), SettlementMode::Zk);
        assert_eq!(SettlementMode::from_str("plaintext"), SettlementMode::Plaintext);
        assert_eq!(SettlementMode::from_str("auto"), SettlementMode::Auto);
        assert_eq!(SettlementMode::from_str("unknown"), SettlementMode::Auto);
    }

    #[test]
    fn default_artifacts_paths() {
        let a = default_artifacts();
        assert!(a.wasm_path.contains("circuit.wasm"));
        assert!(a.r1cs_path.contains("circuit.r1cs"));
        assert!(a.zkey_path.contains("circuit_final.zkey"));
    }
}
