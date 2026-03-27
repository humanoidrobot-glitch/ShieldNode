//! Settlement path selection: ZK (privacy-preserving) or plaintext (legacy).
//!
//! In "auto" mode, attempts ZK settlement first. If circuit artifacts are
//! not available or proof generation fails, falls back to plaintext.
//! In "zk" mode, fails if ZK proof cannot be generated.
//! In "plaintext" mode, always uses the legacy SessionSettlement path.

use tracing::{info, warn};

use crate::zk_prove::{self, CircuitArtifacts, PublicInputs, ReceiptWitness};
use crate::wallet::{self, WalletConfig};

/// Settlement mode.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SettlementMode {
    /// Always use ZK proof. Fail if artifacts unavailable.
    Zk,
    /// Always use plaintext (legacy SessionSettlement).
    Plaintext,
    /// Try ZK first, fall back to plaintext on failure.
    Auto,
}

impl Default for SettlementMode {
    fn default() -> Self {
        Self::Auto
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
            // Try ZK first, fall back to plaintext on any failure.
            match settle_zk(wallet_cfg, session_id).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    info!(error = %e, "ZK settlement unavailable, using plaintext");
                }
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

    // TODO: Build the full witness from session data and generate proof via
    // zk_prove::generate_proof(). Submit to ZKSettlement.settleWithProof.
    // Requires: dual-signed receipt, node Merkle proof, Poseidon commitments.
    Err("ZK proof witness construction not yet wired".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_serde_roundtrip() {
        let json = serde_json::to_string(&SettlementMode::Zk).unwrap();
        assert_eq!(json, "\"zk\"");
        let parsed: SettlementMode = serde_json::from_str("\"plaintext\"").unwrap();
        assert_eq!(parsed, SettlementMode::Plaintext);
        let parsed: SettlementMode = serde_json::from_str("\"auto\"").unwrap();
        assert_eq!(parsed, SettlementMode::Auto);
    }

    #[test]
    fn default_artifacts_paths() {
        let a = default_artifacts();
        assert!(a.wasm_path.contains("circuit.wasm"));
        assert!(a.r1cs_path.contains("circuit.r1cs"));
        assert!(a.zkey_path.contains("circuit_final.zkey"));
    }
}
