//! Bridge between the Rust backend and the frontend wallet (WalletConnect).
//!
//! When WalletConnect mode is active, signing requests are delegated to the
//! frontend via Tauri events. The frontend calls the connected wallet
//! (MetaMask, etc.) and returns the result via Tauri commands.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tokio::sync::Mutex;
use tracing::{info, warn};

/// A pending signing request awaiting a response from the frontend.
struct PendingRequest {
    tx: oneshot::Sender<SigningResponse>,
}

/// Manages pending signing requests between backend and frontend.
pub struct WalletBridge {
    pending: Mutex<Option<PendingRequest>>,
}

/// A signing request sent to the frontend.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum SigningRequest {
    /// Request to send a transaction.
    SendTransaction {
        to: String,
        data: String,
        value: String,
        /// Unique request ID for correlation.
        request_id: String,
    },
    /// Request to sign an EIP-712 typed data hash.
    SignTypedData {
        /// Hex-encoded 32-byte digest to sign.
        digest: String,
        /// Human-readable description for the wallet prompt.
        description: String,
        request_id: String,
    },
}

/// Response from the frontend after signing.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum SigningResponse {
    /// Transaction was sent. Contains the tx hash.
    TransactionSent { tx_hash: String, request_id: String },
    /// Typed data was signed. Contains the 65-byte hex signature.
    Signature { signature: String, request_id: String },
    /// User rejected or wallet errored.
    Error { message: String, request_id: String },
}

impl WalletBridge {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(None),
        }
    }

    /// Send a signing request to the frontend and wait for the response.
    ///
    /// The caller must ensure the Tauri app handle emits the request as an
    /// event. This function blocks until the frontend calls `resolve_signing`.
    pub async fn request_signing(
        &self,
        timeout_secs: u64,
    ) -> Result<SigningResponse, String> {
        let (tx, rx) = oneshot::channel();

        {
            let mut pending = self.pending.lock().await;
            *pending = Some(PendingRequest { tx });
        }

        match tokio::time::timeout(Duration::from_secs(timeout_secs), rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err("signing request channel dropped".to_string()),
            Err(_) => {
                // Clean up the pending request on timeout.
                let mut pending = self.pending.lock().await;
                *pending = None;
                Err(format!("wallet signing timed out after {timeout_secs}s"))
            }
        }
    }

    /// Resolve a pending signing request with a response from the frontend.
    ///
    /// Called by the Tauri command handler when the frontend returns a result.
    pub async fn resolve(&self, response: SigningResponse) -> Result<(), String> {
        let mut pending = self.pending.lock().await;
        match pending.take() {
            Some(req) => {
                req.tx.send(response).map_err(|_| "receiver dropped".to_string())
            }
            None => Err("no pending signing request".to_string()),
        }
    }
}

impl Default for WalletBridge {
    fn default() -> Self {
        Self::new()
    }
}
