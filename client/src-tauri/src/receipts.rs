use serde::{Deserialize, Serialize};
use tracing::info;

/// A bandwidth-receipt that both the client and node co-sign to prove how
/// much data was relayed in a given session.  These receipts are submitted
/// on-chain during settlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthReceipt {
    /// The on-chain session identifier.
    pub session_id: String,

    /// Cumulative bytes transferred so far in this session.
    pub cumulative_bytes: u64,

    /// Unix timestamp (seconds) when this receipt was created.
    pub timestamp: u64,

    /// ECDSA (or Ed25519) signature from the client.
    pub client_signature: Vec<u8>,

    /// ECDSA (or Ed25519) signature from the node.
    pub node_signature: Vec<u8>,
}

/// Create a new **unsigned** bandwidth receipt.
///
/// Both signature fields are left empty; call [`sign_receipt`] afterwards.
pub fn create_receipt(session_id: &str, bytes: u64) -> BandwidthReceipt {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    info!(
        session_id,
        cumulative_bytes = bytes,
        timestamp,
        "created unsigned bandwidth receipt"
    );

    BandwidthReceipt {
        session_id: session_id.to_string(),
        cumulative_bytes: bytes,
        timestamp,
        client_signature: Vec::new(),
        node_signature: Vec::new(),
    }
}

/// Sign a receipt with the client's private key.
///
/// **Phase 1 stub** — writes a deterministic placeholder into
/// `client_signature` so the rest of the pipeline can be exercised.
pub fn sign_receipt(receipt: &mut BandwidthReceipt, _private_key: &[u8; 32]) {
    // TODO: produce a real ECDSA / Ed25519 signature over the receipt payload
    let placeholder: Vec<u8> = {
        let mut sig = Vec::with_capacity(64);
        sig.extend_from_slice(&receipt.cumulative_bytes.to_le_bytes());
        sig.extend_from_slice(&receipt.timestamp.to_le_bytes());
        // Pad to 64 bytes (typical signature length)
        sig.resize(64, 0xAA);
        sig
    };

    receipt.client_signature = placeholder;

    info!(
        session_id = %receipt.session_id,
        sig_len = receipt.client_signature.len(),
        "receipt signed with placeholder (stub)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_receipt_is_unsigned() {
        let r = create_receipt("sess-1", 4096);
        assert_eq!(r.session_id, "sess-1");
        assert_eq!(r.cumulative_bytes, 4096);
        assert!(r.client_signature.is_empty());
        assert!(r.node_signature.is_empty());
    }

    #[test]
    fn sign_receipt_fills_client_sig() {
        let mut r = create_receipt("sess-2", 8192);
        let fake_key = [0u8; 32];
        sign_receipt(&mut r, &fake_key);
        assert_eq!(r.client_signature.len(), 64);
        // node_signature should still be empty
        assert!(r.node_signature.is_empty());
    }
}
