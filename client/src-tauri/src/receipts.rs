use alloy::primitives::{B256, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::sol_types::SolValue;
use tracing::info;

// Re-export shared EIP-712 functions so existing callers still find them here.
pub use shieldnode_types::eip712::{
    compute_domain_separator, compute_receipt_digest, receipt_typehash,
};

/// Sign an EIP-712 digest with the given private key signer.
///
/// Returns a 65-byte signature in `r[32] || s[32] || v[1]` format,
/// where v is 27 or 28 (Electrum notation).
pub async fn sign_receipt(digest: &B256, signer: &PrivateKeySigner) -> Result<Vec<u8>, String> {
    let signature = signer
        .sign_hash(digest)
        .await
        .map_err(|e| format!("failed to sign receipt digest: {e}"))?;

    let bytes = signature.as_bytes();
    info!(
        sig_len = bytes.len(),
        v = bytes[64],
        "signed EIP-712 receipt digest"
    );
    Ok(bytes.to_vec())
}

/// ABI-encode the full settlement receipt for `settleSession(uint256, bytes)`.
///
/// The `signedReceipt` bytes are:
/// ```text
/// abi.encode(sessionId, cumulativeBytes, timestamp, clientSig[65], nodeSig[65])
/// ```
pub fn encode_settlement_receipt(
    session_id: u64,
    cumulative_bytes: u64,
    timestamp: u64,
    client_sig: &[u8],
    node_sig: &[u8],
) -> Vec<u8> {
    let buf = (
        U256::from(session_id),
        U256::from(cumulative_bytes),
        U256::from(timestamp),
        client_sig.to_vec(),
        node_sig.to_vec(),
    )
        .abi_encode_params();

    info!(
        session_id,
        cumulative_bytes,
        timestamp,
        encoded_len = buf.len(),
        "ABI-encoded settlement receipt"
    );

    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Address;

    #[test]
    fn domain_separator_is_deterministic() {
        let addr: Address = "0xF32aE5324E3caCCEC4F198FEF783482A0c5eE959"
            .parse()
            .unwrap();
        let ds1 = compute_domain_separator(11155111, addr);
        let ds2 = compute_domain_separator(11155111, addr);
        assert_eq!(ds1, ds2);
    }

    #[test]
    fn receipt_digest_is_deterministic() {
        let addr: Address = "0xF32aE5324E3caCCEC4F198FEF783482A0c5eE959"
            .parse()
            .unwrap();
        let ds = compute_domain_separator(11155111, addr);
        let d1 = compute_receipt_digest(&ds, 1, 5000, 1700000000);
        let d2 = compute_receipt_digest(&ds, 1, 5000, 1700000000);
        assert_eq!(d1, d2);
    }

    #[test]
    fn encode_settlement_receipt_nonempty() {
        let buf = encode_settlement_receipt(1, 5000, 1700000000, &[0u8; 65], &[0u8; 65]);
        assert!(!buf.is_empty());
    }
}
