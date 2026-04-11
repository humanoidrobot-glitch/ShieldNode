//! EIP-712 bandwidth receipt signing for the relay node.

use alloy::primitives::B256;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;

// Re-export shared EIP-712 functions.
pub use shieldnode_types::eip712::{
    compute_domain_separator, compute_receipt_digest, receipt_typehash,
};

/// Sign an EIP-712 digest with the node operator's private key and return the
/// 65-byte signature in `r || s || v` format expected by the settlement
/// contract.
pub async fn sign_receipt_digest(
    digest: &B256,
    signer: &PrivateKeySigner,
) -> Result<Vec<u8>, String> {
    let signature = signer
        .sign_hash(digest)
        .await
        .map_err(|e| format!("signing receipt digest failed: {e}"))?;

    Ok(signature.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, FixedBytes};

    #[test]
    fn digest_changes_with_inputs() {
        let addr: Address = "0xC6D9923E54547e0C7c5B456bFf16fEdF2d61df11"
            .parse()
            .unwrap();
        let ds = compute_domain_separator(11155111, addr);
        let d1 = compute_receipt_digest(&ds, 1, 1000, 1700000000);
        let d2 = compute_receipt_digest(&ds, 1, 2000, 1700000000);
        assert_ne!(d1, d2);
    }

    #[tokio::test]
    async fn sign_receipt_digest_produces_65_bytes() {
        let signer = PrivateKeySigner::from_bytes(&FixedBytes::from([0x01u8; 32])).unwrap();
        let addr: Address = "0xC6D9923E54547e0C7c5B456bFf16fEdF2d61df11"
            .parse()
            .unwrap();
        let ds = compute_domain_separator(11155111, addr);
        let digest = compute_receipt_digest(&ds, 42, 5000, 1700000000);
        let sig = sign_receipt_digest(&digest, &signer).await.unwrap();
        assert_eq!(sig.len(), 65);
    }
}
