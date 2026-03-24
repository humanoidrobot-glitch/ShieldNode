//! EIP-712 bandwidth receipt signing for the relay node.
//!
//! Mirrors the on-chain `SessionSettlement` contract's EIP-712 domain and
//! `BandwidthReceipt` struct type so that signatures produced here are
//! verifiable by `ecrecover` inside the contract.

use alloy::primitives::{keccak256, Address, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;

// ── EIP-712 constants ────────────────────────────────────────────────────

/// `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`
fn eip712_domain_typehash() -> B256 {
    keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    )
}

/// `keccak256("BandwidthReceipt(uint256 sessionId,uint256 cumulativeBytes,uint256 timestamp)")`
fn receipt_typehash() -> B256 {
    keccak256("BandwidthReceipt(uint256 sessionId,uint256 cumulativeBytes,uint256 timestamp)")
}

// ── public helpers ───────────────────────────────────────────────────────

/// Compute the EIP-712 domain separator for the ShieldNode settlement contract.
///
/// ```text
/// DOMAIN_SEPARATOR = keccak256(abi.encode(
///     DOMAIN_TYPEHASH,
///     keccak256("ShieldNode"),
///     keccak256("1"),
///     chainId,
///     verifyingContract
/// ))
/// ```
pub fn compute_domain_separator(chain_id: u64, verifying_contract: Address) -> B256 {
    let domain_typehash = eip712_domain_typehash();
    let name_hash = keccak256("ShieldNode");
    let version_hash = keccak256("1");

    // abi.encode packs each value into a 32-byte word
    let mut buf = Vec::with_capacity(5 * 32);
    buf.extend_from_slice(domain_typehash.as_slice());
    buf.extend_from_slice(name_hash.as_slice());
    buf.extend_from_slice(version_hash.as_slice());
    buf.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    // Address is 20 bytes, left-padded to 32 bytes for abi.encode
    let mut addr_word = [0u8; 32];
    addr_word[12..].copy_from_slice(verifying_contract.as_slice());
    buf.extend_from_slice(&addr_word);

    keccak256(&buf)
}

/// Compute the full EIP-712 digest for a `BandwidthReceipt`.
///
/// ```text
/// digest = keccak256("\x19\x01" || DOMAIN_SEPARATOR || structHash)
/// structHash = keccak256(abi.encode(RECEIPT_TYPEHASH, sessionId, cumulativeBytes, timestamp))
/// ```
pub fn compute_receipt_digest(
    domain_sep: &B256,
    session_id: u64,
    cumulative_bytes: u64,
    timestamp: u64,
) -> B256 {
    // struct hash
    let typehash = receipt_typehash();
    let mut struct_buf = Vec::with_capacity(4 * 32);
    struct_buf.extend_from_slice(typehash.as_slice());
    struct_buf.extend_from_slice(&U256::from(session_id).to_be_bytes::<32>());
    struct_buf.extend_from_slice(&U256::from(cumulative_bytes).to_be_bytes::<32>());
    struct_buf.extend_from_slice(&U256::from(timestamp).to_be_bytes::<32>());
    let struct_hash = keccak256(&struct_buf);

    // EIP-712 envelope
    let mut envelope = Vec::with_capacity(2 + 32 + 32);
    envelope.push(0x19);
    envelope.push(0x01);
    envelope.extend_from_slice(domain_sep.as_slice());
    envelope.extend_from_slice(struct_hash.as_slice());

    keccak256(&envelope)
}

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

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::FixedBytes;

    #[test]
    fn domain_separator_is_deterministic() {
        let addr: Address = "0xC6D9923E54547e0C7c5B456bFf16fEdF2d61df11"
            .parse()
            .unwrap();
        let ds1 = compute_domain_separator(11155111, addr);
        let ds2 = compute_domain_separator(11155111, addr);
        assert_eq!(ds1, ds2);
    }

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
