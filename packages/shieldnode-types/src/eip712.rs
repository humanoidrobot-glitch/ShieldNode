//! Shared EIP-712 domain separator and receipt digest computation.

use alloy_primitives::{keccak256, Address, B256, U256};

/// EIP-712 BandwidthReceipt typehash.
pub fn receipt_typehash() -> B256 {
    keccak256("BandwidthReceipt(uint256 sessionId,uint256 cumulativeBytes,uint256 timestamp)")
}

/// Compute the EIP-712 domain separator for a ShieldNode contract.
pub fn compute_domain_separator(chain_id: u64, verifying_contract: Address) -> B256 {
    let domain_typehash = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let name_hash = keccak256("ShieldNode");
    let version_hash = keccak256("1");

    let mut buf = Vec::with_capacity(5 * 32);
    buf.extend_from_slice(domain_typehash.as_slice());
    buf.extend_from_slice(name_hash.as_slice());
    buf.extend_from_slice(version_hash.as_slice());
    buf.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    let mut addr_word = [0u8; 32];
    addr_word[12..].copy_from_slice(verifying_contract.as_slice());
    buf.extend_from_slice(&addr_word);

    keccak256(&buf)
}

/// Compute the EIP-712 digest for a bandwidth receipt.
///
/// `digest = keccak256("\x19\x01" || domainSeparator || structHash)`
pub fn compute_receipt_digest(
    domain_separator: &B256,
    session_id: u64,
    cumulative_bytes: u64,
    timestamp: u64,
) -> B256 {
    let typehash = receipt_typehash();

    let mut struct_buf = Vec::with_capacity(4 * 32);
    struct_buf.extend_from_slice(typehash.as_slice());
    struct_buf.extend_from_slice(&U256::from(session_id).to_be_bytes::<32>());
    struct_buf.extend_from_slice(&U256::from(cumulative_bytes).to_be_bytes::<32>());
    struct_buf.extend_from_slice(&U256::from(timestamp).to_be_bytes::<32>());
    let struct_hash = keccak256(&struct_buf);

    let mut envelope = Vec::with_capacity(2 + 32 + 32);
    envelope.extend_from_slice(b"\x19\x01");
    envelope.extend_from_slice(domain_separator.as_slice());
    envelope.extend_from_slice(struct_hash.as_slice());

    keccak256(&envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_separator_deterministic() {
        let addr: Address = "0xC6D9923E54547e0C7c5B456bFf16fEdF2d61df11"
            .parse()
            .unwrap();
        let ds1 = compute_domain_separator(11155111, addr);
        let ds2 = compute_domain_separator(11155111, addr);
        assert_eq!(ds1, ds2);
    }

    #[test]
    fn receipt_digest_deterministic() {
        let addr: Address = "0xC6D9923E54547e0C7c5B456bFf16fEdF2d61df11"
            .parse()
            .unwrap();
        let ds = compute_domain_separator(11155111, addr);
        let d1 = compute_receipt_digest(&ds, 1, 1000, 1700000000);
        let d2 = compute_receipt_digest(&ds, 1, 1000, 1700000000);
        assert_eq!(d1, d2);
    }
}
