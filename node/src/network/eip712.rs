//! Shared EIP-712 domain separator computation for the ShieldNode protocol.
//!
//! Used by both the receipt signer (`receipts.rs`) and the challenge responder
//! (`challenge.rs`) to avoid duplicating the domain encoding logic.

use alloy::primitives::{keccak256, Address, B256, U256};

/// `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`
pub fn eip712_domain_typehash() -> B256 {
    keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    )
}

/// Compute the EIP-712 domain separator for a ShieldNode contract.
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn different_addresses_produce_different_separators() {
        let a1: Address = "0xC6D9923E54547e0C7c5B456bFf16fEdF2d61df11"
            .parse()
            .unwrap();
        let a2: Address = "0x0000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        assert_ne!(
            compute_domain_separator(11155111, a1),
            compute_domain_separator(11155111, a2)
        );
    }
}
