use alloy::primitives::{keccak256, Address, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::sol_types::SolValue;
use tracing::info;

/// Compute the EIP-712 type hash for BandwidthReceipt.
fn receipt_typehash() -> B256 {
    keccak256("BandwidthReceipt(uint256 sessionId,uint256 cumulativeBytes,uint256 timestamp)")
}

/// Compute the EIP-712 domain separator for the ShieldNode protocol.
///
/// ```text
/// DOMAIN_SEPARATOR = keccak256(abi.encode(
///     keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
///     keccak256("ShieldNode"),
///     keccak256("1"),
///     chainId,
///     verifyingContract
/// ))
/// ```
pub fn compute_domain_separator(chain_id: u64, contract: Address) -> B256 {
    let domain_typehash = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let name_hash = keccak256("ShieldNode");
    let version_hash = keccak256("1");

    // abi.encode(domainTypeHash, nameHash, versionHash, chainId, verifyingContract)
    let mut buf = Vec::with_capacity(5 * 32);
    buf.extend_from_slice(domain_typehash.as_slice());
    buf.extend_from_slice(name_hash.as_slice());
    buf.extend_from_slice(version_hash.as_slice());
    buf.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    // Address is 20 bytes; ABI-encode it left-padded to 32 bytes.
    let mut addr_word = [0u8; 32];
    addr_word[12..32].copy_from_slice(contract.as_slice());
    buf.extend_from_slice(&addr_word);

    keccak256(&buf)
}

/// Compute the EIP-712 digest for a BandwidthReceipt.
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
    // Compute struct hash: keccak256(abi.encode(typehash, sessionId, cumulativeBytes, timestamp))
    let typehash = receipt_typehash();
    let mut struct_buf = Vec::with_capacity(4 * 32);
    struct_buf.extend_from_slice(typehash.as_slice());
    struct_buf.extend_from_slice(&U256::from(session_id).to_be_bytes::<32>());
    struct_buf.extend_from_slice(&U256::from(cumulative_bytes).to_be_bytes::<32>());
    struct_buf.extend_from_slice(&U256::from(timestamp).to_be_bytes::<32>());
    let struct_hash = keccak256(&struct_buf);

    // EIP-712 digest: keccak256("\x19\x01" || domainSeparator || structHash)
    let mut digest_buf = Vec::with_capacity(2 + 32 + 32);
    digest_buf.push(0x19);
    digest_buf.push(0x01);
    digest_buf.extend_from_slice(domain_sep.as_slice());
    digest_buf.extend_from_slice(struct_hash.as_slice());

    keccak256(&digest_buf)
}

/// Sign an EIP-712 digest with the given private key signer.
///
/// Returns a 65-byte signature in `r[32] || s[32] || v[1]` format,
/// where v is 27 or 28 (Electrum notation).
pub async fn sign_receipt(digest: &B256, signer: &PrivateKeySigner) -> Result<Vec<u8>, String> {
    let signature = signer
        .sign_hash(digest)
        .await
        .map_err(|e| format!("failed to sign receipt digest: {e}"))?;

    let bytes = signature.as_bytes(); // r[32] || s[32] || v[1] (v = 27 or 28)
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
///
/// This uses Solidity's standard ABI encoding with dynamic `bytes` types for
/// the two signatures.
pub fn encode_settlement_receipt(
    session_id: u64,
    cumulative_bytes: u64,
    timestamp: u64,
    client_sig: &[u8],
    node_sig: &[u8],
) -> Vec<u8> {
    // abi.encode(uint256, uint256, uint256, bytes, bytes)
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

    #[test]
    fn domain_separator_is_deterministic() {
        let contract: Address = "0xF32aE5324E3caCCEC4F198FEF783482A0c5eE959"
            .parse()
            .unwrap();
        let sep1 = compute_domain_separator(11155111, contract);
        let sep2 = compute_domain_separator(11155111, contract);
        assert_eq!(sep1, sep2);
        // Should not be zero
        assert_ne!(sep1, B256::ZERO);
    }

    #[test]
    fn digest_changes_with_inputs() {
        let contract: Address = "0xF32aE5324E3caCCEC4F198FEF783482A0c5eE959"
            .parse()
            .unwrap();
        let sep = compute_domain_separator(11155111, contract);

        let d1 = compute_receipt_digest(&sep, 1, 1000, 1700000000);
        let d2 = compute_receipt_digest(&sep, 1, 2000, 1700000000);
        let d3 = compute_receipt_digest(&sep, 2, 1000, 1700000000);

        assert_ne!(d1, d2);
        assert_ne!(d1, d3);
        assert_ne!(d2, d3);
    }

    #[tokio::test]
    async fn sign_receipt_produces_65_bytes() {
        let signer: PrivateKeySigner =
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                .parse()
                .unwrap();
        let contract: Address = "0xF32aE5324E3caCCEC4F198FEF783482A0c5eE959"
            .parse()
            .unwrap();
        let sep = compute_domain_separator(11155111, contract);
        let digest = compute_receipt_digest(&sep, 1, 4096, 1700000000);
        let sig = sign_receipt(&digest, &signer).await.unwrap();
        assert_eq!(sig.len(), 65);
        // v should be 27 or 28
        assert!(sig[64] == 27 || sig[64] == 28);
    }

    #[test]
    fn encode_settlement_receipt_has_correct_length() {
        let client_sig = [0xAAu8; 65];
        let node_sig = [0xBBu8; 65];
        let encoded = encode_settlement_receipt(1, 4096, 1700000000, &client_sig, &node_sig);
        // 5 words (static) + 1 word (len) + 3 words (data) + 1 word (len) + 3 words (data)
        // = 13 * 32 = 416 bytes
        assert_eq!(encoded.len(), 13 * 32);
    }

    #[test]
    fn receipt_typehash_is_not_zero() {
        assert_ne!(receipt_typehash(), B256::ZERO);
    }
}
