//! ZK witness construction for bandwidth receipt proofs.
//!
//! Converts raw session data (signatures, addresses, Merkle proofs) into the
//! `ReceiptWitness` + `PublicInputs` structures expected by the circom circuit.

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use light_poseidon::{Poseidon, PoseidonBytesHasher, PoseidonHasher};
use num_bigint::BigInt;

use crate::zk_prove::{PublicInputs, ReceiptWitness};

// ── Signature decomposition ──────────────────────────────────────────────

/// Split a 65-byte ECDSA signature (r || s || v) into 4×64-bit limbs for
/// circom-ecdsa. Returns (r_limbs, s_limbs) as decimal strings.
pub fn decompose_sig(sig: &[u8]) -> Result<(Vec<String>, Vec<String>), String> {
    if sig.len() != 65 {
        return Err(format!("expected 65-byte signature, got {}", sig.len()));
    }

    let r_bytes = &sig[0..32];
    let s_bytes = &sig[32..64];

    Ok((bytes32_to_limbs(r_bytes), bytes32_to_limbs(s_bytes)))
}

/// Recover the secp256k1 public key from a 65-byte signature + digest.
/// Returns [[x0,x1,x2,x3],[y0,y1,y2,y3]] as decimal strings.
pub fn recover_pubkey(sig: &[u8], digest: &[u8; 32]) -> Result<Vec<Vec<String>>, String> {
    if sig.len() != 65 {
        return Err(format!("expected 65-byte signature, got {}", sig.len()));
    }

    let r_s = Signature::from_slice(&sig[0..64])
        .map_err(|e| format!("invalid signature: {e}"))?;

    // v is 27 or 28 in Electrum notation; RecoveryId needs 0 or 1.
    let v = sig[64];
    let rec_id = RecoveryId::new(v.wrapping_sub(27) & 1 != 0, false);

    let key = VerifyingKey::recover_from_prehash(digest, &r_s, rec_id)
        .map_err(|e| format!("pubkey recovery failed: {e}"))?;

    // Get uncompressed point (65 bytes: 0x04 || x[32] || y[32]).
    let uncompressed = key.to_encoded_point(false);
    let x_bytes = uncompressed.x().ok_or("missing x coordinate")?;
    let y_bytes = uncompressed.y().ok_or("missing y coordinate")?;

    Ok(vec![
        bytes32_to_limbs(x_bytes),
        bytes32_to_limbs(y_bytes),
    ])
}

/// Recover the Ethereum address from a 65-byte ECDSA signature + digest.
/// Returns the address as a lowercase hex string (no 0x prefix).
pub fn recover_address(sig: &[u8], digest: &[u8; 32]) -> Result<String, String> {
    if sig.len() != 65 {
        return Err(format!("expected 65-byte signature, got {}", sig.len()));
    }

    let r_s = Signature::from_slice(&sig[0..64])
        .map_err(|e| format!("invalid signature: {e}"))?;

    let v = sig[64];
    let rec_id = RecoveryId::new(v.wrapping_sub(27) & 1 != 0, false);

    let key = VerifyingKey::recover_from_prehash(digest, &r_s, rec_id)
        .map_err(|e| format!("pubkey recovery failed: {e}"))?;

    // Ethereum address = last 20 bytes of keccak256(uncompressed_pubkey_without_prefix).
    let uncompressed = key.to_encoded_point(false);
    let pubkey_bytes = &uncompressed.as_bytes()[1..]; // skip 0x04 prefix
    let hash = alloy::primitives::keccak256(pubkey_bytes);
    let addr = &hash[12..]; // last 20 bytes
    Ok(hex::encode(addr))
}

// ── Poseidon hashing ─────────────────────────────────────────────────────

/// Poseidon(2) hash matching circomlib over the BN254 scalar field.
/// Takes two decimal string inputs, returns a decimal string output.
pub fn poseidon_hash2(a: &str, b: &str) -> Result<String, String> {
    let a_bi: BigInt = a.parse().map_err(|e| format!("invalid input a: {e}"))?;
    let b_bi: BigInt = b.parse().map_err(|e| format!("invalid input b: {e}"))?;

    let a_bytes = bigint_to_be_bytes32(&a_bi);
    let b_bytes = bigint_to_be_bytes32(&b_bi);

    let mut poseidon = Poseidon::<ark_bn254::Fr>::new_circom(2)
        .map_err(|e| format!("poseidon init failed: {e}"))?;

    let hash = poseidon
        .hash_bytes_be(&[&a_bytes, &b_bytes])
        .map_err(|e| format!("poseidon hash failed: {e}"))?;

    // Convert result to decimal string.
    let hash_bi = BigInt::from_bytes_be(num_bigint::Sign::Plus, &hash);
    Ok(hash_bi.to_string())
}

// ── Witness builder ──────────────────────────────────────────────────────

/// All data needed to construct a ZK settlement witness.
pub struct ZkSessionData {
    /// Session identifier.
    pub session_id: u64,
    /// Total bytes transferred.
    pub cumulative_bytes: u64,
    /// Receipt timestamp (UNIX seconds).
    pub timestamp: u64,
    /// Exit node's price per byte (wei).
    pub price_per_byte: u64,
    /// Original deposit amount (wei).
    pub deposit: u128,
    /// EIP-712 domain separator (hex, 32 bytes).
    pub domain_separator: [u8; 32],
    /// EIP-712 receipt digest (32 bytes).
    pub digest: [u8; 32],
    /// EIP-712 RECEIPT_TYPEHASH (32 bytes).
    pub receipt_typehash: [u8; 32],
    /// Deposit ID from ZKSettlement.deposit() (32 bytes).
    pub deposit_id: [u8; 32],

    /// Client's 65-byte ECDSA signature (r || s || v).
    pub client_sig: Vec<u8>,
    /// Exit node's 65-byte ECDSA co-signature (r || s || v).
    pub node_sig: Vec<u8>,

    /// Ethereum addresses of all participants (20 bytes each).
    pub client_address: [u8; 20],
    pub entry_address: [u8; 20],
    pub relay_address: [u8; 20],
    pub exit_address: [u8; 20],

    /// Merkle proofs for all 3 nodes (Poseidon tree).
    /// Each proof is MERKLE_DEPTH siblings as decimal strings.
    pub exit_merkle_proof: Vec<String>,
    pub exit_merkle_index: u64,
    pub entry_merkle_proof: Vec<String>,
    pub entry_merkle_index: u64,
    pub relay_merkle_proof: Vec<String>,
    pub relay_merkle_index: u64,

    /// secp256k1 public keys for entry/relay (needed for Merkle leaf computation).
    /// 65 bytes each (uncompressed: 0x04 || x[32] || y[32]).
    pub entry_secp256k1_pubkey: Vec<u8>,
    pub relay_secp256k1_pubkey: Vec<u8>,

    /// Current registry root (from ZKSettlement contract).
    pub registry_root: String,
}

/// Build the ZK witness from session data.
pub fn build_witness(data: &ZkSessionData) -> Result<(ReceiptWitness, PublicInputs), String> {
    // Decompose signatures into limbs.
    let (client_r, client_s) = decompose_sig(&data.client_sig)?;
    let (node_r, node_s) = decompose_sig(&data.node_sig)?;

    // Recover client and exit node secp256k1 public keys from signatures.
    let client_pubkey = recover_pubkey(&data.client_sig, &data.digest)?;
    let node_pubkey = recover_pubkey(&data.node_sig, &data.digest)?;

    // Decompose entry/relay pubkeys into limbs (already have the raw keys).
    let entry_pubkey = uncompressed_pubkey_to_limbs(&data.entry_secp256k1_pubkey)?;
    let relay_pubkey = uncompressed_pubkey_to_limbs(&data.relay_secp256k1_pubkey)?;

    // Compute payment amounts.
    let raw_payment = (data.cumulative_bytes as u128) * (data.price_per_byte as u128);
    let total_payment = raw_payment.min(data.deposit);
    let entry_pay = total_payment * 25 / 100;
    let relay_pay = entry_pay; // same as entry (25%)
    let exit_pay = total_payment - entry_pay - relay_pay;
    let refund = data.deposit - total_payment;

    // Compute Poseidon commitments.
    let client_addr_str = address_to_decimal(&data.client_address);
    let entry_addr_str = address_to_decimal(&data.entry_address);
    let relay_addr_str = address_to_decimal(&data.relay_address);
    let exit_addr_str = address_to_decimal(&data.exit_address);

    let entry_commitment = poseidon_hash2(&entry_addr_str, &entry_pay.to_string())?;
    let relay_commitment = poseidon_hash2(&relay_addr_str, &relay_pay.to_string())?;
    let exit_commitment = poseidon_hash2(&exit_addr_str, &exit_pay.to_string())?;
    let refund_commitment = poseidon_hash2(&client_addr_str, &refund.to_string())?;

    // Compute nullifier = Poseidon(sessionId, clientAddress).
    let nullifier = poseidon_hash2(
        &data.session_id.to_string(),
        &client_addr_str,
    )?;

    let witness = ReceiptWitness {
        session_id: data.session_id.to_string(),
        cumulative_bytes: data.cumulative_bytes.to_string(),
        timestamp: data.timestamp.to_string(),
        price_per_byte: data.price_per_byte.to_string(),
        deposit: data.deposit.to_string(),
        receipt_typehash: bytes32_to_decimal(&data.receipt_typehash),

        client_address: client_addr_str.clone(),
        entry_address: entry_addr_str,
        relay_address: relay_addr_str,
        exit_address: exit_addr_str,

        client_pubkey,
        client_r,
        client_s,

        node_pubkey,
        node_r,
        node_s,

        node_merkle_proof: data.exit_merkle_proof.clone(),
        node_merkle_index: data.exit_merkle_index.to_string(),

        entry_pubkey,
        entry_merkle_proof: data.entry_merkle_proof.clone(),
        entry_merkle_index: data.entry_merkle_index.to_string(),

        relay_pubkey,
        relay_merkle_proof: data.relay_merkle_proof.clone(),
        relay_merkle_index: data.relay_merkle_index.to_string(),

        deposit_id_private: bytes32_to_decimal(&data.deposit_id),
    };

    let public = PublicInputs {
        domain_separator: bytes32_to_decimal(&data.domain_separator),
        total_payment: total_payment.to_string(),
        entry_commitment,
        relay_commitment,
        exit_commitment,
        refund_commitment,
        registry_root: data.registry_root.clone(),
        nullifier,
        deposit_id: bytes32_to_decimal(&data.deposit_id),
        entry_pay: entry_pay.to_string(),
        relay_pay: relay_pay.to_string(),
        exit_pay: exit_pay.to_string(),
        refund: refund.to_string(),
    };

    Ok((witness, public))
}

// ── Internal helpers ─────────────────────────────────────────────────────

/// Convert a 32-byte big-endian value into 4×64-bit limbs (MSB-first) as
/// decimal strings. This matches circom-ecdsa's limb layout.
fn bytes32_to_limbs(bytes: &[u8]) -> Vec<String> {
    assert!(bytes.len() == 32);
    (0..4)
        .map(|i| {
            let start = i * 8;
            let limb_bytes = &bytes[start..start + 8];
            let val = u64::from_be_bytes(limb_bytes.try_into().unwrap());
            val.to_string()
        })
        .collect()
}

/// Convert a 32-byte big-endian value to a decimal string (field element).
fn bytes32_to_decimal(bytes: &[u8; 32]) -> String {
    BigInt::from_bytes_be(num_bigint::Sign::Plus, bytes).to_string()
}

/// Convert a 20-byte Ethereum address to a decimal string.
fn address_to_decimal(addr: &[u8; 20]) -> String {
    BigInt::from_bytes_be(num_bigint::Sign::Plus, addr).to_string()
}

/// Convert a BigInt to 32 big-endian bytes (zero-padded).
fn bigint_to_be_bytes32(bi: &BigInt) -> [u8; 32] {
    let (_, bytes) = bi.to_bytes_be();
    let mut result = [0u8; 32];
    let offset = 32_usize.saturating_sub(bytes.len());
    result[offset..offset + bytes.len()].copy_from_slice(&bytes);
    result
}

/// Convert an uncompressed secp256k1 public key (65 bytes: 0x04 || x || y)
/// into [[x0,x1,x2,x3],[y0,y1,y2,y3]] limb format.
fn uncompressed_pubkey_to_limbs(key: &[u8]) -> Result<Vec<Vec<String>>, String> {
    if key.len() != 65 || key[0] != 0x04 {
        return Err(format!(
            "expected 65-byte uncompressed secp256k1 key (0x04 prefix), got {} bytes",
            key.len()
        ));
    }
    Ok(vec![
        bytes32_to_limbs(&key[1..33]),  // x coordinate
        bytes32_to_limbs(&key[33..65]), // y coordinate
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sig_decomposition_correct_length() {
        // Create a dummy 65-byte signature.
        let mut sig = vec![0u8; 65];
        sig[0] = 1; // r starts with 1
        sig[32] = 2; // s starts with 2
        sig[64] = 27; // v

        let (r_limbs, s_limbs) = decompose_sig(&sig).unwrap();
        assert_eq!(r_limbs.len(), 4);
        assert_eq!(s_limbs.len(), 4);
    }

    #[test]
    fn sig_decomposition_rejects_wrong_length() {
        assert!(decompose_sig(&[0u8; 64]).is_err());
        assert!(decompose_sig(&[0u8; 66]).is_err());
    }

    #[test]
    fn bytes32_to_limbs_known_value() {
        let mut bytes = [0u8; 32];
        bytes[31] = 1; // least significant byte = 1
        let limbs = bytes32_to_limbs(&bytes);
        assert_eq!(limbs[3], "1"); // last limb = 1
        assert_eq!(limbs[0], "0"); // first limb = 0
    }

    #[test]
    fn poseidon_hash2_nonzero() {
        let result = poseidon_hash2("1", "2").unwrap();
        assert!(!result.is_empty());
        assert_ne!(result, "0");
    }

    #[test]
    fn address_to_decimal_known_value() {
        let mut addr = [0u8; 20];
        addr[19] = 1;
        assert_eq!(address_to_decimal(&addr), "1");
    }
}
