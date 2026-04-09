//! Local Poseidon Merkle tree for ZK settlement.
//!
//! Builds a Poseidon-based Merkle tree from registered node secp256k1 public
//! keys, matching the circuit's `MerkleVerify(MERKLE_DEPTH)` template.
//! Provides proof extraction for individual nodes.
//!
//! Memory: ~64 MB at depth 20 (~2M internal nodes × 32 bytes).

use light_poseidon::{Poseidon, PoseidonBytesHasher};
use num_bigint::BigInt;

/// Merkle tree depth (must match circuit instantiation).
pub const MERKLE_DEPTH: usize = 20;

/// A Poseidon Merkle tree for the ZK node registry.
///
/// Stores all layers (leaves through root) for O(1) proof extraction.
pub struct PoseidonMerkleTree {
    /// Tree depth.
    depth: usize,
    /// Number of real leaves inserted.
    count: usize,
    /// Internal nodes, layer by layer from leaves to root.
    /// layers[0] = leaf hashes, layers[depth] = [root].
    layers: Vec<Vec<[u8; 32]>>,
}

/// A Merkle proof for a single leaf.
pub struct MerkleProof {
    /// Sibling hashes along the path from leaf to root.
    pub siblings: Vec<String>,
    /// Leaf index in the tree.
    pub index: u64,
    /// The Merkle root.
    pub root: String,
}

impl PoseidonMerkleTree {
    /// Build a new tree from secp256k1 public keys with the production depth.
    pub fn from_pubkeys(pubkeys: &[Vec<u8>]) -> Result<Self, String> {
        Self::from_pubkeys_with_depth(pubkeys, MERKLE_DEPTH)
    }

    /// Build a new tree from secp256k1 public keys with a custom depth.
    ///
    /// Each key should be 65 bytes (uncompressed: 0x04 || x[32] || y[32]).
    /// The leaf hash is `Poseidon(x_limb0..x_limb3, y_limb0..y_limb3)`,
    /// matching the circuit's `Poseidon(8)` template.
    pub fn from_pubkeys_with_depth(pubkeys: &[Vec<u8>], depth: usize) -> Result<Self, String> {
        let max_leaves = 1 << depth;
        if pubkeys.len() > max_leaves {
            return Err(format!("too many pubkeys: {} > {max_leaves}", pubkeys.len()));
        }

        // Create hashers once and reuse across all hashes.
        let mut hasher8 = Poseidon::<ark_bn254::Fr>::new_circom(8)
            .map_err(|e| format!("poseidon8 init: {e}"))?;
        let mut hasher2 = Poseidon::<ark_bn254::Fr>::new_circom(2)
            .map_err(|e| format!("poseidon2 init: {e}"))?;

        // Compute leaf hashes.
        let mut leaves = Vec::with_capacity(max_leaves);
        for (i, pk) in pubkeys.iter().enumerate() {
            if pk.len() != 65 || pk[0] != 0x04 {
                return Err(format!("pubkey[{i}]: expected 65-byte uncompressed key"));
            }
            let leaf = poseidon8_pubkey_with(&mut hasher8, pk)?;
            leaves.push(leaf);
        }
        let count = leaves.len();

        // Pad with zeros to fill the tree.
        leaves.resize(max_leaves, [0u8; 32]);

        // Build layers bottom-up. Move leaves into layers[0] (no clone).
        let mut layers: Vec<Vec<[u8; 32]>> = Vec::with_capacity(depth + 1);
        layers.push(leaves);

        for d in 0..depth {
            let prev = &layers[d];
            let mut next = Vec::with_capacity(prev.len() / 2);
            for pair in prev.chunks(2) {
                let hash = poseidon2_hash_with(&mut hasher2, &pair[0], &pair[1])?;
                next.push(hash);
            }
            layers.push(next);
        }

        Ok(Self { depth, count, layers })
    }

    /// Get the Merkle root as a decimal string.
    pub fn root(&self) -> String {
        let root_bytes = &self.layers[self.depth][0];
        BigInt::from_bytes_be(num_bigint::Sign::Plus, root_bytes).to_string()
    }

    /// Get the number of real (non-zero) leaves.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Extract a Merkle proof for a leaf at the given index.
    pub fn proof(&self, index: usize) -> Result<MerkleProof, String> {
        if index >= self.count {
            return Err(format!("index {index} >= count {}", self.count));
        }

        let mut siblings = Vec::with_capacity(self.depth);
        let mut idx = index;

        for d in 0..self.depth {
            let sibling_idx = idx ^ 1;
            let sibling = &self.layers[d][sibling_idx];
            siblings.push(BigInt::from_bytes_be(num_bigint::Sign::Plus, sibling).to_string());
            idx >>= 1;
        }

        Ok(MerkleProof {
            siblings,
            index: index as u64,
            root: self.root(),
        })
    }

    /// Find the leaf index for a given uncompressed secp256k1 pubkey.
    pub fn find_index(&self, pubkey: &[u8]) -> Result<usize, String> {
        let leaf = poseidon8_pubkey(pubkey)?;
        self.layers[0].iter()
            .position(|l| l == &leaf)
            .ok_or_else(|| "pubkey not found in tree".to_string())
    }
}

// ── Internal helpers ─────────────────────────────────────────────────────

/// Poseidon(2) hash with a pre-created hasher (avoids re-allocation).
fn poseidon2_hash_with(
    hasher: &mut Poseidon<ark_bn254::Fr>,
    a: &[u8; 32],
    b: &[u8; 32],
) -> Result<[u8; 32], String> {
    let hash_bytes = hasher
        .hash_bytes_be(&[a.as_slice(), b.as_slice()])
        .map_err(|e| format!("poseidon2 hash: {e}"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash_bytes);
    Ok(out)
}

/// Poseidon(8) hash with a pre-created hasher (avoids re-allocation).
fn poseidon8_pubkey_with(
    hasher: &mut Poseidon<ark_bn254::Fr>,
    pubkey: &[u8],
) -> Result<[u8; 32], String> {
    if pubkey.len() != 65 || pubkey[0] != 0x04 {
        return Err("poseidon8: expected 65-byte uncompressed key (0x04 prefix)".to_string());
    }
    hash_pubkey_coords(hasher, pubkey)
}

/// Poseidon(8) hash of a pubkey (standalone, creates its own hasher).
/// Used by `find_index` which doesn't have a hasher in scope.
fn poseidon8_pubkey(pubkey: &[u8]) -> Result<[u8; 32], String> {
    if pubkey.len() != 65 || pubkey[0] != 0x04 {
        return Err("poseidon8: expected 65-byte uncompressed key (0x04 prefix)".to_string());
    }
    let mut hasher = Poseidon::<ark_bn254::Fr>::new_circom(8)
        .map_err(|e| format!("poseidon8 init: {e}"))?;
    hash_pubkey_coords(&mut hasher, pubkey)
}

/// Core pubkey hashing: split x,y into 4×64-bit limbs, hash with Poseidon(8).
fn hash_pubkey_coords(
    hasher: &mut Poseidon<ark_bn254::Fr>,
    pubkey: &[u8],
) -> Result<[u8; 32], String> {
    let x = &pubkey[1..33];
    let y = &pubkey[33..65];

    let limb_bufs: Vec<[u8; 32]> = (0..8)
        .map(|i| {
            let coord = if i < 4 { x } else { y };
            let start = (i % 4) * 8;
            let limb_u64 = u64::from_be_bytes(coord[start..start + 8].try_into().unwrap());
            let mut buf = [0u8; 32];
            buf[24..32].copy_from_slice(&limb_u64.to_be_bytes());
            buf
        })
        .collect();

    let inputs: Vec<&[u8]> = limb_bufs.iter().map(|b| b.as_slice()).collect();

    let hash_bytes = hasher
        .hash_bytes_be(&inputs)
        .map_err(|e| format!("poseidon8 hash: {e}"))?;

    let mut out = [0u8; 32];
    out.copy_from_slice(&hash_bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_pubkey(seed: u8) -> Vec<u8> {
        let mut pk = vec![0x04];
        pk.extend(std::iter::repeat(seed).take(32));
        pk.extend(std::iter::repeat(seed.wrapping_add(1)).take(32));
        pk
    }

    const TEST_DEPTH: usize = 4;

    fn test_tree(pubkeys: &[Vec<u8>]) -> PoseidonMerkleTree {
        PoseidonMerkleTree::from_pubkeys_with_depth(pubkeys, TEST_DEPTH).unwrap()
    }

    #[test]
    fn build_tree_with_3_nodes() {
        let tree = test_tree(&[fake_pubkey(1), fake_pubkey(2), fake_pubkey(3)]);
        assert_eq!(tree.count(), 3);
        assert!(!tree.root().is_empty());
        assert_ne!(tree.root(), "0");
    }

    #[test]
    fn proof_has_correct_depth() {
        let tree = test_tree(&[fake_pubkey(10), fake_pubkey(20)]);
        let proof = tree.proof(0).unwrap();
        assert_eq!(proof.siblings.len(), TEST_DEPTH);
        assert_eq!(proof.index, 0);
        assert_eq!(proof.root, tree.root());
    }

    #[test]
    fn find_index_returns_correct_position() {
        let pk1 = fake_pubkey(1);
        let pk2 = fake_pubkey(2);
        let pk3 = fake_pubkey(3);
        let tree = test_tree(&[pk1.clone(), pk2.clone(), pk3.clone()]);
        assert_eq!(tree.find_index(&pk1).unwrap(), 0);
        assert_eq!(tree.find_index(&pk2).unwrap(), 1);
        assert_eq!(tree.find_index(&pk3).unwrap(), 2);
    }

    #[test]
    fn find_index_errors_for_missing_key() {
        let tree = test_tree(&[fake_pubkey(1)]);
        assert!(tree.find_index(&fake_pubkey(99)).is_err());
    }

    #[test]
    fn different_pubkeys_produce_different_roots() {
        let tree1 = test_tree(&[fake_pubkey(1)]);
        let tree2 = test_tree(&[fake_pubkey(2)]);
        assert_ne!(tree1.root(), tree2.root());
    }
}
