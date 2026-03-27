pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/mux1.circom";

/// @title MerkleVerify
/// @notice Verifies a Poseidon Merkle inclusion proof.
///
///         Given a leaf hash, a Merkle index, and a sibling path, walks
///         the tree from leaf to root using Poseidon(2) at each level.
///         Constrains the computed root to equal the expected root.
///
/// @param DEPTH  Number of levels in the Merkle tree.
template MerkleVerify(DEPTH) {
    signal input leaf;                 // Hash of the leaf to verify
    signal input index;                // Leaf index (bit-decomposed internally)
    signal input siblings[DEPTH];      // Sibling hashes along the path
    signal input root;                 // Expected Merkle root

    component indexBits = Num2Bits(DEPTH);
    indexBits.in <== index;

    signal hash[DEPTH + 1];
    hash[0] <== leaf;

    component hashers[DEPTH];
    component mux[DEPTH];

    for (var i = 0; i < DEPTH; i++) {
        mux[i] = Mux1();
        mux[i].c[0] <== hash[i];
        mux[i].c[1] <== siblings[i];
        mux[i].s <== indexBits.out[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i].out;
        // XOR trick: A + B - selected = the other value
        hashers[i].inputs[1] <== hash[i] + siblings[i] - mux[i].out;

        hash[i + 1] <== hashers[i].out;
    }

    hash[DEPTH] === root;
}
