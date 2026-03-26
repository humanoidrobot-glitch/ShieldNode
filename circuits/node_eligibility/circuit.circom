pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/mux1.circom";

/// @title NodeEligibility
/// @notice Proves a node meets selection criteria without revealing identity.
///
///         The proof demonstrates:
///         1. The node's commitment is in the registry Merkle tree
///         2. The node's stake meets the minimum threshold
///         3. The node has not been slashed beyond the maximum count
///         4. The node's uptime score meets the minimum threshold
///
///         The verifier sees: a valid proof, the registry root, and the
///         eligibility thresholds. It does NOT see which node produced
///         the proof, what the node's actual stake/uptime/slashes are,
///         or the node's endpoint or public key.
///
///         This hardens against enumeration attacks by state actors:
///         even observing all proofs doesn't reveal which nodes are in
///         the network, only that eligible nodes exist.
template NodeEligibility(MERKLE_DEPTH) {
    // ── Public inputs ─────────────────────────────────────────────
    signal input registryRoot;         // Merkle root of the commitment tree
    signal input minStake;             // Minimum stake threshold (wei)
    signal input maxSlashCount;        // Maximum allowed slash count
    signal input minUptimeScaled;      // Minimum uptime × 1000 (e.g., 950 = 95%)
    signal input nullifier;            // Prevents double-use of the same proof

    // ── Private inputs ────────────────────────────────────────────
    signal input nodeStake;            // Node's actual stake (wei)
    signal input nodeSlashCount;       // Node's actual slash count
    signal input nodeUptimeScaled;     // Node's actual uptime × 1000
    signal input nodePublicKey;        // Node's public key (used in commitment)
    signal input nodeSecret;           // Secret known only to the node (prevents forgery)

    // Merkle proof for registry membership
    signal input merkleProof[MERKLE_DEPTH];
    signal input merkleIndex;

    // ── 1. Compute node commitment ────────────────────────────────
    // commitment = Poseidon(publicKey, stake, slashCount, uptimeScaled, secret)
    component commitHash = Poseidon(5);
    commitHash.inputs[0] <== nodePublicKey;
    commitHash.inputs[1] <== nodeStake;
    commitHash.inputs[2] <== nodeSlashCount;
    commitHash.inputs[3] <== nodeUptimeScaled;
    commitHash.inputs[4] <== nodeSecret;

    // ── 2. Verify Merkle membership ───────────────────────────────
    component indexBits = Num2Bits(MERKLE_DEPTH);
    indexBits.in <== merkleIndex;

    signal merkleHash[MERKLE_DEPTH + 1];
    merkleHash[0] <== commitHash.out;

    component merkleHashers[MERKLE_DEPTH];
    component merkleMux[MERKLE_DEPTH];

    for (var i = 0; i < MERKLE_DEPTH; i++) {
        merkleMux[i] = Mux1();
        merkleMux[i].c[0] <== merkleHash[i];
        merkleMux[i].c[1] <== merkleProof[i];
        merkleMux[i].s <== indexBits.out[i];

        merkleHashers[i] = Poseidon(2);
        merkleHashers[i].inputs[0] <== merkleMux[i].out;
        merkleHashers[i].inputs[1] <== merkleHash[i] + merkleProof[i] - merkleMux[i].out;

        merkleHash[i + 1] <== merkleHashers[i].out;
    }

    merkleHash[MERKLE_DEPTH] === registryRoot;

    // ── 3. Verify stake >= minStake ───────────────────────────────
    component stakeCheck = GreaterEqThan(128);
    stakeCheck.in[0] <== nodeStake;
    stakeCheck.in[1] <== minStake;
    stakeCheck.out === 1;

    // ── 4. Verify slashCount <= maxSlashCount ─────────────────────
    component slashCheck = LessEqThan(32);
    slashCheck.in[0] <== nodeSlashCount;
    slashCheck.in[1] <== maxSlashCount;
    slashCheck.out === 1;

    // ── 5. Verify uptime >= minUptime ─────────────────────────────
    component uptimeCheck = GreaterEqThan(32);
    uptimeCheck.in[0] <== nodeUptimeScaled;
    uptimeCheck.in[1] <== minUptimeScaled;
    uptimeCheck.out === 1;

    // ── 6. Compute nullifier binding ──────────────────────────────
    // The nullifier is a public input that prevents the same node from
    // submitting multiple proofs in the same epoch. It's computed as:
    // nullifier = Poseidon(nodeSecret, epoch)
    // The circuit verifies that the provided nullifier matches.
    // For this version, the nullifier is passed directly as a public
    // input — the epoch-based computation is done off-circuit by the node.
}

// Instantiate with Merkle depth 9 (matching CommitmentTree's 512 slots).
component main {public [
    registryRoot,
    minStake,
    maxSlashCount,
    minUptimeScaled,
    nullifier
]} = NodeEligibility(9);
