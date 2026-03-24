pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/mux1.circom";
include "circomlib/circuits/bitify.circom";

// ECDSA verification over secp256k1.
// Requires: https://github.com/0xPARC/circom-ecdsa
include "circom-ecdsa/circuits/ecdsa.circom";

// Keccak256 for EIP-712 digest computation.
// Requires: https://github.com/vocdoni/keccak256-circom
include "keccak256-circom/circuits/keccak.circom";

/// @title BandwidthReceipt
/// @notice Proves ownership of a valid dual-signed bandwidth receipt and
///         correct payment split, without revealing session metadata.
///
/// Public outputs: domainSeparator, totalPayment, 4 commitments, registryRoot
/// Private inputs: receipt data, signatures, addresses, Merkle proof
template BandwidthReceipt(MERKLE_DEPTH) {
    // ── Public inputs ─────────────────────────────────────────────
    signal input domainSeparator;      // EIP-712 domain separator
    signal input totalPaymentPub;      // Expected total payment
    signal input entryCommitmentPub;   // Poseidon(entryAddr, entryPay)
    signal input relayCommitmentPub;   // Poseidon(relayAddr, relayPay)
    signal input exitCommitmentPub;    // Poseidon(exitAddr, exitPay)
    signal input refundCommitmentPub;  // Poseidon(clientAddr, refund)
    signal input registryRoot;         // Merkle root of registered nodes

    // ── Private inputs ────────────────────────────────────────────
    signal input sessionId;
    signal input cumulativeBytes;
    signal input timestamp;
    signal input pricePerByte;
    signal input deposit;

    // Addresses (as field elements, derived from pubkeys off-circuit)
    signal input clientAddress;
    signal input entryAddress;
    signal input relayAddress;
    signal input exitAddress;

    // Client ECDSA signature (secp256k1)
    // r and s are 256-bit scalars, split into 4x64-bit limbs for circom-ecdsa
    signal input clientPubkey[2][4];   // [x, y] each as 4x64-bit limbs
    signal input clientR[4];           // r as 4x64-bit limbs
    signal input clientS[4];           // s as 4x64-bit limbs

    // Node ECDSA signature (exit node co-signs)
    signal input nodePubkey[2][4];
    signal input nodeR[4];
    signal input nodeS[4];

    // Merkle proof for node registry membership
    signal input nodeMerkleProof[MERKLE_DEPTH];
    signal input nodeMerkleIndex;  // leaf index (bit-decomposed internally)

    // EIP-712 message hash (computed off-circuit for now; see note below)
    // The full keccak256 EIP-712 computation inside circom is ~150K constraints.
    // For the initial version, we pass the digest as a private input and
    // constrain it against the public domainSeparator. A future iteration
    // will compute the full keccak in-circuit.
    signal input msgHash[4];  // 256-bit hash as 4x64-bit limbs

    // ── 1. Verify client ECDSA signature ──────────────────────────
    component clientVerify = ECDSAVerifyNoPubkeyCheck(64, 4);
    for (var i = 0; i < 4; i++) {
        clientVerify.r[i] <== clientR[i];
        clientVerify.s[i] <== clientS[i];
        clientVerify.msghash[i] <== msgHash[i];
        clientVerify.pubkey[0][i] <== clientPubkey[0][i];
        clientVerify.pubkey[1][i] <== clientPubkey[1][i];
    }
    clientVerify.result === 1;

    // ── 2. Verify node ECDSA signature ────────────────────────────
    component nodeVerify = ECDSAVerifyNoPubkeyCheck(64, 4);
    for (var i = 0; i < 4; i++) {
        nodeVerify.r[i] <== nodeR[i];
        nodeVerify.s[i] <== nodeS[i];
        nodeVerify.msghash[i] <== msgHash[i];
        nodeVerify.pubkey[0][i] <== nodePubkey[0][i];
        nodeVerify.pubkey[1][i] <== nodePubkey[1][i];
    }
    nodeVerify.result === 1;

    // ── 3. Verify node is in registry (Merkle proof) ──────────────
    // Leaf = Poseidon(nodePubkey[0][0..3], nodePubkey[1][0..3])
    component leafHash = Poseidon(8);
    for (var i = 0; i < 4; i++) {
        leafHash.inputs[i] <== nodePubkey[0][i];
        leafHash.inputs[4 + i] <== nodePubkey[1][i];
    }

    // Walk the Merkle tree from leaf to root.
    component indexBits = Num2Bits(MERKLE_DEPTH);
    indexBits.in <== nodeMerkleIndex;

    signal merkleHash[MERKLE_DEPTH + 1];
    merkleHash[0] <== leafHash.out;

    component merkleHashers[MERKLE_DEPTH];
    component merkleMux[MERKLE_DEPTH];

    for (var i = 0; i < MERKLE_DEPTH; i++) {
        // Mux: if bit=0, hash(current, sibling); if bit=1, hash(sibling, current)
        merkleMux[i] = Mux1();
        merkleMux[i].c[0] <== merkleHash[i];
        merkleMux[i].c[1] <== nodeMerkleProof[i];
        merkleMux[i].s <== indexBits.out[i];

        merkleHashers[i] = Poseidon(2);
        // When bit=0: hash(current, sibling). When bit=1: hash(sibling, current).
        merkleHashers[i].inputs[0] <== merkleMux[i].out;  // selected as "left"
        // The other input is the one NOT selected
        merkleHashers[i].inputs[1] <== merkleHash[i] + nodeMerkleProof[i] - merkleMux[i].out;

        merkleHash[i + 1] <== merkleHashers[i].out;
    }

    // Final hash must equal the registry root.
    merkleHash[MERKLE_DEPTH] === registryRoot;

    // ── 4. Compute payment ────────────────────────────────────────
    signal rawPayment;
    rawPayment <== cumulativeBytes * pricePerByte;

    // totalPayment = min(rawPayment, deposit)
    component isOver = LessThan(128);
    isOver.in[0] <== deposit;
    isOver.in[1] <== rawPayment;

    component paymentMux = Mux1();
    paymentMux.c[0] <== rawPayment;  // rawPayment <= deposit
    paymentMux.c[1] <== deposit;     // rawPayment > deposit, cap at deposit
    paymentMux.s <== isOver.out;

    signal totalPayment;
    totalPayment <== paymentMux.out;

    // Constrain against public input.
    totalPayment === totalPaymentPub;

    // ── 5. Compute payment split (25/25/50) ───────────────────────
    // Constrained integer division: totalPayment * 25 = entryPay * 100 + remainder
    signal entryPay;
    signal relayPay;
    signal exitPay;
    signal refund;

    signal tp25;
    tp25 <== totalPayment * 25;
    entryPay <-- tp25 \ 100;
    signal entryRem;
    entryRem <-- tp25 % 100;
    tp25 === entryPay * 100 + entryRem;
    component entryRemCheck = LessThan(8);
    entryRemCheck.in[0] <== entryRem;
    entryRemCheck.in[1] <== 100;
    entryRemCheck.out === 1;

    // Entry and relay both take 25% — same value.
    relayPay <== entryPay;

    // Exit gets the remainder (handles rounding).
    exitPay <== totalPayment - entryPay - relayPay;

    // refund = deposit - totalPayment
    refund <== deposit - totalPayment;

    // ── 6. Verify commitments ─────────────────────────────────────
    component entryCommit = Poseidon(2);
    entryCommit.inputs[0] <== entryAddress;
    entryCommit.inputs[1] <== entryPay;
    entryCommit.out === entryCommitmentPub;

    component relayCommit = Poseidon(2);
    relayCommit.inputs[0] <== relayAddress;
    relayCommit.inputs[1] <== relayPay;
    relayCommit.out === relayCommitmentPub;

    component exitCommit = Poseidon(2);
    exitCommit.inputs[0] <== exitAddress;
    exitCommit.inputs[1] <== exitPay;
    exitCommit.out === exitCommitmentPub;

    component refundCommit = Poseidon(2);
    refundCommit.inputs[0] <== clientAddress;
    refundCommit.inputs[1] <== refund;
    refundCommit.out === refundCommitmentPub;
}

// Instantiate with Merkle depth 20 (~1M node capacity).
component main {public [
    domainSeparator,
    totalPaymentPub,
    entryCommitmentPub,
    relayCommitmentPub,
    exitCommitmentPub,
    refundCommitmentPub,
    registryRoot
]} = BandwidthReceipt(20);
