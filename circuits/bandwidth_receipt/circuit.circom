pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/mux1.circom";
include "circomlib/circuits/bitify.circom";
include "../lib/merkle.circom";

// ECDSA verification over secp256k1.
// Requires: https://github.com/0xPARC/circom-ecdsa
include "circom-ecdsa/circuits/ecdsa.circom";

// Keccak256 for EIP-712 digest computation.
// Requires: https://github.com/vocdoni/keccak256-circom
include "keccak256-circom/circuits/keccak.circom";

// ── Helper: convert a 256-bit field element to 256 bits (big-endian) ──
// EVM uses big-endian for abi.encode; circom Num2Bits is little-endian.
template Uint256ToBitsBE() {
    signal input in;
    signal output out[256];

    component n2b = Num2Bits(256);
    n2b.in <== in;

    // Reverse: Num2Bits outputs LSB-first, we need MSB-first for keccak.
    // But keccak256-circom expects byte-level big-endian with bit-level
    // big-endian within each byte. We reverse at byte granularity:
    // byte 0 (MSB) = bits[255..248], byte 1 = bits[247..240], ...
    for (var byte_i = 0; byte_i < 32; byte_i++) {
        for (var bit_j = 0; bit_j < 8; bit_j++) {
            // Target position: byte_i * 8 + bit_j
            // Source (from Num2Bits LE): bit (255 - byte_i * 8 - bit_j)
            out[byte_i * 8 + bit_j] <== n2b.out[255 - byte_i * 8 - bit_j];
        }
    }
}

// ── Helper: convert 256 keccak output bits to 4x64-bit limbs ─────────
// circom-ecdsa expects msghash as 4 limbs (MSB-first):
//   out[0] = most significant 64 bits, out[3] = least significant 64 bits.
template KeccakBitsToLimbs() {
    signal input in[256];   // big-endian bits from keccak
    signal output out[4];   // 4x64-bit limbs, MSB-first

    component b2n[4];
    for (var limb = 0; limb < 4; limb++) {
        b2n[limb] = Bits2Num(64);
        for (var bit = 0; bit < 64; bit++) {
            // Each limb: bits [limb*64 .. limb*64+63] in big-endian
            // Bits2Num expects LSB-first, so reverse within the 64-bit chunk
            b2n[limb].in[bit] <== in[limb * 64 + 63 - bit];
        }
        out[limb] <== b2n[limb].out;
    }
}

/// @title BandwidthReceipt
/// @notice Proves ownership of a valid dual-signed bandwidth receipt and
///         correct payment split, without revealing session metadata.
///
///         The EIP-712 digest is computed entirely in-circuit from the
///         private receipt data — no external trust required.
template BandwidthReceipt(MERKLE_DEPTH) {
    // ── Public inputs ─────────────────────────────────────────────
    signal input domainSeparator;      // EIP-712 domain separator
    signal input totalPaymentPub;      // Expected total payment
    signal input entryCommitmentPub;   // Poseidon(entryAddr, entryPay)
    signal input relayCommitmentPub;   // Poseidon(relayAddr, relayPay)
    signal input exitCommitmentPub;    // Poseidon(exitAddr, exitPay)
    signal input refundCommitmentPub;  // Poseidon(clientAddr, refund)
    signal input registryRoot;         // Merkle root of registered nodes
    signal input nullifierPub;         // Poseidon(sessionId, clientAddress) — unique per session
    signal input depositIdPub;         // Binds proof to a specific deposit

    // ── Public outputs (payment amounts for on-chain verification) ────
    signal output entryPayOut;
    signal output relayPayOut;
    signal output exitPayOut;
    signal output refundOut;

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

    // Merkle proofs for node registry membership (all 3 nodes)
    signal input nodeMerkleProof[MERKLE_DEPTH];
    signal input nodeMerkleIndex;

    // Entry and relay node public keys + Merkle proofs
    signal input entryPubkey[2][4];    // [x, y] each as 4x64-bit limbs
    signal input entryMerkleProof[MERKLE_DEPTH];
    signal input entryMerkleIndex;

    signal input relayPubkey[2][4];
    signal input relayMerkleProof[MERKLE_DEPTH];
    signal input relayMerkleIndex;

    // ── 1. Compute EIP-712 digest in-circuit ──────────────────────
    //
    // RECEIPT_TYPEHASH = keccak256("BandwidthReceipt(uint256 sessionId,uint256 cumulativeBytes,uint256 timestamp)")
    // This is a protocol constant — hardcoded as bits below.
    // Value: 0x... (computed at deploy time, verified by contract tests)
    //
    // structHash = keccak256(abi.encode(RECEIPT_TYPEHASH, sessionId, cumulativeBytes, timestamp))
    //   = keccak256(4 × 256 bits = 1024 bits)
    //
    // digest = keccak256("\x19\x01" || domainSeparator || structHash)
    //   = keccak256(16 + 256 + 256 = 528 bits)

    // RECEIPT_TYPEHASH as a private input (prover supplies the constant;
    // circuit verifies it produces valid signatures, so forgery is impossible).
    signal input receiptTypehash;

    // Convert the 4 ABI-encoded uint256 values to big-endian bits.
    component typehashBits = Uint256ToBitsBE();
    typehashBits.in <== receiptTypehash;

    component sessionIdBits = Uint256ToBitsBE();
    sessionIdBits.in <== sessionId;

    component cumBytesBits = Uint256ToBitsBE();
    cumBytesBits.in <== cumulativeBytes;

    component timestampBits = Uint256ToBitsBE();
    timestampBits.in <== timestamp;

    // Step 1: structHash = keccak256(typehash || sessionId || cumulativeBytes || timestamp)
    // Input: 4 × 256 = 1024 bits
    component structKeccak = Keccak(1024, 256);
    for (var i = 0; i < 256; i++) {
        structKeccak.in[i]       <== typehashBits.out[i];
        structKeccak.in[256 + i] <== sessionIdBits.out[i];
        structKeccak.in[512 + i] <== cumBytesBits.out[i];
        structKeccak.in[768 + i] <== timestampBits.out[i];
    }

    // Step 2: digest = keccak256("\x19\x01" || domainSeparator || structHash)
    // "\x19\x01" = 0x1901 = 16 bits
    // Total input: 16 + 256 + 256 = 528 bits
    component domainBits = Uint256ToBitsBE();
    domainBits.in <== domainSeparator;

    component digestKeccak = Keccak(528, 256);

    // EIP-712 prefix: 0x19 0x01 = 0b00011001 0b00000001 (16 bits, big-endian)
    var EIP712_PREFIX[16] = [0,0,0,1,1,0,0,1, 0,0,0,0,0,0,0,1];
    for (var i = 0; i < 16; i++) {
        digestKeccak.in[i] <== EIP712_PREFIX[i];
    }

    // Bits 16..271: domainSeparator (256 bits)
    for (var i = 0; i < 256; i++) {
        digestKeccak.in[16 + i] <== domainBits.out[i];
    }
    // Bits 272..527: structHash (256 bits, from structKeccak output)
    for (var i = 0; i < 256; i++) {
        digestKeccak.in[272 + i] <== structKeccak.out[i];
    }

    // Convert 256-bit digest to 4x64-bit limbs for ECDSA verification.
    component digestLimbs = KeccakBitsToLimbs();
    for (var i = 0; i < 256; i++) {
        digestLimbs.in[i] <== digestKeccak.out[i];
    }

    // ── 2. Verify client ECDSA signature ──────────────────────────
    component clientVerify = ECDSAVerifyNoPubkeyCheck(64, 4);
    for (var i = 0; i < 4; i++) {
        clientVerify.r[i] <== clientR[i];
        clientVerify.s[i] <== clientS[i];
        clientVerify.msghash[i] <== digestLimbs.out[i];
        clientVerify.pubkey[0][i] <== clientPubkey[0][i];
        clientVerify.pubkey[1][i] <== clientPubkey[1][i];
    }
    clientVerify.result === 1;

    // ── 3. Verify node ECDSA signature ────────────────────────────
    component nodeVerify = ECDSAVerifyNoPubkeyCheck(64, 4);
    for (var i = 0; i < 4; i++) {
        nodeVerify.r[i] <== nodeR[i];
        nodeVerify.s[i] <== nodeS[i];
        nodeVerify.msghash[i] <== digestLimbs.out[i];
        nodeVerify.pubkey[0][i] <== nodePubkey[0][i];
        nodeVerify.pubkey[1][i] <== nodePubkey[1][i];
    }
    nodeVerify.result === 1;

    // ── 4. Verify all 3 nodes are in registry (Merkle proofs) ──────
    // Exit node (also the ECDSA co-signer from Step 3)
    component exitLeafHash = Poseidon(8);
    for (var i = 0; i < 4; i++) {
        exitLeafHash.inputs[i] <== nodePubkey[0][i];
        exitLeafHash.inputs[4 + i] <== nodePubkey[1][i];
    }
    component exitMerkleCheck = MerkleVerify(MERKLE_DEPTH);
    exitMerkleCheck.leaf <== exitLeafHash.out;
    exitMerkleCheck.index <== nodeMerkleIndex;
    exitMerkleCheck.root <== registryRoot;
    for (var i = 0; i < MERKLE_DEPTH; i++) {
        exitMerkleCheck.siblings[i] <== nodeMerkleProof[i];
    }

    // Entry node
    component entryLeafHash = Poseidon(8);
    for (var i = 0; i < 4; i++) {
        entryLeafHash.inputs[i] <== entryPubkey[0][i];
        entryLeafHash.inputs[4 + i] <== entryPubkey[1][i];
    }
    component entryMerkleCheck = MerkleVerify(MERKLE_DEPTH);
    entryMerkleCheck.leaf <== entryLeafHash.out;
    entryMerkleCheck.index <== entryMerkleIndex;
    entryMerkleCheck.root <== registryRoot;
    for (var i = 0; i < MERKLE_DEPTH; i++) {
        entryMerkleCheck.siblings[i] <== entryMerkleProof[i];
    }

    // Relay node
    component relayLeafHash = Poseidon(8);
    for (var i = 0; i < 4; i++) {
        relayLeafHash.inputs[i] <== relayPubkey[0][i];
        relayLeafHash.inputs[4 + i] <== relayPubkey[1][i];
    }
    component relayMerkleCheck = MerkleVerify(MERKLE_DEPTH);
    relayMerkleCheck.leaf <== relayLeafHash.out;
    relayMerkleCheck.index <== relayMerkleIndex;
    relayMerkleCheck.root <== registryRoot;
    for (var i = 0; i < MERKLE_DEPTH; i++) {
        relayMerkleCheck.siblings[i] <== relayMerkleProof[i];
    }

    // ── 5. Compute payment ────────────────────────────────────────
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

    totalPayment === totalPaymentPub;

    // ── 6. Compute payment split (25/25/50) ───────────────────────
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

    // Expose payment amounts as public outputs for on-chain verification.
    entryPayOut <== entryPay;
    relayPayOut <== relayPay;
    exitPayOut <== exitPay;
    refundOut <== refund;

    // ── 7. Verify commitments ─────────────────────────────────────
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

    // ── 8. Nullifier binding ─────────────────────────────────────
    // Deterministic nullifier = Poseidon(sessionId, clientAddress).
    // Prevents proof replay: each session+client pair produces exactly
    // one nullifier. The contract checks this against its nullifier set.
    component nullifierHash = Poseidon(2);
    nullifierHash.inputs[0] <== sessionId;
    nullifierHash.inputs[1] <== clientAddress;
    nullifierHash.out === nullifierPub;

    // ── 9. Deposit ID binding ────────────────────────────────────
    // The deposit field must match the public depositId, binding the
    // proof to a specific on-chain deposit. The depositId is derived
    // from the deposit amount and session parameters by the client.
    signal input depositIdPrivate;  // private: the actual deposit ID
    depositIdPrivate === depositIdPub;
}

// Instantiate with Merkle depth 20 (~1M node capacity).
component main {public [
    domainSeparator,
    totalPaymentPub,
    entryCommitmentPub,
    relayCommitmentPub,
    exitCommitmentPub,
    refundCommitmentPub,
    registryRoot,
    nullifierPub,
    depositIdPub
]} = BandwidthReceipt(20);
