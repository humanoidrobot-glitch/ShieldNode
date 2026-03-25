# ZK Bandwidth Receipt Circuit

## What This Proves

"I hold a valid dual-signed bandwidth receipt. The total payment is Y, split across three node commitments, with the remainder refunded to a client commitment."

The chain sees: a valid proof, ETH distributed to commitments, refund to a commitment. It does **not** see: session ID, node identities, byte count, timestamps, or who the client is.

## Proving System

**Groth16** via circom + snarkjs. On-chain verification cost: ~200K gas.

Groth16 requires a trusted setup (powers-of-tau ceremony). For testnet we use a development ceremony; mainnet requires a proper multi-party ceremony.

## Inputs

### Public (visible on-chain)

| Input | Type | Description |
|-------|------|-------------|
| `domainSeparator` | uint256 | EIP-712 domain separator (ties proof to specific contract) |
| `totalPayment` | uint256 | Total ETH to distribute to nodes |
| `entryCommitment` | uint256 | Poseidon(entryAddress, entryPayment) |
| `relayCommitment` | uint256 | Poseidon(relayAddress, relayPayment) |
| `exitCommitment` | uint256 | Poseidon(exitAddress, exitPayment) |
| `refundCommitment` | uint256 | Poseidon(clientAddress, refundAmount) |
| `registryRoot` | uint256 | Merkle root of registered node public keys |

### Public outputs (proven by the circuit, verified on-chain)

| Output | Type | Description |
|--------|------|-------------|
| `entryPayOut` | uint256 | Entry node's payment (25% of totalPayment) |
| `relayPayOut` | uint256 | Relay node's payment (25% of totalPayment) |
| `exitPayOut` | uint256 | Exit node's payment (50% of totalPayment) |
| `refundOut` | uint256 | Refund to client (deposit - totalPayment) |

### Private (known only to prover)

| Input | Type | Description |
|-------|------|-------------|
| `sessionId` | uint256 | Session identifier |
| `cumulativeBytes` | uint256 | Total bytes transferred |
| `timestamp` | uint256 | Receipt timestamp |
| `pricePerByte` | uint256 | Exit node's price rate |
| `deposit` | uint256 | Original session deposit |
| `clientAddress` | address | Client's Ethereum address |
| `entryAddress` | address | Entry node operator address |
| `relayAddress` | address | Relay node operator address |
| `exitAddress` | address | Exit node operator address |
| `clientPubkey` | (uint256, uint256) | Client's secp256k1 public key (x, y) |
| `clientSig` | (uint256, uint256) | Client's ECDSA signature (r, s) |
| `nodePubkey` | (uint256, uint256) | Exit node's secp256k1 public key (x, y) |
| `nodeSig` | (uint256, uint256) | Exit node's ECDSA signature (r, s) |
| `receiptTypehash` | uint256 | EIP-712 RECEIPT_TYPEHASH constant (protocol-defined) |
| `nodeMerkleProof` | uint256[] | Merkle proof that nodePubkey is in registryRoot |
| `nodeMerkleIndex` | uint256 | Leaf index in the Merkle tree |

## Constraints

1. **EIP-712 digest computation** — Compute `structHash = keccak256(RECEIPT_TYPEHASH, sessionId, cumulativeBytes, timestamp)`, then `digest = keccak256("\x19\x01" || domainSeparator || structHash)`
2. **Client signature verification** — Verify `clientSig` is a valid ECDSA signature by `clientPubkey` over `digest`
3. **Node signature verification** — Verify `nodeSig` is a valid ECDSA signature by `nodePubkey` over `digest`
4. **Node registry membership** — Verify `nodePubkey` is in the Merkle tree with root `registryRoot`
5. **Payment computation** — `totalPayment = min(cumulativeBytes * pricePerByte, deposit)`
6. **Payment split** — `entryPay = totalPayment * 25 / 100`, `relayPay = totalPayment * 25 / 100`, `exitPay = totalPayment - entryPay - relayPay`
7. **Refund computation** — `refund = deposit - totalPayment`
8. **Commitment verification** — Each commitment matches `Poseidon(address, amount)`

## Constraint Count Estimate

| Component | Constraints |
|-----------|------------|
| Keccak256 (structHash, 1024-bit input) | ~150K |
| Keccak256 (digest, 528-bit input) | ~150K |
| Uint256-to-bits conversions (5x) | ~5K |
| ECDSA verify (client) | ~1.5M |
| ECDSA verify (node) | ~1.5M |
| Merkle proof (depth 20) | ~20K |
| Poseidon hashes (4 commitments) | ~1K |
| Arithmetic (payment split) | ~100 |
| **Total** | **~3.5M** |

Proving time estimate: 3-10s on modern hardware (16GB RAM, 8 cores) with Groth16.

## Dependencies

- [circom](https://docs.circom.io/) >= 2.1.0
- [snarkjs](https://github.com/iden3/snarkjs) >= 0.7.0
- [circomlib](https://github.com/iden3/circomlib) — Poseidon, comparators, mux
- [circom-ecdsa](https://github.com/0xPARC/circom-ecdsa) — secp256k1 ECDSA verification
- [keccak256-circom](https://github.com/vocdoni/keccak256-circom) — Keccak256 for in-circuit EIP-712 digest

## Trustlessness: In-Circuit EIP-712 Digest

The EIP-712 digest is computed **entirely inside the circuit** from the private receipt data (sessionId, cumulativeBytes, timestamp) and the public domainSeparator. No external trust is required — the prover cannot lie about the receipt data because the digest fed to ECDSA verification is derived from the private inputs, not supplied externally.

This costs ~300K additional constraints (two keccak256 calls) but eliminates any trust assumption about the prover's honesty regarding receipt content.

## Post-Quantum Note

The circuit accepts ECDSA signatures now. The `Signer` trait selector (ECDSA vs ML-DSA) will be added as a circuit input in a future iteration. Inside the ZK circuit, ML-DSA's 3,293-byte signatures carry no gas penalty — only the constant-size proof goes on-chain.

## Build

```bash
cd circuits
./scripts/compile.sh    # Compile circuit → R1CS + WASM
./scripts/setup.sh      # Trusted setup (dev ceremony)
./scripts/prove.sh      # Generate proof from input.json
./scripts/verify.sh     # Verify proof off-chain
```
